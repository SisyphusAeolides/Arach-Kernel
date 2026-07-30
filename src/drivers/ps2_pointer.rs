//! Bounded PS/2 input transport for QEMU Crest.
//!
//! Arach owns the 8042 controller and demultiplexes its auxiliary mouse
//! packets from translated Set-1 keyboard scancodes before exposing either
//! normalized event stream through Crest's authenticated syscalls. During
//! initialization Arach requests the standard IntelliMouse wheel protocol;
//! a controller that declines it remains a three-byte motion device. User
//! space never receives a controller port, an IRQ capability, or raw bytes.

use crate::arch::x86_64::{inb, outb};
use crate::serial::SerialPort;
use crate::sync::SpinLock;
use core::fmt::Write;

const STATUS_PORT: u16 = 0x64;
const DATA_PORT: u16 = 0x60;
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;
const STATUS_AUXILIARY: u8 = 1 << 5;
const MAXIMUM_WAIT_SPINS: usize = 20_000;
const MAXIMUM_DRAIN_BYTES: usize = 32;
const MAXIMUM_QUEUED_EVENTS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerMotion {
    pub delta_x: i16,
    pub delta_y: i16,
    pub scroll_x: i16,
    pub scroll_y: i16,
    pub buttons: u8,
    reserved: [u8; 3],
}

impl PointerMotion {
    const fn new(delta_x: i16, delta_y: i16, scroll_x: i16, scroll_y: i16, buttons: u8) -> Self {
        Self {
            delta_x,
            delta_y,
            scroll_x,
            scroll_y,
            buttons,
            reserved: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyEvent {
    pub code: u32,
    pub pressed: u8,
    reserved: [u8; 3],
}

impl KeyEvent {
    const fn new(code: u32, pressed: bool) -> Self {
        Self {
            code,
            pressed: pressed as u8,
            reserved: [0; 3],
        }
    }
}

struct Ps2Input {
    initialized: bool,
    unavailable: bool,
    reported: bool,
    pointer_bytes: [u8; 4],
    pointer_count: usize,
    pointer_packet_length: usize,
    wheel_enabled: bool,
    explorer_buttons: bool,
    keyboard_extended: bool,
    pointer_stream_reported: bool,
    pointer_events: [Option<PointerMotion>; MAXIMUM_QUEUED_EVENTS],
    pointer_head: usize,
    pointer_len: usize,
    key_events: [Option<KeyEvent>; MAXIMUM_QUEUED_EVENTS],
    key_head: usize,
    key_len: usize,
}

impl Ps2Input {
    const EMPTY: Self = Self {
        initialized: false,
        unavailable: false,
        reported: false,
        pointer_bytes: [0; 4],
        pointer_count: 0,
        pointer_packet_length: 3,
        wheel_enabled: false,
        explorer_buttons: false,
        keyboard_extended: false,
        pointer_stream_reported: false,
        pointer_events: [None; MAXIMUM_QUEUED_EVENTS],
        pointer_head: 0,
        pointer_len: 0,
        key_events: [None; MAXIMUM_QUEUED_EVENTS],
        key_head: 0,
        key_len: 0,
    };

    fn poll_pointer(&mut self) -> Option<PointerMotion> {
        self.ensure_initialized();
        self.drain();
        self.dequeue_pointer()
    }

    fn poll_key(&mut self) -> Option<KeyEvent> {
        self.ensure_initialized();
        self.drain();
        self.dequeue_key()
    }

    fn ensure_initialized(&mut self) {
        if !self.initialized && !self.unavailable {
            if !self.initialize() {
                self.unavailable = true;
            }
            self.report_state();
        }
    }

    fn drain(&mut self) {
        if self.unavailable {
            return;
        }
        for _ in 0..MAXIMUM_DRAIN_BYTES {
            // SAFETY: Arach owns the legacy controller ports for this
            // bounded polling transaction.
            let status = unsafe { inb(STATUS_PORT) };
            if status & STATUS_OUTPUT_FULL == 0 {
                return;
            }
            // SAFETY: Output-full was observed immediately before the read.
            let byte = unsafe { inb(DATA_PORT) };
            if status & STATUS_AUXILIARY != 0 {
                if let Some(event) = self.push_pointer(byte) {
                    self.enqueue_pointer(event);
                }
            } else if let Some(event) = decode_keyboard_byte(byte, &mut self.keyboard_extended) {
                self.enqueue_key(event);
            }
        }
    }

    fn report_state(&mut self) {
        if self.reported {
            return;
        }
        self.reported = true;
        let mut serial = unsafe { SerialPort::initialize(0x3f8) };
        let _ = writeln!(
            serial,
            "Arach: PS/2 input {}",
            if self.initialized {
                if self.wheel_enabled {
                    "streams enabled (wheel)"
                } else {
                    "streams enabled (three-byte pointer)"
                }
            } else {
                "unavailable"
            }
        );
    }

    fn initialize(&mut self) -> bool {
        // Enable both legacy controller channels, enable IRQ12 delivery, and
        // make the controller translate keyboard Set-2 bytes to the Set-1
        // key codes carried by the Crest ABI. Then reset defaults and enable
        // mouse packet streaming. Wheel setup is best-effort: an older
        // pointer must remain usable rather than being rejected for lacking a
        // capability that did not exist when it was manufactured.
        //
        // Firmware may leave one or more keyboard bytes in the shared 8042
        // output register. Drain that stale prefix before reading the
        // controller configuration byte; otherwise a keyboard scancode can be
        // mistaken for the config and leave the auxiliary clock disabled,
        // which looks exactly like a dead mouse to Crest.
        self.flush_stale_output();
        if !write_command(0xae) || !write_command(0xa8) || !write_command(0x20) || !wait_output() {
            return false;
        }
        // SAFETY: wait_output guarantees a controller reply is ready.
        let config = unsafe { inb(DATA_PORT) };
        if !write_command(0x60) || !write_data((config | 0x42) & !0x30) {
            return false;
        }
        if !mouse_command(0xf6) || !expect_ack() {
            return false;
        }
        self.enable_wheel_protocol();
        if !mouse_command(0xf4) || !expect_ack() {
            return false;
        }
        self.initialized = true;
        true
    }

    fn flush_stale_output(&mut self) {
        for _ in 0..MAXIMUM_DRAIN_BYTES {
            // SAFETY: Arach owns the controller during initialization and
            // only reads DATA_PORT after observing OUTPUT_FULL.
            let status = unsafe { inb(STATUS_PORT) };
            if status & STATUS_OUTPUT_FULL == 0 {
                break;
            }
            // SAFETY: OUTPUT_FULL was observed immediately above.
            let _ = unsafe { inb(DATA_PORT) };
        }
    }

    fn push_pointer(&mut self, byte: u8) -> Option<PointerMotion> {
        if self.pointer_count == 0 && byte & 0x08 == 0 {
            return None;
        }
        self.pointer_bytes[self.pointer_count] = byte;
        self.pointer_count += 1;
        if self.pointer_count != self.pointer_packet_length {
            return None;
        }
        self.pointer_count = 0;
        decode_packet(
            self.pointer_bytes,
            self.wheel_enabled,
            self.explorer_buttons,
        )
    }

    /// Uses the documented IntelliMouse sample-rate handshake. The device ID
    /// is consumed before streaming starts, so it cannot desynchronize the
    /// packet parser. ID 3 provides a wheel; ID 4 additionally provides two
    /// auxiliary buttons. Any other reply is a clean legacy fallback.
    fn enable_wheel_protocol(&mut self) {
        for rate in [200_u8, 100, 80] {
            if !mouse_command(0xf3) || !expect_ack() || !mouse_command(rate) || !expect_ack() {
                return;
            }
        }
        if !mouse_command(0xf2) || !expect_ack() || !wait_output() {
            return;
        }
        // SAFETY: `wait_output` observed the controller output buffer full.
        let device_id = unsafe { inb(DATA_PORT) };
        match device_id {
            3 => {
                self.pointer_packet_length = 4;
                self.wheel_enabled = true;
            }
            4 => {
                self.pointer_packet_length = 4;
                self.wheel_enabled = true;
                self.explorer_buttons = true;
            }
            _ => {}
        }
    }

    fn enqueue_pointer(&mut self, event: PointerMotion) {
        if !self.pointer_stream_reported {
            self.pointer_stream_reported = true;
            let mut serial = unsafe { SerialPort::initialize(0x3f8) };
            let _ = writeln!(serial, "Arach: PS/2 pointer packet stream live");
        }
        if self.pointer_len == MAXIMUM_QUEUED_EVENTS {
            self.pointer_events[self.pointer_head] = None;
            self.pointer_head = (self.pointer_head + 1) % MAXIMUM_QUEUED_EVENTS;
            self.pointer_len -= 1;
        }
        let tail = (self.pointer_head + self.pointer_len) % MAXIMUM_QUEUED_EVENTS;
        self.pointer_events[tail] = Some(event);
        self.pointer_len += 1;
    }

    fn dequeue_pointer(&mut self) -> Option<PointerMotion> {
        if self.pointer_len == 0 {
            return None;
        }
        let event = self.pointer_events[self.pointer_head].take();
        self.pointer_head = (self.pointer_head + 1) % MAXIMUM_QUEUED_EVENTS;
        self.pointer_len -= 1;
        event
    }

    fn enqueue_key(&mut self, event: KeyEvent) {
        if self.key_len == MAXIMUM_QUEUED_EVENTS {
            self.key_events[self.key_head] = None;
            self.key_head = (self.key_head + 1) % MAXIMUM_QUEUED_EVENTS;
            self.key_len -= 1;
        }
        let tail = (self.key_head + self.key_len) % MAXIMUM_QUEUED_EVENTS;
        self.key_events[tail] = Some(event);
        self.key_len += 1;
    }

    fn dequeue_key(&mut self) -> Option<KeyEvent> {
        if self.key_len == 0 {
            return None;
        }
        let event = self.key_events[self.key_head].take();
        self.key_head = (self.key_head + 1) % MAXIMUM_QUEUED_EVENTS;
        self.key_len -= 1;
        event
    }
}

static INPUT: SpinLock<Ps2Input> = SpinLock::new(Ps2Input::EMPTY);

/// Reads at most one complete normalized auxiliary-pointer packet.
pub fn poll() -> Option<PointerMotion> {
    INPUT.lock().poll_pointer()
}

/// Reads at most one normalized Set-1 keyboard event.
pub fn poll_key() -> Option<KeyEvent> {
    INPUT.lock().poll_key()
}

fn wait_input_empty() -> bool {
    for _ in 0..MAXIMUM_WAIT_SPINS {
        // SAFETY: status port is readable while Arach owns the controller.
        if unsafe { inb(STATUS_PORT) } & STATUS_INPUT_FULL == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn wait_output() -> bool {
    for _ in 0..MAXIMUM_WAIT_SPINS {
        // SAFETY: status port is readable while Arach owns the controller.
        if unsafe { inb(STATUS_PORT) } & STATUS_OUTPUT_FULL != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn write_command(command: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    // SAFETY: the input buffer is empty and this call owns the controller
    // command sequencing.
    unsafe { outb(STATUS_PORT, command) };
    true
}

fn write_data(data: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    // SAFETY: the input buffer is empty and this call owns the data phase.
    unsafe { outb(DATA_PORT, data) };
    true
}

fn mouse_command(command: u8) -> bool {
    write_command(0xd4) && write_data(command)
}

fn expect_ack() -> bool {
    wait_output()
        // SAFETY: `wait_output` guarantees a controller reply is ready.
        && unsafe { inb(DATA_PORT) } == 0xfa
}

fn decode_packet(
    bytes: [u8; 4],
    wheel_enabled: bool,
    explorer_buttons: bool,
) -> Option<PointerMotion> {
    if bytes[0] & 0x08 == 0 || bytes[0] & 0xc0 != 0 {
        return None;
    }
    let scroll_y = if wheel_enabled {
        // IntelliMouse transmits a signed four-bit wheel delta. Positive is
        // the physical wheel-up direction, preserved through the Crest ABI.
        let value = bytes[3] & 0x0f;
        if value & 0x08 != 0 {
            i16::from(value) - 16
        } else {
            i16::from(value)
        }
    } else {
        0
    };
    let mut buttons = bytes[0] & 0x07;
    if explorer_buttons {
        // Explorer-compatible ID 4 encodes buttons 4 and 5 in bits 4 and 5
        // of the fourth byte. Preserve them in the normalized button mask.
        buttons |= (bytes[3] & 0x30) >> 1;
    }
    Some(PointerMotion::new(
        i16::from(bytes[1] as i8),
        -i16::from(bytes[2] as i8),
        0,
        scroll_y,
        buttons,
    ))
}

fn decode_keyboard_byte(byte: u8, extended: &mut bool) -> Option<KeyEvent> {
    if byte == 0xe0 {
        *extended = true;
        return None;
    }
    if byte == 0xe1 {
        // Pause is a multi-byte sequence that Crest does not bind. Dropping
        // its prefix keeps the bounded decoder synchronized for normal keys.
        *extended = false;
        return None;
    }

    let pressed = byte & 0x80 == 0;
    let scancode = byte & 0x7f;
    let code = if *extended {
        *extended = false;
        match scancode {
            0x1d => 97,  // right control
            0x38 => 100, // AltGr
            0x5b => 125, // left Super
            0x5c => 126, // right Super
            _ => return None,
        }
    } else {
        u32::from(scancode)
    };
    (code != 0).then(|| KeyEvent::new(code, pressed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_requires_sync_and_rejects_overflow() {
        assert_eq!(decode_packet([0, 1, 1, 0], false, false), None);
        assert_eq!(decode_packet([0x48, 1, 1, 0], false, false), None);
    }

    #[test]
    fn packet_normalizes_screen_y() {
        assert_eq!(
            decode_packet([0x09, 4, 0xfc, 0], false, false),
            Some(PointerMotion::new(4, 4, 0, 0, 1))
        );
    }

    #[test]
    fn wheel_packets_preserve_signed_delta_and_auxiliary_buttons() {
        let packet = decode_packet([0x08, 0, 0, 0x2f], true, true).expect("wheel packet");
        assert_eq!(packet.scroll_y, -1);
        assert_eq!(packet.buttons, 0x10);
    }

    #[test]
    fn keyboard_decoder_normalizes_set_one_make_break_and_super() {
        let mut extended = false;
        assert_eq!(
            decode_keyboard_byte(0x1e, &mut extended),
            Some(KeyEvent::new(30, true))
        );
        assert_eq!(
            decode_keyboard_byte(0x9e, &mut extended),
            Some(KeyEvent::new(30, false))
        );
        assert_eq!(decode_keyboard_byte(0xe0, &mut extended), None);
        assert_eq!(
            decode_keyboard_byte(0x5b, &mut extended),
            Some(KeyEvent::new(125, true))
        );
    }

    #[test]
    fn keyboard_queue_preserves_fifo_order() {
        let mut input = Ps2Input::EMPTY;
        input.enqueue_key(KeyEvent::new(30, true));
        input.enqueue_key(KeyEvent::new(48, false));
        assert_eq!(input.dequeue_key(), Some(KeyEvent::new(30, true)));
        assert_eq!(input.dequeue_key(), Some(KeyEvent::new(48, false)));
        assert_eq!(input.dequeue_key(), None);
    }
}
