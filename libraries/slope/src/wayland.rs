//! Capability-bound display and input records for promoting Crest's shell.
//!
//! These records are deliberately only an ABI contract.  Boulder must still
//! mint the shared mapping and endpoint capabilities before a native process
//! can publish or consume one.  The hosted Smithay compositor is the first
//! implementation of the policy; this module gives the native adapter an
//! exact, bounded wire shape for pointer, keyboard, touch, axis, and gesture
//! events to implement next.

pub const WAYLAND_WIRE_VERSION: u16 = 1;
pub const MAXIMUM_SURFACES: usize = 16;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelFormat {
    Bgra8888 = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayLease {
    pub version: u16,
    pub format: PixelFormat,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub generation: u64,
    pub capability: u64,
}

impl DisplayLease {
    pub const fn valid(self) -> bool {
        self.version == WAYLAND_WIRE_VERSION
            && self.format as u16 == PixelFormat::Bgra8888 as u16
            && self.width != 0
            && self.height != 0
            && self.pitch >= self.width.saturating_mul(4)
            && self.generation != 0
            && self.capability != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceLease {
    pub surface_id: u32,
    pub buffer_id: u32,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub generation: u64,
    pub capability: u64,
}

impl SurfaceLease {
    pub const fn valid_for(self, display: DisplayLease) -> bool {
        display.valid()
            && self.surface_id != 0
            && self.buffer_id != 0
            && self.width != 0
            && self.height != 0
            && self.stride >= self.width.saturating_mul(4)
            && self.generation == display.generation
            && self.capability != 0
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputKind {
    Motion = 1,
    Button = 2,
    Axis = 3,
    Key = 4,
    Touch = 5,
    Gesture = 6,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputRecord {
    pub kind: InputKind,
    pub state: u8,
    pub reserved: [u8; 2],
    pub code: u32,
    pub x: i32,
    pub y: i32,
    pub value: i32,
    pub serial: u64,
}

impl InputRecord {
    pub const fn valid(self) -> bool {
        matches!(
            self.kind,
            InputKind::Motion
                | InputKind::Button
                | InputKind::Axis
                | InputKind::Key
                | InputKind::Touch
                | InputKind::Gesture
        ) && self.serial != 0
    }
}

const _: () = assert!(core::mem::size_of::<DisplayLease>() == 32);
const _: () = assert!(core::mem::size_of::<SurfaceLease>() == 48);
const _: () = assert!(core::mem::size_of::<InputRecord>() == 32);

#[cfg(test)]
mod tests {
    use super::*;

    const DISPLAY: DisplayLease = DisplayLease {
        version: WAYLAND_WIRE_VERSION,
        format: PixelFormat::Bgra8888,
        width: 1280,
        height: 800,
        pitch: 5120,
        generation: 7,
        capability: 11,
    };

    #[test]
    fn display_and_surface_records_bind_to_one_generation() {
        assert!(DISPLAY.valid());
        let surface = SurfaceLease {
            surface_id: 1,
            buffer_id: 2,
            x: 0,
            y: 0,
            width: 640,
            height: 400,
            stride: 2560,
            generation: 7,
            capability: 12,
        };
        assert!(surface.valid_for(DISPLAY));
        assert!(
            !SurfaceLease {
                generation: 8,
                ..surface
            }
            .valid_for(DISPLAY)
        );
    }

    #[test]
    fn malformed_records_fail_closed() {
        assert!(
            !DisplayLease {
                pitch: 1,
                ..DISPLAY
            }
            .valid()
        );
        assert!(
            !InputRecord {
                kind: InputKind::Motion,
                state: 0,
                reserved: [0; 2],
                code: 0,
                x: 0,
                y: 0,
                value: 0,
                serial: 0,
            }
            .valid()
        );
        assert!(
            InputRecord {
                kind: InputKind::Touch,
                state: 1,
                reserved: [0; 2],
                code: 0,
                x: 100,
                y: 200,
                value: 0,
                serial: 1,
            }
            .valid()
        );
        assert!(
            InputRecord {
                kind: InputKind::Gesture,
                state: 1,
                reserved: [0; 2],
                code: 0,
                x: 0,
                y: 0,
                value: 0,
                serial: 2,
            }
            .valid()
        );
    }
}
