//! Bounded local message transport.
//!
//! [`SpscRing`] is a real fixed-capacity single-producer/single-consumer ring
//! for one address space. Cross-process channels are deliberately absent until
//! Boulder provides shared mappings and capability-validated endpoints.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const CHANNEL_DEPTH: usize = 128;
pub const MESSAGE_BYTES: usize = 64;
pub const PAYLOAD_BYTES: usize = 48;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct ChannelMessage {
    pub capability: u64,
    pub tag: u32,
    pub sequence: u32,
    pub payload: [u8; PAYLOAD_BYTES],
}

const _: () = assert!(core::mem::size_of::<ChannelMessage>() == MESSAGE_BYTES);

impl ChannelMessage {
    pub const fn empty() -> Self {
        Self {
            capability: 0,
            tag: 0,
            sequence: 0,
            payload: [0; PAYLOAD_BYTES],
        }
    }

    pub const fn with_tag(tag: u32) -> Self {
        Self {
            capability: 0,
            tag,
            sequence: 0,
            payload: [0; PAYLOAD_BYTES],
        }
    }

    pub fn with_payload(tag: u32, data: &[u8]) -> Self {
        let mut message = Self::with_tag(tag);
        let length = data.len().min(PAYLOAD_BYTES);
        message.payload[..length].copy_from_slice(&data[..length]);
        message
    }
}

const SLOT_EMPTY: u64 = 0;
const SLOT_WRITING: u64 = 1;
const SLOT_READY: u64 = 2;
const SLOT_READING: u64 = 3;

#[repr(C, align(64))]
struct RingSlot {
    state: AtomicU64,
    message: UnsafeCell<ChannelMessage>,
}

impl RingSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(SLOT_EMPTY),
            message: UnsafeCell::new(ChannelMessage::empty()),
        }
    }
}

// SAFETY: slot state gives the sole producer and sole consumer mutually
// exclusive access to `message`; publication uses Release/Acquire ordering.
unsafe impl Sync for RingSlot {}

#[repr(C, align(4096))]
pub struct SpscRing {
    producer: AtomicU32,
    consumer: AtomicU32,
    _pad: [u8; 56],
    slots: [RingSlot; CHANNEL_DEPTH],
}

impl SpscRing {
    pub const fn new() -> Self {
        Self {
            producer: AtomicU32::new(0),
            consumer: AtomicU32::new(0),
            _pad: [0; 56],
            slots: [const { RingSlot::new() }; CHANNEL_DEPTH],
        }
    }

    pub fn send(&self, message: ChannelMessage) -> Result<(), ChannelError> {
        let head = self.producer.load(Ordering::Relaxed) as usize;
        let slot = &self.slots[head % CHANNEL_DEPTH];
        slot.state
            .compare_exchange(
                SLOT_EMPTY,
                SLOT_WRITING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .map_err(|_| ChannelError::Full)?;
        // SAFETY: this producer owns the slot in WRITING state.
        unsafe { *slot.message.get() = message };
        slot.state.store(SLOT_READY, Ordering::Release);
        self.producer
            .store(((head + 1) % CHANNEL_DEPTH) as u32, Ordering::Release);
        Ok(())
    }

    pub fn recv(&self) -> Option<ChannelMessage> {
        let tail = self.consumer.load(Ordering::Relaxed) as usize;
        let slot = &self.slots[tail % CHANNEL_DEPTH];
        slot.state
            .compare_exchange(
                SLOT_READY,
                SLOT_READING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .ok()?;
        // SAFETY: this consumer owns the slot in READING state.
        let message = unsafe { *slot.message.get() };
        slot.state.store(SLOT_EMPTY, Ordering::Release);
        self.consumer
            .store(((tail + 1) % CHANNEL_DEPTH) as u32, Ordering::Release);
        Some(message)
    }

    pub fn is_empty(&self) -> bool {
        let tail = self.consumer.load(Ordering::Relaxed) as usize;
        self.slots[tail % CHANNEL_DEPTH]
            .state
            .load(Ordering::Acquire)
            != SLOT_READY
    }
}

impl Default for SpscRing {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsc_ring_send_recv_roundtrip() {
        let ring = SpscRing::new();
        let message = ChannelMessage::with_tag(42);
        ring.send(message).unwrap();
        assert_eq!(ring.recv().unwrap().tag, 42);
        assert!(ring.is_empty());
    }

    #[test]
    fn ring_full_returns_error() {
        let ring = SpscRing::new();
        for index in 0..CHANNEL_DEPTH {
            ring.send(ChannelMessage::with_tag(index as u32)).unwrap();
        }
        assert_eq!(
            ring.send(ChannelMessage::with_tag(999)),
            Err(ChannelError::Full)
        );
    }

    #[test]
    fn ring_empty_returns_none() {
        assert!(SpscRing::new().recv().is_none());
    }

    #[test]
    fn payload_is_bounded_without_allocating() {
        let message = ChannelMessage::with_payload(7, &[0xaa; PAYLOAD_BYTES + 1]);
        assert_eq!(message.payload, [0xaa; PAYLOAD_BYTES]);
    }
}
