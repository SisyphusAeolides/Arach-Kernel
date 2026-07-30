//! Bounded TCP reassembly core for Argus' future HTTPS broker.
//!
//! The e1000 driver remains the sole owner of NIC/DMA authority. This module
//! owns only connection-local protocol state and copied payload bytes. It has
//! no user-space entry point: a later Arach broker must bind it to a live
//! e1000 path and an authenticated Push/Argus IPC mapping.

use crate::predictive_control::hash::Sha256;
use slope::hypermedia::{
    ArgusEndpointSession, EndpointError, HttpIpcRequest, HttpLease, HttpsRequest, HypermediaError,
    MAX_HTTP_REQUEST_BYTES, MAX_HTTP_RESPONSE_BYTES, TlsPeerIdentity, TlsTrustAnchor,
    TlsTrustError,
};

pub const MAX_REASSEMBLY_SEGMENTS: usize = 16;
pub const MAX_REASSEMBLY_BYTES: usize = 8 * 1024;
pub const MAX_TCP_SEGMENT_BYTES: usize = 1_460;
pub const MAX_TLS_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_TLS_CERTIFICATE_BYTES: usize = 16 * 1024;
pub const MAX_TLS_HANDSHAKE_BYTES: usize = 32 * 1024;
const ETHERNET_HEADER_BYTES: usize = 14;
const IPV4_HEADER_BYTES: usize = 20;
const TCP_HEADER_BYTES: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub address: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpBudget {
    pub max_bytes: u16,
    pub max_segments: u8,
    pub yield_every_segments: u8,
}

impl TcpBudget {
    pub const HTTPS_DEFAULT: Self = Self {
        max_bytes: MAX_REASSEMBLY_BYTES as u16,
        max_segments: MAX_REASSEMBLY_SEGMENTS as u8,
        yield_every_segments: 1,
    };

    pub const fn is_valid(self) -> bool {
        self.max_bytes != 0
            && self.max_bytes as usize <= MAX_REASSEMBLY_BYTES
            && self.max_segments != 0
            && self.max_segments as usize <= MAX_REASSEMBLY_SEGMENTS
            && self.yield_every_segments != 0
            && self.yield_every_segments <= self.max_segments
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const SYN: Self = Self(1 << 0);
    pub const ACK: Self = Self(1 << 1);
    pub const FIN: Self = Self(1 << 2);
    pub const RST: Self = Self(1 << 3);
    pub const PSH: Self = Self(1 << 4);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpWireError {
    Incomplete,
    WrongEthernetType,
    WrongDestination,
    InvalidIpv4Header,
    FragmentedIpv4,
    UnsupportedProtocol,
    WrongAddress,
    WrongPort,
    InvalidChecksum,
    UnsupportedFlags,
    SegmentTooLarge,
    BufferTooSmall,
}

/// Parses one complete Ethernet/IPv4/TCP frame into the bounded, copied
/// protocol representation used by [`TcpConnection`].  The returned payload
/// borrows only the caller's immutable frame buffer; it never aliases an
/// e1000 descriptor after the broker has copied that frame into its buffer.
pub fn parse_tcp_frame<'frame>(
    frame: &'frame [u8],
    local_mac: [u8; 6],
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
) -> Result<TcpSegment<'frame>, TcpWireError> {
    if frame.len() < ETHERNET_HEADER_BYTES + IPV4_HEADER_BYTES + TCP_HEADER_BYTES {
        return Err(TcpWireError::Incomplete);
    }
    if frame[..6] != local_mac {
        return Err(TcpWireError::WrongDestination);
    }
    if frame[12..14] != 0x0800_u16.to_be_bytes() {
        return Err(TcpWireError::WrongEthernetType);
    }
    let ip = ETHERNET_HEADER_BYTES;
    let version_ihl = frame[ip];
    if version_ihl >> 4 != 4 {
        return Err(TcpWireError::InvalidIpv4Header);
    }
    let ip_header_length = usize::from(version_ihl & 0x0f) * 4;
    if !(IPV4_HEADER_BYTES..=60).contains(&ip_header_length)
        || frame.len() < ip.saturating_add(ip_header_length)
        || internet_checksum(&frame[ip..ip + ip_header_length]) != 0
    {
        return Err(TcpWireError::InvalidIpv4Header);
    }
    let total_length = usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]));
    let fragment_field = u16::from_be_bytes([frame[ip + 6], frame[ip + 7]]);
    if total_length < ip_header_length + TCP_HEADER_BYTES
        || total_length > frame.len()
        || fragment_field & 0x3fff != 0
    {
        return Err(if total_length > frame.len() {
            TcpWireError::Incomplete
        } else if fragment_field & 0x3fff != 0 {
            TcpWireError::FragmentedIpv4
        } else {
            TcpWireError::InvalidIpv4Header
        });
    }
    if frame[ip + 9] != 6 {
        return Err(TcpWireError::UnsupportedProtocol);
    }
    if frame[ip + 12..ip + 16] != remote_ip || frame[ip + 16..ip + 20] != local_ip {
        return Err(TcpWireError::WrongAddress);
    }
    let tcp = ip + ip_header_length;
    let tcp_header_length = usize::from(frame[tcp + 12] >> 4) * 4;
    if !(TCP_HEADER_BYTES..=60).contains(&tcp_header_length)
        || tcp + tcp_header_length > ip + total_length
    {
        return Err(TcpWireError::InvalidIpv4Header);
    }
    if u16::from_be_bytes([frame[tcp], frame[tcp + 1]]) != remote_port
        || u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]) != local_port
    {
        return Err(TcpWireError::WrongPort);
    }
    let tcp_payload_start = tcp + tcp_header_length;
    let tcp_payload_end = ip + total_length;
    let payload = &frame[tcp_payload_start..tcp_payload_end];
    if payload.len() > MAX_TCP_SEGMENT_BYTES {
        return Err(TcpWireError::SegmentTooLarge);
    }
    if tcp_checksum(
        &frame[ip + 12..ip + 16],
        &frame[ip + 16..ip + 20],
        &frame[tcp..tcp_payload_end],
    ) != 0
    {
        return Err(TcpWireError::InvalidChecksum);
    }
    let wire_flags = frame[tcp + 13];
    if wire_flags & 0xe0 != 0 {
        return Err(TcpWireError::UnsupportedFlags);
    }
    let mut flags = TcpFlags::empty();
    if wire_flags & 0x01 != 0 {
        flags = flags.union(TcpFlags::FIN);
    }
    if wire_flags & 0x02 != 0 {
        flags = flags.union(TcpFlags::SYN);
    }
    if wire_flags & 0x04 != 0 {
        flags = flags.union(TcpFlags::RST);
    }
    if wire_flags & 0x08 != 0 {
        flags = flags.union(TcpFlags::PSH);
    }
    if wire_flags & 0x10 != 0 {
        flags = flags.union(TcpFlags::ACK);
    }
    Ok(TcpSegment {
        source: Endpoint {
            address: remote_ip,
            port: remote_port,
        },
        destination: Endpoint {
            address: local_ip,
            port: local_port,
        },
        sequence: u32::from_be_bytes([
            frame[tcp + 4],
            frame[tcp + 5],
            frame[tcp + 6],
            frame[tcp + 7],
        ]),
        acknowledgment: u32::from_be_bytes([
            frame[tcp + 8],
            frame[tcp + 9],
            frame[tcp + 10],
            frame[tcp + 11],
        ]),
        flags,
        payload,
    })
}

/// Encodes one IPv4/TCP segment into a complete Ethernet frame.  The fixed
/// IPv4/TCP headers intentionally omit options; MSS/window negotiation belongs
/// to the future broker policy and cannot be inferred from a caller buffer.
pub fn encode_tcp_frame(
    output: &mut [u8],
    destination_mac: [u8; 6],
    source_mac: [u8; 6],
    segment: TcpSegment<'_>,
    identification: u16,
) -> Result<usize, TcpWireError> {
    if segment.source.port == 0 || segment.destination.port == 0 {
        return Err(TcpWireError::WrongPort);
    }
    if segment.payload.len() > MAX_TCP_SEGMENT_BYTES {
        return Err(TcpWireError::SegmentTooLarge);
    }
    let total_length = ETHERNET_HEADER_BYTES
        .checked_add(IPV4_HEADER_BYTES)
        .and_then(|length| length.checked_add(TCP_HEADER_BYTES))
        .and_then(|length| length.checked_add(segment.payload.len()))
        .ok_or(TcpWireError::SegmentTooLarge)?;
    if output.len() < total_length {
        return Err(TcpWireError::BufferTooSmall);
    }
    output[..total_length].fill(0);
    output[..6].copy_from_slice(&destination_mac);
    output[6..12].copy_from_slice(&source_mac);
    output[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = ETHERNET_HEADER_BYTES;
    output[ip] = 0x45;
    output[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(total_length - ETHERNET_HEADER_BYTES)
            .unwrap()
            .to_be_bytes(),
    );
    output[ip + 4..ip + 6].copy_from_slice(&identification.to_be_bytes());
    output[ip + 6..ip + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
    output[ip + 8] = 64;
    output[ip + 9] = 6;
    output[ip + 12..ip + 16].copy_from_slice(&segment.source.address);
    output[ip + 16..ip + 20].copy_from_slice(&segment.destination.address);
    let ip_checksum = internet_checksum(&output[ip..ip + IPV4_HEADER_BYTES]);
    output[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());
    let tcp = ip + IPV4_HEADER_BYTES;
    output[tcp..tcp + 2].copy_from_slice(&segment.source.port.to_be_bytes());
    output[tcp + 2..tcp + 4].copy_from_slice(&segment.destination.port.to_be_bytes());
    output[tcp + 4..tcp + 8].copy_from_slice(&segment.sequence.to_be_bytes());
    output[tcp + 8..tcp + 12].copy_from_slice(&segment.acknowledgment.to_be_bytes());
    output[tcp + 12] = 5 << 4;
    output[tcp + 13] = tcp_wire_flags(segment.flags)?;
    output[tcp + 14..tcp + 16].copy_from_slice(&64240_u16.to_be_bytes());
    let payload_start = tcp + TCP_HEADER_BYTES;
    output[payload_start..payload_start + segment.payload.len()].copy_from_slice(segment.payload);
    let checksum = tcp_checksum(
        &segment.source.address,
        &segment.destination.address,
        &output[tcp..total_length],
    );
    output[tcp + 16..tcp + 18].copy_from_slice(&checksum.to_be_bytes());
    Ok(total_length)
}

fn tcp_wire_flags(flags: TcpFlags) -> Result<u8, TcpWireError> {
    let known = TcpFlags::SYN
        .union(TcpFlags::ACK)
        .union(TcpFlags::FIN)
        .union(TcpFlags::RST)
        .union(TcpFlags::PSH);
    if flags.0 & !known.0 != 0 {
        return Err(TcpWireError::UnsupportedFlags);
    }
    let mut wire = 0;
    if flags.contains(TcpFlags::FIN) {
        wire |= 0x01;
    }
    if flags.contains(TcpFlags::SYN) {
        wire |= 0x02;
    }
    if flags.contains(TcpFlags::RST) {
        wire |= 0x04;
    }
    if flags.contains(TcpFlags::PSH) {
        wire |= 0x08;
    }
    if flags.contains(TcpFlags::ACK) {
        wire |= 0x10;
    }
    Ok(wire)
}

fn tcp_checksum(source: &[u8], destination: &[u8], tcp: &[u8]) -> u16 {
    let mut sum = 0_u32;
    sum = checksum_sum(sum, source);
    sum = checksum_sum(sum, destination);
    sum = checksum_sum(sum, &[0, 6]);
    sum = checksum_sum(
        sum,
        &(u16::try_from(tcp.len()).unwrap_or(u16::MAX)).to_be_bytes(),
    );
    sum = checksum_sum(sum, tcp);
    !fold_checksum(sum)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    !fold_checksum(checksum_sum(0, bytes))
}

fn checksum_sum(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut index = 0;
    while index + 1 < bytes.len() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([
            bytes[index],
            bytes[index + 1],
        ])));
        index += 2;
    }
    if index < bytes.len() {
        sum = sum.wrapping_add(u32::from(bytes[index]) << 8);
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
    }
    sum as u16
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'payload> {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: TcpFlags,
    pub payload: &'payload [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
    SynSent,
    Established,
    CloseWait,
    Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpError {
    InvalidBudget,
    WrongEndpoint,
    InvalidHandshake,
    InvalidAcknowledgment,
    InvalidFlags,
    SegmentTooLarge,
    ReassemblyFull,
    OverlappingSegment,
    ConnectionReset,
    WrongState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpObservation {
    SendAck { sequence: u32, acknowledgment: u32 },
    Buffered,
    PeerFinished { sequence: u32, acknowledgment: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainReceipt {
    pub bytes: u16,
    pub segments: u8,
    pub must_yield: bool,
    pub next_acknowledgment: u32,
}

#[derive(Clone, Copy)]
struct Fragment {
    sequence: u32,
    offset: u16,
    length: u16,
    occupied: bool,
}

impl Fragment {
    const EMPTY: Self = Self {
        sequence: 0,
        offset: 0,
        length: 0,
        occupied: false,
    };
}

/// One connection-local, non-cloneable protocol state. Callers submit copied
/// segments, drain at a bounded safe point, then use `next_acknowledgment` in
/// the e1000-owned response frame. The payload never aliases the RX DMA ring.
pub struct TcpConnection {
    local: Endpoint,
    remote: Endpoint,
    state: TcpState,
    next_send: u32,
    next_receive: u32,
    budget: TcpBudget,
    fragments: [Fragment; MAX_REASSEMBLY_SEGMENTS],
    fragment_count: u8,
    storage: [u8; MAX_REASSEMBLY_BYTES],
    storage_used: u16,
    pending_fin: bool,
}

impl TcpConnection {
    /// Begins a client-side TCP handshake and returns the exact SYN metadata
    /// for the e1000 framing layer to encode.
    pub fn begin(
        local: Endpoint,
        remote: Endpoint,
        initial_sequence: u32,
        budget: TcpBudget,
    ) -> Result<(Self, TcpSegment<'static>), TcpError> {
        if local.port == 0 || remote.port == 0 || !budget.is_valid() {
            return Err(TcpError::InvalidBudget);
        }
        let connection = Self {
            local,
            remote,
            state: TcpState::SynSent,
            next_send: initial_sequence.wrapping_add(1),
            next_receive: 0,
            budget,
            fragments: [Fragment::EMPTY; MAX_REASSEMBLY_SEGMENTS],
            fragment_count: 0,
            storage: [0; MAX_REASSEMBLY_BYTES],
            storage_used: 0,
            pending_fin: false,
        };
        Ok((
            connection,
            TcpSegment {
                source: local,
                destination: remote,
                sequence: initial_sequence,
                acknowledgment: 0,
                flags: TcpFlags::SYN,
                payload: &[],
            },
        ))
    }

    pub const fn state(&self) -> TcpState {
        self.state
    }

    pub const fn next_acknowledgment(&self) -> u32 {
        self.next_receive
    }

    /// Accepts a peer segment into a bounded reassembly queue. Payload does
    /// not become visible until `drain_contiguous` copies an in-order prefix
    /// into the broker-owned output buffer.
    pub fn observe(&mut self, segment: TcpSegment<'_>) -> Result<TcpObservation, TcpError> {
        if segment.source != self.remote || segment.destination != self.local {
            return Err(TcpError::WrongEndpoint);
        }
        if segment.flags.contains(TcpFlags::RST) {
            self.state = TcpState::Reset;
            return Err(TcpError::ConnectionReset);
        }
        match self.state {
            TcpState::SynSent => self.accept_syn_ack(segment),
            TcpState::Established | TcpState::CloseWait => self.accept_data(segment),
            TcpState::Reset => Err(TcpError::ConnectionReset),
        }
    }

    /// Copies the next contiguous sequence prefix into `output`. It drains no
    /// more than the lease's configured segment slice, making the caller's
    /// scheduler yield point explicit and testable.
    pub fn drain_contiguous(&mut self, output: &mut [u8]) -> DrainReceipt {
        let mut written = 0_usize;
        let mut drained = 0_u8;
        while drained < self.budget.yield_every_segments {
            let Some(index) = self.fragment_for(self.next_receive) else {
                break;
            };
            let fragment = self.fragments[index];
            let length = usize::from(fragment.length);
            if written.saturating_add(length) > output.len() {
                break;
            }
            let source = usize::from(fragment.offset);
            output[written..written + length]
                .copy_from_slice(&self.storage[source..source + length]);
            written += length;
            drained += 1;
            self.next_receive = self.next_receive.wrapping_add(u32::from(fragment.length));
            self.fragments[index] = Fragment::EMPTY;
            self.fragment_count -= 1;
        }
        if self.pending_fin && self.fragment_for(self.next_receive).is_none() {
            self.next_receive = self.next_receive.wrapping_add(1);
            self.pending_fin = false;
            self.state = TcpState::CloseWait;
        }
        DrainReceipt {
            bytes: written as u16,
            segments: drained,
            must_yield: drained == self.budget.yield_every_segments,
            next_acknowledgment: self.next_receive,
        }
    }

    fn accept_syn_ack(&mut self, segment: TcpSegment<'_>) -> Result<TcpObservation, TcpError> {
        if segment.flags != TcpFlags::SYN.union(TcpFlags::ACK)
            || !segment.payload.is_empty()
            || segment.acknowledgment != self.next_send
        {
            return Err(TcpError::InvalidHandshake);
        }
        self.next_receive = segment.sequence.wrapping_add(1);
        self.state = TcpState::Established;
        Ok(TcpObservation::SendAck {
            sequence: self.next_send,
            acknowledgment: self.next_receive,
        })
    }

    fn accept_data(&mut self, segment: TcpSegment<'_>) -> Result<TcpObservation, TcpError> {
        if !segment.flags.contains(TcpFlags::ACK) || segment.acknowledgment != self.next_send {
            return Err(TcpError::InvalidAcknowledgment);
        }
        let allowed_flags = TcpFlags::ACK.union(TcpFlags::FIN).union(TcpFlags::PSH);
        if segment.flags.0 & !allowed_flags.0 != 0 {
            return Err(TcpError::InvalidFlags);
        }
        if segment.payload.len() > MAX_TCP_SEGMENT_BYTES {
            return Err(TcpError::SegmentTooLarge);
        }
        if segment.payload.is_empty() {
            if segment.flags.contains(TcpFlags::FIN) {
                if segment.sequence != self.next_receive {
                    return Err(TcpError::OverlappingSegment);
                }
                self.pending_fin = true;
                return Ok(TcpObservation::PeerFinished {
                    sequence: self.next_send,
                    acknowledgment: self.next_receive,
                });
            }
            return Ok(TcpObservation::SendAck {
                sequence: self.next_send,
                acknowledgment: self.next_receive,
            });
        }
        if segment.sequence < self.next_receive {
            return Ok(TcpObservation::SendAck {
                sequence: self.next_send,
                acknowledgment: self.next_receive,
            });
        }
        self.store_fragment(segment.sequence, segment.payload)?;
        if segment.flags.contains(TcpFlags::FIN) {
            self.pending_fin = true;
        }
        Ok(TcpObservation::Buffered)
    }

    fn store_fragment(&mut self, sequence: u32, payload: &[u8]) -> Result<(), TcpError> {
        if self.fragment_count >= self.budget.max_segments {
            return Err(TcpError::ReassemblyFull);
        }
        let payload_length = u16::try_from(payload.len()).map_err(|_| TcpError::SegmentTooLarge)?;
        let end = sequence.wrapping_add(u32::from(payload_length));
        for fragment in self.fragments.iter().filter(|fragment| fragment.occupied) {
            let fragment_end = fragment.sequence.wrapping_add(u32::from(fragment.length));
            if sequence < fragment_end && fragment.sequence < end {
                return Err(TcpError::OverlappingSegment);
            }
        }
        let start = usize::from(self.storage_used);
        let storage_end = start
            .checked_add(payload.len())
            .ok_or(TcpError::ReassemblyFull)?;
        if storage_end > usize::from(self.budget.max_bytes) || storage_end > MAX_REASSEMBLY_BYTES {
            return Err(TcpError::ReassemblyFull);
        }
        let Some(index) = self
            .fragments
            .iter()
            .position(|fragment| !fragment.occupied)
        else {
            return Err(TcpError::ReassemblyFull);
        };
        self.storage[start..storage_end].copy_from_slice(payload);
        self.fragments[index] = Fragment {
            sequence,
            offset: self.storage_used,
            length: payload_length,
            occupied: true,
        };
        self.storage_used = storage_end as u16;
        self.fragment_count += 1;
        Ok(())
    }

    fn fragment_for(&self, sequence: u32) -> Option<usize> {
        self.fragments
            .iter()
            .position(|fragment| fragment.occupied && fragment.sequence == sequence)
    }

    pub const fn local_endpoint(&self) -> Endpoint {
        self.local
    }

    pub const fn remote_endpoint(&self) -> Endpoint {
        self.remote
    }

    pub const fn next_send_sequence(&self) -> u32 {
        self.next_send
    }

    pub const fn acknowledgment_segment(&self) -> TcpSegment<'static> {
        TcpSegment {
            source: self.local,
            destination: self.remote,
            sequence: self.next_send,
            acknowledgment: self.next_receive,
            flags: TcpFlags::ACK,
            payload: &[],
        }
    }

    pub fn commit_send(&mut self, payload_bytes: usize, fin: bool) -> Result<(), TcpError> {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err(TcpError::WrongState);
        }
        let payload_bytes = u32::try_from(payload_bytes).map_err(|_| TcpError::SegmentTooLarge)?;
        self.next_send = self
            .next_send
            .wrapping_add(payload_bytes)
            .wrapping_add(u32::from(fin));
        Ok(())
    }
}

/// Maximum response-header bytes accepted before the HTTP layer yields a
/// protocol error. This is deliberately smaller than the TCP payload budget;
/// a peer cannot consume the complete reassembly arena with headers alone.
pub const MAX_HTTP_HEADER_BYTES: usize = 2 * 1024;
pub const MAX_HTTP_HEADERS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpResponse<'body> {
    status: u16,
    body: &'body [u8],
}

impl<'body> HttpResponse<'body> {
    pub const fn status(self) -> u16 {
        self.status
    }

    pub const fn body(self) -> &'body [u8] {
        self.body
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    Incomplete,
    HeaderTooLarge,
    InvalidStatusLine,
    InvalidHeader,
    TooManyHeaders,
    UnsupportedTransferEncoding,
    InvalidContentLength,
    BodyTooLarge,
    BodyIncomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRequestError {
    BufferTooSmall,
    BudgetExceeded,
}

/// Encodes the only request shape currently admitted by Argus: a canonical
/// origin-bound GET with a close-delimited response. The validated request is
/// the source of both the path and Host header; callers cannot inject a
/// second authority or an arbitrary method.
pub fn encode_https_get(
    request: &HttpsRequest,
    output: &mut [u8],
) -> Result<usize, HttpRequestError> {
    let mut length = 0_usize;
    append_request_bytes(&mut length, output, b"GET ")?;
    append_request_bytes(&mut length, output, request.path())?;
    append_request_bytes(&mut length, output, b" HTTP/1.1\r\nHost: ")?;
    append_request_bytes(&mut length, output, request.origin().host())?;
    append_request_bytes(
        &mut length,
        output,
        b"\r\nAccept: text/html\r\nConnection: close\r\n\r\n",
    )?;
    if length > usize::from(request.budget().request_bytes) {
        return Err(HttpRequestError::BudgetExceeded);
    }
    Ok(length)
}

fn append_request_bytes(
    length: &mut usize,
    output: &mut [u8],
    bytes: &[u8],
) -> Result<(), HttpRequestError> {
    let end = length
        .checked_add(bytes.len())
        .ok_or(HttpRequestError::BufferTooSmall)?;
    if end > output.len() {
        return Err(HttpRequestError::BufferTooSmall);
    }
    output[*length..end].copy_from_slice(bytes);
    *length = end;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsRecord<'payload> {
    content_type: u8,
    version: u16,
    payload: &'payload [u8],
}

impl<'payload> TlsRecord<'payload> {
    pub const fn content_type(self) -> u8 {
        self.content_type
    }

    pub const fn version(self) -> u16 {
        self.version
    }

    pub const fn payload(self) -> &'payload [u8] {
        self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsError {
    Incomplete,
    InvalidHeader,
    UnsupportedVersion,
    UnsupportedContentType,
    RecordTooLarge,
    CertificateEmpty,
    CertificateTooLarge,
    CertificateTrust(TlsTrustError),
}

/// Hashes one broker-delivered DER certificate and checks it against the
/// generation-bound pin selected by Hermes. Arach must perform full DER
/// chain and hostname validation before publishing the anchor; this function
/// intentionally performs no ambient trust-store lookup and never treats an
/// arbitrary certificate as trusted.
pub fn verify_pinned_certificate(
    anchor: TlsTrustAnchor,
    origin: slope::hypermedia::HttpsOrigin,
    certificate_der: &[u8],
    generation: u32,
) -> Result<TlsPeerIdentity, TlsError> {
    if certificate_der.is_empty() {
        return Err(TlsError::CertificateEmpty);
    }
    if certificate_der.len() > MAX_TLS_CERTIFICATE_BYTES {
        return Err(TlsError::CertificateTooLarge);
    }
    let fingerprint = ::blacklab::oureboros::sha256(certificate_der);
    anchor
        .permits(origin, fingerprint, generation)
        .map_err(TlsError::CertificateTrust)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsHandshakeError {
    WrongContentType,
    IncompleteMessage,
    MessageTooLarge,
    TranscriptTooLarge,
    UnexpectedMessage,
    PeerBeforeCertificate,
    HashFailure,
}

/// Structural TLS handshake transcript gate. It authenticates no keys and
/// does not decrypt TLS 1.3 encrypted handshake records; those operations
/// remain a broker authority. This gate nevertheless prevents malformed or
/// out-of-order plaintext handshake messages from being promoted to Argus and
/// gives the broker a bounded transcript digest to bind to its crypto result.
#[derive(Clone, Copy)]
pub struct TlsHandshakeTranscript {
    transcript: Sha256,
    transcript_bytes: usize,
    client_hello: bool,
    server_hello: bool,
    certificate: bool,
    peer: Option<TlsPeerIdentity>,
    complete: bool,
}

impl TlsHandshakeTranscript {
    pub const fn new() -> Self {
        Self {
            transcript: Sha256::new(),
            transcript_bytes: 0,
            client_hello: false,
            server_hello: false,
            certificate: false,
            peer: None,
            complete: false,
        }
    }

    pub const fn is_complete(self) -> bool {
        self.complete
    }

    pub const fn transcript_bytes(self) -> usize {
        self.transcript_bytes
    }

    pub const fn peer(self) -> Option<TlsPeerIdentity> {
        self.peer
    }

    pub fn accept_peer(&mut self, peer: TlsPeerIdentity) -> Result<(), TlsHandshakeError> {
        if !self.certificate {
            return Err(TlsHandshakeError::PeerBeforeCertificate);
        }
        self.peer = Some(peer);
        Ok(())
    }

    /// Ingests one plaintext handshake record. The record's complete payload
    /// is retained only through the fixed SHA-256 state; no certificate,
    /// socket, or key material is copied into the client process.
    pub fn ingest_record(
        &mut self,
        record: TlsRecord<'_>,
    ) -> Result<TlsHandshakeEvent, TlsHandshakeError> {
        if record.content_type() != 22 {
            return Err(TlsHandshakeError::WrongContentType);
        }
        if self.complete {
            return Err(TlsHandshakeError::UnexpectedMessage);
        }
        let mut candidate = *self;
        let mut offset = 0_usize;
        while offset < record.payload().len() {
            let remaining = &record.payload()[offset..];
            if remaining.len() < 4 {
                return Err(TlsHandshakeError::IncompleteMessage);
            }
            let length = (usize::from(remaining[1]) << 16)
                | (usize::from(remaining[2]) << 8)
                | usize::from(remaining[3]);
            if length > MAX_TLS_HANDSHAKE_BYTES {
                return Err(TlsHandshakeError::MessageTooLarge);
            }
            let end = 4_usize
                .checked_add(length)
                .and_then(|value| offset.checked_add(value))
                .ok_or(TlsHandshakeError::MessageTooLarge)?;
            if end > record.payload().len() {
                return Err(TlsHandshakeError::IncompleteMessage);
            }
            let message = &record.payload()[offset..end];
            let next_total = candidate
                .transcript_bytes
                .checked_add(message.len())
                .ok_or(TlsHandshakeError::TranscriptTooLarge)?;
            if next_total > MAX_TLS_HANDSHAKE_BYTES {
                return Err(TlsHandshakeError::TranscriptTooLarge);
            }
            candidate
                .transcript
                .update(message)
                .map_err(|_| TlsHandshakeError::HashFailure)?;
            candidate.transcript_bytes = next_total;
            candidate.consume_message(remaining[0])?;
            offset = end;
        }
        *self = candidate;
        Ok(TlsHandshakeEvent {
            transcript_bytes: self.transcript_bytes,
            complete: self.complete,
        })
    }

    pub fn transcript_digest(self) -> Option<[u8; 32]> {
        self.complete.then(|| self.transcript.finalize())
    }

    fn consume_message(&mut self, message_type: u8) -> Result<(), TlsHandshakeError> {
        match message_type {
            1 if !self.client_hello && !self.server_hello => self.client_hello = true,
            2 if self.client_hello && !self.server_hello => self.server_hello = true,
            // TLS 1.3's EncryptedExtensions and TLS 1.2 key-exchange messages
            // are structurally admitted; the encrypted records themselves are
            // still rejected by ingest_record's content-type gate.
            8 | 12 | 14 | 15 | 16 if self.server_hello => {}
            11 if self.server_hello && !self.certificate => self.certificate = true,
            20 if self.server_hello && self.certificate && self.peer.is_some() => {
                self.complete = true
            }
            _ => return Err(TlsHandshakeError::UnexpectedMessage),
        }
        Ok(())
    }
}

impl Default for TlsHandshakeTranscript {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsHandshakeEvent {
    pub transcript_bytes: usize,
    pub complete: bool,
}

/// Validates one TLS record boundary without decrypting it. Cryptographic
/// handshake, certificate validation, and key schedule remain a separate
/// broker authority; this layer only prevents malformed record lengths and
/// unsupported protocol versions from reaching it.
pub fn parse_tls_record(bytes: &[u8]) -> Result<TlsRecord<'_>, TlsError> {
    if bytes.len() < 5 {
        return Err(TlsError::Incomplete);
    }
    let content_type = bytes[0];
    if !matches!(content_type, 20..=23) {
        return Err(TlsError::UnsupportedContentType);
    }
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);
    if !(0x0301..=0x0303).contains(&version) {
        return Err(TlsError::UnsupportedVersion);
    }
    let length = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    if length > MAX_TLS_RECORD_BYTES {
        return Err(TlsError::RecordTooLarge);
    }
    let end = 5_usize.saturating_add(length);
    if bytes.len() < end {
        return Err(TlsError::Incomplete);
    }
    Ok(TlsRecord {
        content_type,
        version,
        payload: &bytes[5..end],
    })
}

pub const TLS13_TAG_BYTES: usize = 16;
pub const TLS13_INNER_TYPE_BYTES: usize = 1;
pub const MAX_TLS13_PLAINTEXT_BYTES: usize =
    MAX_TLS_RECORD_BYTES - TLS13_TAG_BYTES - TLS13_INNER_TYPE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsKeyScheduleError {
    InvalidSecret,
    ExpandFailed,
}

/// The traffic key and IV selected by the authenticated TLS 1.3 key schedule.
/// The record layer never accepts a caller-provided nonce; every nonce is the
/// traffic IV XORed with the monotonically increasing record sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tls13TrafficKey {
    key: [u8; 32],
    iv: [u8; 12],
}

impl Tls13TrafficKey {
    pub fn from_traffic_secret(secret: &[u8]) -> Result<Self, TlsKeyScheduleError> {
        if secret.len() != 32 {
            return Err(TlsKeyScheduleError::InvalidSecret);
        }
        let mut secret_bytes = [0_u8; 32];
        secret_bytes.copy_from_slice(secret);
        let mut key = [0_u8; 32];
        let mut iv = [0_u8; 12];
        hkdf_expand_label(&secret_bytes, b"key", &mut key)?;
        hkdf_expand_label(&secret_bytes, b"iv", &mut iv)?;
        Ok(Self { key, iv })
    }

    pub const fn key(self) -> [u8; 32] {
        self.key
    }

    pub const fn iv(self) -> [u8; 12] {
        self.iv
    }
}

fn hkdf_expand_label(
    secret: &[u8; 32],
    label: &[u8],
    output: &mut [u8],
) -> Result<(), TlsKeyScheduleError> {
    const PREFIX: &[u8] = b"tls13 ";
    let full_label_length = PREFIX
        .len()
        .checked_add(label.len())
        .ok_or(TlsKeyScheduleError::ExpandFailed)?;
    let info_length = 2_usize
        .checked_add(1)
        .and_then(|length| length.checked_add(full_label_length))
        .and_then(|length| length.checked_add(1))
        .ok_or(TlsKeyScheduleError::ExpandFailed)?;
    if full_label_length > u8::MAX as usize || info_length > 32 {
        return Err(TlsKeyScheduleError::ExpandFailed);
    }
    let output_length =
        u16::try_from(output.len()).map_err(|_| TlsKeyScheduleError::ExpandFailed)?;
    let mut info = [0_u8; 32];
    info[..2].copy_from_slice(&output_length.to_be_bytes());
    info[2] = full_label_length as u8;
    let mut cursor = 3;
    info[cursor..cursor + PREFIX.len()].copy_from_slice(PREFIX);
    cursor += PREFIX.len();
    info[cursor..cursor + label.len()].copy_from_slice(label);
    cursor += label.len();
    info[cursor] = 0;
    let message_length = info_length
        .checked_add(1)
        .ok_or(TlsKeyScheduleError::ExpandFailed)?;
    info[info_length] = 1;
    let digest = hmac_sha256(secret, &info[..message_length]);
    output.copy_from_slice(&digest[..output.len()]);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsRecordCryptoError {
    Framing(TlsError),
    TrailingBytes,
    UnsupportedVersion,
    UnsupportedOuterContentType,
    InvalidInnerContentType,
    InvalidPadding,
    PlaintextTooLarge,
    CiphertextTooLarge,
    BufferTooSmall,
    AuthenticationFailed,
    CipherFailure,
    SequenceExhausted,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tls13Plaintext<'payload> {
    content_type: u8,
    payload: &'payload [u8],
}

impl<'payload> Tls13Plaintext<'payload> {
    pub const fn content_type(self) -> u8 {
        self.content_type
    }

    pub const fn payload(self) -> &'payload [u8] {
        self.payload
    }
}

/// Bounded TLS 1.3 ChaCha20-Poly1305 record protection. This is deliberately
/// only the post-handshake record layer: a broker must still authenticate the
/// peer, derive the traffic secret, and transfer that secret through the
/// measured Hermes/Push capability before constructing this type.
pub struct Tls13RecordProtector {
    traffic: Tls13TrafficKey,
    sequence: u64,
    poisoned: bool,
}

impl Tls13RecordProtector {
    pub const fn new(traffic: Tls13TrafficKey) -> Self {
        Self {
            traffic,
            sequence: 0,
            poisoned: false,
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn seal(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize, TlsRecordCryptoError> {
        self.ensure_usable()?;
        validate_inner_content_type(content_type)?;
        if plaintext.len() > MAX_TLS13_PLAINTEXT_BYTES {
            return Err(TlsRecordCryptoError::PlaintextTooLarge);
        }
        let ciphertext_length = plaintext
            .len()
            .checked_add(TLS13_INNER_TYPE_BYTES)
            .and_then(|length| length.checked_add(TLS13_TAG_BYTES))
            .ok_or(TlsRecordCryptoError::CiphertextTooLarge)?;
        let total_length = 5_usize
            .checked_add(ciphertext_length)
            .ok_or(TlsRecordCryptoError::CiphertextTooLarge)?;
        if ciphertext_length > MAX_TLS_RECORD_BYTES {
            return Err(TlsRecordCryptoError::CiphertextTooLarge);
        }
        if output.len() < total_length {
            return Err(TlsRecordCryptoError::BufferTooSmall);
        }
        let wire_length = u16::try_from(ciphertext_length)
            .map_err(|_| TlsRecordCryptoError::CiphertextTooLarge)?;
        output[..3].copy_from_slice(&[23, 0x03, 0x03]);
        output[3..5].copy_from_slice(&wire_length.to_be_bytes());
        let inner_length = plaintext.len() + TLS13_INNER_TYPE_BYTES;
        output[5..5 + plaintext.len()].copy_from_slice(plaintext);
        output[5 + plaintext.len()] = content_type;
        let nonce = self.nonce();
        let aad = [output[0], output[1], output[2], output[3], output[4]];
        let one_time_key = chacha20_block(&self.traffic.key, 0, &nonce);
        chacha20_xor(
            &self.traffic.key,
            &nonce,
            1,
            &mut output[5..5 + inner_length],
        );
        let tag = poly1305_authenticate(
            &one_time_key[..POLY1305_KEY_BYTES],
            &aad,
            &output[5..5 + inner_length],
        );
        output[5 + inner_length..total_length].copy_from_slice(&tag);
        self.advance_sequence()?;
        Ok(total_length)
    }

    pub fn open<'output>(
        &mut self,
        wire: &[u8],
        output: &'output mut [u8],
    ) -> Result<Tls13Plaintext<'output>, TlsRecordCryptoError> {
        self.ensure_usable()?;
        let record = parse_tls_record(wire).map_err(TlsRecordCryptoError::Framing)?;
        if wire.len() != 5 + record.payload().len() {
            return Err(TlsRecordCryptoError::TrailingBytes);
        }
        if record.version() != 0x0303 {
            return Err(TlsRecordCryptoError::UnsupportedVersion);
        }
        if record.content_type() != 23 {
            return Err(TlsRecordCryptoError::UnsupportedOuterContentType);
        }
        if record.payload().len() < TLS13_TAG_BYTES + TLS13_INNER_TYPE_BYTES {
            self.poisoned = true;
            return Err(TlsRecordCryptoError::InvalidPadding);
        }
        let ciphertext_length = record.payload().len() - TLS13_TAG_BYTES;
        if ciphertext_length > MAX_TLS13_PLAINTEXT_BYTES + TLS13_INNER_TYPE_BYTES {
            return Err(TlsRecordCryptoError::CiphertextTooLarge);
        }
        if output.len() < ciphertext_length {
            return Err(TlsRecordCryptoError::BufferTooSmall);
        }
        let nonce = self.nonce();
        let one_time_key = chacha20_block(&self.traffic.key, 0, &nonce);
        let expected = poly1305_authenticate(
            &one_time_key[..POLY1305_KEY_BYTES],
            &wire[..5],
            &record.payload()[..ciphertext_length],
        );
        if !constant_time_equal_16(
            &expected,
            &record.payload()[ciphertext_length..ciphertext_length + TLS13_TAG_BYTES],
        ) {
            self.poisoned = true;
            return Err(TlsRecordCryptoError::AuthenticationFailed);
        }
        output[..ciphertext_length].copy_from_slice(&record.payload()[..ciphertext_length]);
        chacha20_xor(
            &self.traffic.key,
            &nonce,
            1,
            &mut output[..ciphertext_length],
        );
        let mut inner_end = ciphertext_length;
        while inner_end != 0 && output[inner_end - 1] == 0 {
            inner_end -= 1;
        }
        if inner_end == 0 {
            self.poisoned = true;
            return Err(TlsRecordCryptoError::InvalidPadding);
        }
        let content_type = output[inner_end - 1];
        if !is_tls_inner_content_type(content_type) {
            self.poisoned = true;
            return Err(TlsRecordCryptoError::InvalidInnerContentType);
        }
        self.advance_sequence()?;
        Ok(Tls13Plaintext {
            content_type,
            payload: &output[..inner_end - 1],
        })
    }

    fn ensure_usable(&self) -> Result<(), TlsRecordCryptoError> {
        if self.poisoned {
            Err(TlsRecordCryptoError::Poisoned)
        } else if self.sequence == u64::MAX {
            Err(TlsRecordCryptoError::SequenceExhausted)
        } else {
            Ok(())
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.traffic.iv;
        let sequence = self.sequence.to_be_bytes();
        for index in 0..sequence.len() {
            nonce[4 + index] ^= sequence[index];
        }
        nonce
    }

    fn advance_sequence(&mut self) -> Result<(), TlsRecordCryptoError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(TlsRecordCryptoError::SequenceExhausted)?;
        Ok(())
    }
}

fn is_tls_inner_content_type(content_type: u8) -> bool {
    matches!(content_type, 20..=23)
}

fn validate_inner_content_type(content_type: u8) -> Result<(), TlsRecordCryptoError> {
    if is_tls_inner_content_type(content_type) {
        Ok(())
    } else {
        Err(TlsRecordCryptoError::InvalidInnerContentType)
    }
}

const POLY1305_KEY_BYTES: usize = 32;
const POLY1305_TAG_BYTES: usize = 16;
const POLY1305_BLOCK_BYTES: usize = 16;

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..key.len() {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Sha256::new();
    let _ = inner.update(&inner_pad);
    let _ = inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    let _ = outer.update(&outer_pad);
    let _ = outer.update(&inner_digest);
    outer.finalize()
}

fn load_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0_u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for index in 0..8 {
        state[4 + index] = load_u32_le(&key[index * 4..index * 4 + 4]);
    }
    state[12] = counter;
    for index in 0..3 {
        state[13 + index] = load_u32_le(&nonce[index * 4..index * 4 + 4]);
    }
    let initial = state;
    for _ in 0..10 {
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut output = [0_u8; 64];
    for index in 0..16 {
        output[index * 4..index * 4 + 4]
            .copy_from_slice(&state[index].wrapping_add(initial[index]).to_le_bytes());
    }
    output
}

fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], mut counter: u32, bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(64) {
        let keystream = chacha20_block(key, counter, nonce);
        for (byte, mask) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= *mask;
        }
        counter = counter.wrapping_add(1);
    }
}

struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buffer: [u8; POLY1305_BLOCK_BYTES],
    buffer_len: usize,
}

impl Poly1305 {
    fn new(key: &[u8; POLY1305_KEY_BYTES]) -> Self {
        Self {
            r: [
                load_u32_le(&key[0..4]) & 0x3ff_ffff,
                (load_u32_le(&key[3..7]) >> 2) & 0x3ff_ff03,
                (load_u32_le(&key[6..10]) >> 4) & 0x3ff_c0ff,
                (load_u32_le(&key[9..13]) >> 6) & 0x3f0_3fff,
                (load_u32_le(&key[12..16]) >> 8) & 0x00f_ffff,
            ],
            h: [0; 5],
            pad: [
                load_u32_le(&key[16..20]),
                load_u32_le(&key[20..24]),
                load_u32_le(&key[24..28]),
                load_u32_le(&key[28..32]),
            ],
            buffer: [0; POLY1305_BLOCK_BYTES],
            buffer_len: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        if self.buffer_len != 0 {
            let take = (POLY1305_BLOCK_BYTES - self.buffer_len).min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&bytes[..take]);
            self.buffer_len += take;
            bytes = &bytes[take..];
            if self.buffer_len == POLY1305_BLOCK_BYTES {
                let block = self.buffer;
                self.process_block(&block, false);
                self.buffer = [0; POLY1305_BLOCK_BYTES];
                self.buffer_len = 0;
            }
        }
        while bytes.len() >= POLY1305_BLOCK_BYTES {
            let mut block = [0_u8; POLY1305_BLOCK_BYTES];
            block.copy_from_slice(&bytes[..POLY1305_BLOCK_BYTES]);
            self.process_block(&block, false);
            bytes = &bytes[POLY1305_BLOCK_BYTES..];
        }
        if !bytes.is_empty() {
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.buffer_len = bytes.len();
        }
    }

    fn process_block(&mut self, block: &[u8; POLY1305_BLOCK_BYTES], partial: bool) {
        let hibit = if partial { 0 } else { 1 << 24 };
        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];
        h0 += load_u32_le(&block[0..4]) & 0x3ff_ffff;
        h1 += (load_u32_le(&block[3..7]) >> 2) & 0x3ff_ffff;
        h2 += (load_u32_le(&block[6..10]) >> 4) & 0x3ff_ffff;
        h3 += (load_u32_le(&block[9..13]) >> 6) & 0x3ff_ffff;
        h4 += (load_u32_le(&block[12..16]) >> 8) | hibit;
        let d0 = u64::from(h0) * u64::from(r0)
            + u64::from(h1) * u64::from(s4)
            + u64::from(h2) * u64::from(s3)
            + u64::from(h3) * u64::from(s2)
            + u64::from(h4) * u64::from(s1);
        let mut d1 = u64::from(h0) * u64::from(r1)
            + u64::from(h1) * u64::from(r0)
            + u64::from(h2) * u64::from(s4)
            + u64::from(h3) * u64::from(s3)
            + u64::from(h4) * u64::from(s2);
        let mut d2 = u64::from(h0) * u64::from(r2)
            + u64::from(h1) * u64::from(r1)
            + u64::from(h2) * u64::from(r0)
            + u64::from(h3) * u64::from(s4)
            + u64::from(h4) * u64::from(s3);
        let mut d3 = u64::from(h0) * u64::from(r3)
            + u64::from(h1) * u64::from(r2)
            + u64::from(h2) * u64::from(r1)
            + u64::from(h3) * u64::from(r0)
            + u64::from(h4) * u64::from(s4);
        let mut d4 = u64::from(h0) * u64::from(r4)
            + u64::from(h1) * u64::from(r3)
            + u64::from(h2) * u64::from(r2)
            + u64::from(h3) * u64::from(r1)
            + u64::from(h4) * u64::from(r0);
        let mut carry = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ff_ffff;
        d1 += u64::from(carry);
        carry = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ff_ffff;
        d2 += u64::from(carry);
        carry = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ff_ffff;
        d3 += u64::from(carry);
        carry = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ff_ffff;
        d4 += u64::from(carry);
        carry = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ff_ffff;
        h0 += carry * 5;
        carry = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += carry;
        self.h = [h0, h1, h2, h3, h4];
    }

    fn finish(mut self) -> [u8; POLY1305_TAG_BYTES] {
        if self.buffer_len != 0 {
            let mut block = [0_u8; POLY1305_BLOCK_BYTES];
            block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            block[self.buffer_len] = 1;
            self.process_block(&block, true);
        }
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];
        let mut carry = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += carry;
        carry = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += carry;
        carry = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += carry;
        carry = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += carry * 5;
        carry = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += carry;
        let mut g0 = h0.wrapping_add(5);
        carry = g0 >> 26;
        g0 &= 0x3ff_ffff;
        let mut g1 = h1.wrapping_add(carry);
        carry = g1 >> 26;
        g1 &= 0x3ff_ffff;
        let mut g2 = h2.wrapping_add(carry);
        carry = g2 >> 26;
        g2 &= 0x3ff_ffff;
        let mut g3 = h3.wrapping_add(carry);
        carry = g3 >> 26;
        g3 &= 0x3ff_ffff;
        let g4 = h4.wrapping_add(carry).wrapping_sub(1 << 26);
        let mut mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 as u32 & mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;
        h0 |= h1 << 26;
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);
        let mut tag = [0_u8; POLY1305_TAG_BYTES];
        let mut f = u64::from(h0) + u64::from(self.pad[0]);
        tag[0..4].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
        tag[4..8].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
        tag[8..12].copy_from_slice(&(f as u32).to_le_bytes());
        f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
        tag[12..16].copy_from_slice(&(f as u32).to_le_bytes());
        tag
    }
}

fn poly1305_authenticate(key: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let key: &[u8; POLY1305_KEY_BYTES] = key.try_into().unwrap();
    let mut mac = Poly1305::new(key);
    let mut padding = [0_u8; POLY1305_BLOCK_BYTES];
    mac.update(aad);
    if aad.len() % POLY1305_BLOCK_BYTES != 0 {
        let length = POLY1305_BLOCK_BYTES - aad.len() % POLY1305_BLOCK_BYTES;
        mac.update(&padding[..length]);
    }
    mac.update(ciphertext);
    if ciphertext.len() % POLY1305_BLOCK_BYTES != 0 {
        padding.fill(0);
        let length = POLY1305_BLOCK_BYTES - ciphertext.len() % POLY1305_BLOCK_BYTES;
        mac.update(&padding[..length]);
    }
    let mut lengths = [0_u8; POLY1305_BLOCK_BYTES];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.update(&lengths);
    mac.finish()
}

fn constant_time_equal_16(left: &[u8; 16], right: &[u8]) -> bool {
    if right.len() != 16 {
        return false;
    }
    let mut difference = 0_u8;
    for index in 0..16 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

/// Parses one complete or incrementally received HTTP/1.1 response. The
/// parser is intentionally conservative: it accepts only CRLF framing, one
/// bounded Content-Length, and identity-delimited bodies. Chunked transfer
/// coding and connection upgrades are rejected until a separately verified
/// broker implementation exists.
pub fn parse_http_response(bytes: &[u8], complete: bool) -> Result<HttpResponse<'_>, HttpError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or_else(|| {
            if bytes.len() > MAX_HTTP_HEADER_BYTES {
                HttpError::HeaderTooLarge
            } else {
                HttpError::Incomplete
            }
        })?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err(HttpError::HeaderTooLarge);
    }

    let status_end =
        find_crlf(&bytes[..header_end.saturating_sub(2)]).ok_or(HttpError::InvalidStatusLine)?;
    let status_line = &bytes[..status_end];
    if status_line.len() < 13 || !status_line.starts_with(b"HTTP/1.1 ") {
        return Err(HttpError::InvalidStatusLine);
    }
    let status = parse_status(&status_line[9..12]).ok_or(HttpError::InvalidStatusLine)?;
    if status_line[12] != b' ' {
        return Err(HttpError::InvalidStatusLine);
    }

    let mut header_count = 0_usize;
    let mut content_length = None;
    let mut cursor = status_end + 2;
    while cursor < header_end.saturating_sub(2) {
        let relative_end = find_crlf(&bytes[cursor..header_end.saturating_sub(2)])
            .ok_or(HttpError::InvalidHeader)?;
        let line_end = cursor + relative_end;
        if line_end == cursor {
            return Err(HttpError::InvalidHeader);
        }
        header_count += 1;
        if header_count > MAX_HTTP_HEADERS {
            return Err(HttpError::TooManyHeaders);
        }
        let line = &bytes[cursor..line_end];
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(HttpError::InvalidHeader)?;
        if colon == 0 || !line[..colon].iter().all(|byte| is_header_name(*byte)) {
            return Err(HttpError::InvalidHeader);
        }
        let value = trim_ows(&line[colon + 1..]);
        if value.iter().any(|byte| *byte < 0x20 && *byte != b'\t') {
            return Err(HttpError::InvalidHeader);
        }
        if ascii_eq_ignore_case(&line[..colon], b"transfer-encoding") {
            return Err(HttpError::UnsupportedTransferEncoding);
        }
        if ascii_eq_ignore_case(&line[..colon], b"content-length") {
            let parsed = parse_decimal(value).ok_or(HttpError::InvalidContentLength)?;
            if parsed > MAX_REASSEMBLY_BYTES {
                return Err(HttpError::BodyTooLarge);
            }
            if let Some(previous) = content_length {
                if previous != parsed {
                    return Err(HttpError::InvalidContentLength);
                }
            } else {
                content_length = Some(parsed);
            }
        }
        cursor = line_end + 2;
    }

    let body = &bytes[header_end..];
    let expected = match content_length {
        Some(length) => length,
        None if complete => body.len(),
        None => return Err(HttpError::Incomplete),
    };
    if body.len() < expected {
        return Err(HttpError::BodyIncomplete);
    }
    if body.len() > expected || expected > MAX_REASSEMBLY_BYTES {
        return Err(HttpError::BodyTooLarge);
    }
    Ok(HttpResponse {
        status,
        body: &body[..expected],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerPhase {
    SynSent,
    RequestPending,
    AwaitingResponse,
    Complete,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerEvent {
    HandshakeAccepted,
    Acknowledged,
    ResponseBuffered { bytes: u16, must_yield: bool },
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerError {
    Lease(HypermediaError),
    Endpoint(EndpointError),
    Tcp(TcpError),
    Wire(TcpWireError),
    Request(HttpRequestError),
    Response(HttpError),
    ResponseBufferFull,
    Nic,
    NotReady,
    WrongPhase,
}

impl From<TcpError> for BrokerError {
    fn from(error: TcpError) -> Self {
        Self::Tcp(error)
    }
}

impl From<TcpWireError> for BrokerError {
    fn from(error: TcpWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<HttpRequestError> for BrokerError {
    fn from(error: HttpRequestError) -> Self {
        Self::Request(error)
    }
}

/// A single capability-bound Argus transaction. The session owns only copied
/// request/response bytes and a [`TcpConnection`]; the caller supplies MAC
/// addresses and an output frame at each bounded step, so no NIC register,
/// descriptor, or raw socket escapes the Arach broker.
pub struct ArgusBrokerSession {
    lease: HttpLease,
    request: HttpsRequest,
    connection: TcpConnection,
    phase: BrokerPhase,
    pending: Option<PendingFrame>,
    request_bytes: [u8; MAX_HTTP_REQUEST_BYTES as usize],
    request_length: usize,
    response_bytes: [u8; MAX_HTTP_RESPONSE_BYTES as usize],
    response_length: usize,
    ipc_sequence: Option<u32>,
}

#[derive(Clone, Copy)]
enum PendingFrame {
    Syn(TcpSegment<'static>),
    Ack,
    Request,
}

impl ArgusBrokerSession {
    pub fn begin_ipc(
        lease: HttpLease,
        wire: &HttpIpcRequest,
        current_epoch: u64,
        local: Endpoint,
        remote: Endpoint,
        initial_sequence: u32,
    ) -> Result<Self, BrokerError> {
        let request = lease
            .authorize_ipc(wire, current_epoch)
            .map_err(BrokerError::Lease)?;
        let mut session = Self::begin(
            lease,
            request,
            current_epoch,
            local,
            remote,
            initial_sequence,
        )?;
        session.ipc_sequence = Some(wire.sequence());
        Ok(session)
    }

    /// Admits one fixed Argus request through the endpoint and mapping lease,
    /// then starts the same bounded transport core used by the direct test
    /// harness.  Endpoint state is committed only after all request and TCP
    /// admission checks succeed.
    pub fn begin_endpoint_ipc(
        lease: HttpLease,
        endpoint: &mut ArgusEndpointSession,
        wire: &HttpIpcRequest,
        current_epoch: u64,
        local: Endpoint,
        remote: Endpoint,
        initial_sequence: u32,
    ) -> Result<Self, BrokerError> {
        let envelope = endpoint
            .prepare(*wire, current_epoch)
            .map_err(BrokerError::Endpoint)?;
        let request = lease
            .authorize_ipc(&envelope.request, current_epoch)
            .map_err(BrokerError::Lease)?;
        let mut session = Self::begin(
            lease,
            request,
            current_epoch,
            local,
            remote,
            initial_sequence,
        )?;
        endpoint.commit(envelope).map_err(BrokerError::Endpoint)?;
        session.ipc_sequence = Some(envelope.request.sequence());
        Ok(session)
    }

    pub fn begin(
        lease: HttpLease,
        request: HttpsRequest,
        current_epoch: u64,
        local: Endpoint,
        remote: Endpoint,
        initial_sequence: u32,
    ) -> Result<Self, BrokerError> {
        lease
            .permits(request, current_epoch)
            .map_err(BrokerError::Lease)?;
        let mut request_bytes = [0_u8; MAX_HTTP_REQUEST_BYTES as usize];
        let request_length = encode_https_get(&request, &mut request_bytes)?;
        let (connection, syn) = TcpConnection::begin(
            local,
            remote,
            initial_sequence,
            TcpBudget {
                max_bytes: request
                    .budget()
                    .response_bytes
                    .min(MAX_REASSEMBLY_BYTES as u16),
                max_segments: request
                    .budget()
                    .max_segments
                    .min(MAX_REASSEMBLY_SEGMENTS as u8),
                yield_every_segments: request
                    .budget()
                    .yield_every_segments
                    .min(MAX_REASSEMBLY_SEGMENTS as u8),
            },
        )?;
        Ok(Self {
            lease,
            request,
            connection,
            phase: BrokerPhase::SynSent,
            pending: Some(PendingFrame::Syn(syn)),
            request_bytes,
            request_length,
            response_bytes: [0; MAX_HTTP_RESPONSE_BYTES as usize],
            response_length: 0,
            ipc_sequence: None,
        })
    }

    /// Releases the endpoint's one-in-flight slot after a complete response.
    /// Revocation remains a separate terminal operation on the endpoint
    /// session and can therefore be performed on timeout or service exit.
    pub fn complete_endpoint(
        &self,
        endpoint: &mut ArgusEndpointSession,
    ) -> Result<(), BrokerError> {
        if self.phase != BrokerPhase::Complete {
            return Err(BrokerError::WrongPhase);
        }
        endpoint
            .complete(self.ipc_sequence.ok_or(BrokerError::WrongPhase)?)
            .map_err(BrokerError::Endpoint)
    }

    pub const fn phase(&self) -> BrokerPhase {
        self.phase
    }

    pub const fn request(&self) -> HttpsRequest {
        self.request
    }

    pub fn transmit(
        &mut self,
        current_epoch: u64,
        output: &mut [u8],
        destination_mac: [u8; 6],
        source_mac: [u8; 6],
        identification: u16,
    ) -> Result<Option<usize>, BrokerError> {
        self.lease
            .permits(self.request, current_epoch)
            .map_err(BrokerError::Lease)?;
        let Some(pending) = self.pending else {
            return Ok(None);
        };
        let segment = match pending {
            PendingFrame::Syn(segment) => segment,
            PendingFrame::Ack => self.connection.acknowledgment_segment(),
            PendingFrame::Request => TcpSegment {
                source: self.connection.local_endpoint(),
                destination: self.connection.remote_endpoint(),
                sequence: self.connection.next_send_sequence(),
                acknowledgment: self.connection.next_acknowledgment(),
                flags: TcpFlags::ACK.union(TcpFlags::PSH).union(TcpFlags::FIN),
                payload: &self.request_bytes[..self.request_length],
            },
        };
        let length =
            encode_tcp_frame(output, destination_mac, source_mac, segment, identification)?;
        self.pending = None;
        match pending {
            PendingFrame::Syn(_) => {}
            PendingFrame::Ack => {}
            PendingFrame::Request => {
                self.connection
                    .commit_send(self.request_length, true)
                    .map_err(BrokerError::Tcp)?;
                self.phase = BrokerPhase::AwaitingResponse;
            }
        }
        Ok(Some(length))
    }

    pub fn receive(
        &mut self,
        current_epoch: u64,
        frame: &[u8],
        local_mac: [u8; 6],
    ) -> Result<BrokerEvent, BrokerError> {
        self.lease
            .permits(self.request, current_epoch)
            .map_err(BrokerError::Lease)?;
        if matches!(self.phase, BrokerPhase::Complete | BrokerPhase::Failed) {
            return Err(BrokerError::WrongPhase);
        }
        let segment = parse_tcp_frame(
            frame,
            local_mac,
            self.connection.local_endpoint().address,
            self.connection.remote_endpoint().address,
            self.connection.local_endpoint().port,
            self.connection.remote_endpoint().port,
        )?;
        let observation = self.connection.observe(segment)?;
        match (self.phase, observation) {
            (BrokerPhase::SynSent, TcpObservation::SendAck { .. }) => {
                self.phase = BrokerPhase::RequestPending;
                self.pending = Some(PendingFrame::Request);
                Ok(BrokerEvent::HandshakeAccepted)
            }
            (_, TcpObservation::Buffered) | (_, TcpObservation::PeerFinished { .. }) => {
                if self.response_length == self.response_bytes.len() {
                    self.phase = BrokerPhase::Failed;
                    return Err(BrokerError::ResponseBufferFull);
                }
                let available = &mut self.response_bytes[self.response_length..];
                let receipt = self.connection.drain_contiguous(available);
                self.response_length = self
                    .response_length
                    .checked_add(usize::from(receipt.bytes))
                    .ok_or(BrokerError::ResponseBufferFull)?;
                if self.connection.state() == TcpState::CloseWait {
                    parse_http_response(&self.response_bytes[..self.response_length], true)
                        .map_err(BrokerError::Response)?;
                    self.phase = BrokerPhase::Complete;
                    self.pending = Some(PendingFrame::Ack);
                    return Ok(BrokerEvent::Complete);
                }
                self.pending = Some(PendingFrame::Ack);
                Ok(BrokerEvent::ResponseBuffered {
                    bytes: receipt.bytes,
                    must_yield: receipt.must_yield,
                })
            }
            (_, TcpObservation::SendAck { .. }) => {
                self.pending = Some(PendingFrame::Ack);
                Ok(BrokerEvent::Acknowledged)
            }
        }
    }

    pub fn response(&self) -> Result<HttpResponse<'_>, BrokerError> {
        if self.phase != BrokerPhase::Complete {
            return Err(BrokerError::NotReady);
        }
        parse_http_response(&self.response_bytes[..self.response_length], true)
            .map_err(BrokerError::Response)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerPoll {
    Idle,
    FrameTransmitted(usize),
    Event(BrokerEvent),
}

/// Kernel-only adapter between one admitted broker session and Arach's
/// retained e1000 rings. Each call performs at most one transmit or one
/// receive, so the caller can place an explicit scheduler yield between
/// packets. The adapter is not exported through the Crest syscall surface.
pub struct E1000ArgusBroker {
    session: ArgusBrokerSession,
    local_mac: [u8; 6],
    remote_mac: [u8; 6],
    identification: u16,
    receive_buffer: [u8; crate::drivers::e1000::FRAME_BYTES],
}

impl E1000ArgusBroker {
    pub fn new(
        session: ArgusBrokerSession,
        local_mac: [u8; 6],
        remote_mac: [u8; 6],
        identification: u16,
    ) -> Result<Self, BrokerError> {
        if local_mac == [0; 6]
            || remote_mac == [0; 6]
            || local_mac[0] & 1 != 0
            || remote_mac[0] & 1 != 0
        {
            return Err(BrokerError::Wire(TcpWireError::WrongDestination));
        }
        Ok(Self {
            session,
            local_mac,
            remote_mac,
            identification,
            receive_buffer: [0; crate::drivers::e1000::FRAME_BYTES],
        })
    }

    pub const fn session(&self) -> &ArgusBrokerSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut ArgusBrokerSession {
        &mut self.session
    }

    pub fn pump_once(&mut self, current_epoch: u64) -> Result<BrokerPoll, BrokerError> {
        let mut transmit_buffer = [0_u8; crate::drivers::e1000::FRAME_BYTES];
        if let Some(length) = self
            .session
            .transmit(
                current_epoch,
                &mut transmit_buffer,
                self.remote_mac,
                self.local_mac,
                self.identification,
            )
            .map_err(|error| error)?
        {
            crate::drivers::e1000::send(&transmit_buffer[..length])
                .map_err(|_| BrokerError::Nic)?;
            self.identification = self.identification.wrapping_add(1);
            return Ok(BrokerPoll::FrameTransmitted(length));
        }
        match crate::drivers::e1000::receive(&mut self.receive_buffer) {
            Ok(Some(length)) => {
                let event = self.session.receive(
                    current_epoch,
                    &self.receive_buffer[..length],
                    self.local_mac,
                )?;
                Ok(BrokerPoll::Event(event))
            }
            Ok(None) => Ok(BrokerPoll::Idle),
            Err(_) => Err(BrokerError::Nic),
        }
    }
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn parse_status(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 3 || !bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(
        u16::from(bytes[0] - b'0') * 100
            + u16::from(bytes[1] - b'0') * 10
            + u16::from(bytes[2] - b'0'),
    )
}

fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || !bytes.iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut value = 0_usize;
    for byte in bytes {
        value = value
            .checked_mul(10)?
            .checked_add(usize::from(byte - b'0'))?;
    }
    Some(value)
}

fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while let Some(first) = bytes.first() {
        if *first == b' ' || *first == b'\t' {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }
    while let Some(last) = bytes.last() {
        if *last == b' ' || *last == b'\t' {
            bytes = &bytes[..bytes.len() - 1];
        } else {
            break;
        }
    }
    bytes
}

fn is_header_name(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.to_ascii_lowercase() == right.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: Endpoint = Endpoint {
        address: [10, 0, 2, 15],
        port: 49_152,
    };
    const REMOTE: Endpoint = Endpoint {
        address: [93, 184, 216, 34],
        port: 443,
    };

    fn connected() -> TcpConnection {
        let (mut connection, syn) =
            TcpConnection::begin(LOCAL, REMOTE, 100, TcpBudget::HTTPS_DEFAULT).expect("connection");
        assert_eq!(syn.flags, TcpFlags::SYN);
        assert_eq!(
            connection.observe(TcpSegment {
                source: REMOTE,
                destination: LOCAL,
                sequence: 500,
                acknowledgment: 101,
                flags: TcpFlags::SYN.union(TcpFlags::ACK),
                payload: &[],
            }),
            Ok(TcpObservation::SendAck {
                sequence: 101,
                acknowledgment: 501,
            })
        );
        connection
    }

    #[test]
    fn handshake_binds_exact_endpoints_and_sequence_space() {
        let mut connection = connected();
        assert_eq!(connection.state(), TcpState::Established);
        assert_eq!(connection.next_acknowledgment(), 501);
        assert_eq!(
            connection.observe(TcpSegment {
                source: LOCAL,
                destination: REMOTE,
                sequence: 0,
                acknowledgment: 0,
                flags: TcpFlags::ACK,
                payload: &[],
            }),
            Err(TcpError::WrongEndpoint)
        );
    }

    #[test]
    fn bounded_reassembly_orders_fragments_and_exposes_a_yield_point() {
        let mut connection = connected();
        for (sequence, payload) in [(504, b"def".as_slice()), (501, b"abc".as_slice())] {
            assert_eq!(
                connection.observe(TcpSegment {
                    source: REMOTE,
                    destination: LOCAL,
                    sequence,
                    acknowledgment: 101,
                    flags: TcpFlags::ACK,
                    payload,
                }),
                Ok(TcpObservation::Buffered)
            );
        }
        let mut first = [0_u8; 8];
        let receipt = connection.drain_contiguous(&mut first);
        assert_eq!(receipt.bytes, 3);
        assert!(receipt.must_yield);
        assert_eq!(&first[..3], b"abc");
        assert_eq!(receipt.next_acknowledgment, 504);

        let receipt = connection.drain_contiguous(&mut first);
        assert_eq!(receipt.bytes, 3);
        assert_eq!(&first[..3], b"def");
        assert_eq!(receipt.next_acknowledgment, 507);
    }

    #[test]
    fn malformed_or_overlapping_segments_fail_closed() {
        let mut connection = connected();
        assert_eq!(
            connection.observe(TcpSegment {
                source: REMOTE,
                destination: LOCAL,
                sequence: 501,
                acknowledgment: 99,
                flags: TcpFlags::ACK,
                payload: b"abc",
            }),
            Err(TcpError::InvalidAcknowledgment)
        );
        let accepted = TcpSegment {
            source: REMOTE,
            destination: LOCAL,
            sequence: 501,
            acknowledgment: 101,
            flags: TcpFlags::ACK,
            payload: b"abc",
        };
        assert_eq!(connection.observe(accepted), Ok(TcpObservation::Buffered));
        assert_eq!(
            connection.observe(accepted),
            Err(TcpError::OverlappingSegment)
        );
    }

    #[test]
    fn tcp_wire_round_trip_preserves_endpoints_flags_and_payload() {
        let segment = TcpSegment {
            source: REMOTE,
            destination: LOCAL,
            sequence: 501,
            acknowledgment: 101,
            flags: TcpFlags::ACK.union(TcpFlags::PSH),
            payload: b"hello",
        };
        let local_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let remote_mac = [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef];
        let mut frame = [0_u8; 1_500];
        let length = encode_tcp_frame(&mut frame, local_mac, remote_mac, segment, 17)
            .expect("encoded TCP frame");
        let parsed = parse_tcp_frame(
            &frame[..length],
            local_mac,
            LOCAL.address,
            REMOTE.address,
            LOCAL.port,
            REMOTE.port,
        )
        .expect("parsed TCP frame");
        assert_eq!(parsed, segment);
    }

    #[test]
    fn tcp_wire_parser_rejects_corruption_and_wrong_routing() {
        let segment = TcpSegment {
            source: REMOTE,
            destination: LOCAL,
            sequence: 501,
            acknowledgment: 101,
            flags: TcpFlags::ACK,
            payload: b"hello",
        };
        let local_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let remote_mac = [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef];
        let mut frame = [0_u8; 1_500];
        let length = encode_tcp_frame(&mut frame, local_mac, remote_mac, segment, 18)
            .expect("encoded TCP frame");
        frame[length - 1] ^= 0x80;
        assert_eq!(
            parse_tcp_frame(
                &frame[..length],
                local_mac,
                LOCAL.address,
                REMOTE.address,
                LOCAL.port,
                REMOTE.port,
            ),
            Err(TcpWireError::InvalidChecksum)
        );
        assert_eq!(
            parse_tcp_frame(
                &frame[..length],
                remote_mac,
                LOCAL.address,
                REMOTE.address,
                LOCAL.port,
                REMOTE.port,
            ),
            Err(TcpWireError::WrongDestination)
        );
    }

    #[test]
    fn broker_session_drives_handshake_request_and_bounded_response() {
        let request = slope::hypermedia::HttpsRequest::parse_location(
            b"https://example.com/",
            slope::hypermedia::HttpBudget::DEFAULT,
        )
        .expect("request");
        // SAFETY: this test models the authenticated Push reply with a
        // nonzero capability and an exact origin/budget binding.
        let lease = unsafe {
            slope::hypermedia::HttpLease::from_broker(7, 3, request.origin(), request.budget(), 20)
                .expect("lease")
        };
        let local_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let remote_mac = [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef];
        let wire = lease.to_ipc_request(request, 1, 42).expect("IPC request");
        let mut session = ArgusBrokerSession::begin_ipc(lease, &wire, 1, LOCAL, REMOTE, 100)
            .expect("broker session");
        let mut frame = [0_u8; 1_500];
        let syn_length = session
            .transmit(2, &mut frame, remote_mac, local_mac, 1)
            .expect("SYN result")
            .expect("SYN frame");
        assert_eq!(frame[47] & 0x02, 0x02);
        assert_eq!(session.phase(), BrokerPhase::SynSent);

        let syn_ack = TcpSegment {
            source: REMOTE,
            destination: LOCAL,
            sequence: 900,
            acknowledgment: 101,
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
            payload: &[],
        };
        let mut reply = [0_u8; 1_500];
        let reply_length =
            encode_tcp_frame(&mut reply, local_mac, remote_mac, syn_ack, 2).expect("SYN-ACK frame");
        assert_eq!(
            session
                .receive(2, &reply[..reply_length], local_mac)
                .expect("handshake event"),
            BrokerEvent::HandshakeAccepted
        );
        assert_eq!(session.phase(), BrokerPhase::RequestPending);
        let request_length = session
            .transmit(2, &mut frame, remote_mac, local_mac, 3)
            .expect("request result")
            .expect("request frame");
        assert!(request_length > 54);
        assert_eq!(session.phase(), BrokerPhase::AwaitingResponse);

        let body = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let response = TcpSegment {
            source: REMOTE,
            destination: LOCAL,
            sequence: 901,
            acknowledgment: 101 + request_length as u32 - 54 + 1,
            flags: TcpFlags::ACK.union(TcpFlags::PSH).union(TcpFlags::FIN),
            payload: body,
        };
        let response_length = encode_tcp_frame(&mut reply, local_mac, remote_mac, response, 4)
            .expect("response frame");
        assert_eq!(
            session
                .receive(2, &reply[..response_length], local_mac)
                .expect("response event"),
            BrokerEvent::Complete
        );
        let parsed = session.response().expect("complete response");
        assert_eq!(parsed.status(), 200);
        assert_eq!(parsed.body(), b"hello");
        assert!(syn_length > 0);
    }

    #[test]
    fn broker_endpoint_admission_binds_one_mapping_generation() {
        let request = slope::hypermedia::HttpsRequest::parse_location(
            b"https://example.com/",
            slope::hypermedia::HttpBudget::DEFAULT,
        )
        .expect("request");
        // SAFETY: synthetic values model authenticated Push/Hermes replies.
        let lease = unsafe {
            slope::hypermedia::HttpLease::from_broker(31, 7, request.origin(), request.budget(), 20)
                .expect("HTTP lease")
        };
        let endpoint_lease = unsafe {
            slope::hypermedia::ArgusEndpointLease::from_broker(41, 42, 8, 9, 20)
                .expect("endpoint lease")
        };
        let mut endpoint = slope::hypermedia::ArgusEndpointSession::new(endpoint_lease);
        let wire = lease.to_ipc_request(request, 1, 1).expect("IPC request");
        let session = ArgusBrokerSession::begin_endpoint_ipc(
            lease,
            &mut endpoint,
            &wire,
            1,
            LOCAL,
            REMOTE,
            100,
        )
        .expect("endpoint admission");
        assert_eq!(session.phase(), BrokerPhase::SynSent);
        assert_eq!(
            endpoint.prepare(wire, 1),
            Err(slope::hypermedia::EndpointError::Busy)
        );
        assert_eq!(
            session.complete_endpoint(&mut endpoint),
            Err(BrokerError::WrongPhase)
        );
    }

    #[test]
    fn http_response_parser_accepts_bounded_identity_body() {
        let response = parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
            false,
        )
        .expect("bounded response");
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), b"hello");
    }

    #[test]
    fn http_response_parser_requires_complete_body_or_connection_end() {
        assert_eq!(
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", false),
            Err(HttpError::BodyIncomplete)
        );
        assert_eq!(
            parse_http_response(b"HTTP/1.1 200 OK\r\n\r\nhello", false),
            Err(HttpError::Incomplete)
        );
        let response = parse_http_response(b"HTTP/1.1 204 No Content\r\n\r\n", true)
            .expect("complete connection-delimited response");
        assert_eq!(response.status(), 204);
        assert!(response.body().is_empty());
    }

    #[test]
    fn http_response_parser_rejects_ambiguous_or_unbounded_framing() {
        assert_eq!(
            parse_http_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                true,
            ),
            Err(HttpError::UnsupportedTransferEncoding)
        );
        assert_eq!(
            parse_http_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc",
                true,
            ),
            Err(HttpError::InvalidContentLength)
        );
        assert_eq!(
            parse_http_response(b"HTTP/1.0 200 OK\r\n\r\n", true),
            Err(HttpError::InvalidStatusLine)
        );
    }

    #[test]
    fn https_get_encoder_binds_the_canonical_origin_and_budget() {
        let request = slope::hypermedia::HttpsRequest::parse_location(
            b"https://Example.COM/docs/start",
            slope::hypermedia::HttpBudget::DEFAULT,
        )
        .expect("request");
        let mut output = [0_u8; 256];
        let length = encode_https_get(&request, &mut output).expect("GET");
        assert_eq!(
            &output[..length],
            b"GET /docs/start HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
        );
        let mut tiny = [0_u8; 8];
        assert_eq!(
            encode_https_get(&request, &mut tiny),
            Err(HttpRequestError::BufferTooSmall)
        );
    }

    #[test]
    fn tls_record_parser_validates_framing_without_claiming_decryption() {
        let record = parse_tls_record(&[22, 0x03, 0x03, 0, 3, 1, 2, 3]).expect("record");
        assert_eq!(record.content_type(), 22);
        assert_eq!(record.version(), 0x0303);
        assert_eq!(record.payload(), &[1, 2, 3]);
        assert_eq!(
            parse_tls_record(&[23, 0x03, 0x04, 0, 0]),
            Err(TlsError::UnsupportedVersion)
        );
        assert_eq!(
            parse_tls_record(&[24, 0x03, 0x03, 0, 0]),
            Err(TlsError::UnsupportedContentType)
        );
        assert_eq!(
            parse_tls_record(&[22, 0x03, 0x03, 0, 4, 1, 2]),
            Err(TlsError::Incomplete)
        );
    }

    #[test]
    fn pinned_certificate_check_hashes_der_and_binds_origin_generation() {
        let origin = slope::hypermedia::HttpsOrigin::new(b"example.com").expect("origin");
        let certificate_der = b"bounded-certificate-der";
        let fingerprint = ::blacklab::oureboros::sha256(certificate_der);
        // SAFETY: synthetic values model the authenticated broker anchor.
        let anchor =
            unsafe { TlsTrustAnchor::from_broker(origin, fingerprint, 11).expect("anchor") };
        let peer = verify_pinned_certificate(anchor, origin, certificate_der, 11)
            .expect("pinned certificate");
        assert_eq!(peer.origin(), origin);
        assert_eq!(peer.certificate_sha256(), fingerprint);
        assert_eq!(peer.generation(), 11);
        assert_eq!(
            verify_pinned_certificate(anchor, origin, b"different", 11),
            Err(TlsError::CertificateTrust(
                TlsTrustError::CertificateMismatch
            ))
        );
        assert_eq!(
            verify_pinned_certificate(anchor, origin, &[], 11),
            Err(TlsError::CertificateEmpty)
        );
    }

    fn handshake_message(message_type: u8) -> [u8; 4] {
        [message_type, 0, 0, 0]
    }

    #[test]
    fn tls_handshake_transcript_requires_order_and_pinned_peer_before_finished() {
        let origin = slope::hypermedia::HttpsOrigin::new(b"example.com").expect("origin");
        let certificate_der = b"certificate";
        let fingerprint = ::blacklab::oureboros::sha256(certificate_der);
        // SAFETY: synthetic values model the authenticated broker anchor.
        let anchor =
            unsafe { TlsTrustAnchor::from_broker(origin, fingerprint, 4).expect("anchor") };
        let peer = anchor
            .permits(origin, fingerprint, 4)
            .expect("peer identity");
        let mut transcript = TlsHandshakeTranscript::new();
        assert_eq!(
            transcript.ingest_record(
                parse_tls_record(&[22, 3, 3, 0, 4, 20, 0, 0, 0]).expect("finished record")
            ),
            Err(TlsHandshakeError::UnexpectedMessage)
        );
        assert!(!transcript.is_complete());
        assert_eq!(transcript.transcript_bytes(), 0);

        for message_type in [1_u8, 2, 11] {
            let message = handshake_message(message_type);
            let mut record = [0_u8; 9];
            record[..5].copy_from_slice(&[22, 3, 3, 0, 4]);
            record[5..].copy_from_slice(&message);
            transcript
                .ingest_record(parse_tls_record(&record).expect("handshake record"))
                .expect("ordered handshake");
        }
        assert_eq!(
            transcript.accept_peer(peer),
            Ok(()),
            "the broker pin must be accepted after Certificate"
        );
        let finished = [22, 3, 3, 0, 4, 20, 0, 0, 0];
        let event = transcript
            .ingest_record(parse_tls_record(&finished).expect("finished record"))
            .expect("finished");
        assert!(event.complete);
        assert!(transcript.transcript_digest().is_some());
        assert_eq!(transcript.peer(), Some(peer));
    }

    #[test]
    fn tls_handshake_transcript_rejects_encrypted_records_and_unbounded_input() {
        let mut transcript = TlsHandshakeTranscript::new();
        assert_eq!(
            transcript.ingest_record(
                parse_tls_record(&[23, 3, 3, 0, 0]).expect("application record framing")
            ),
            Err(TlsHandshakeError::WrongContentType)
        );
        let mut payload = [0_u8; 5];
        payload[..4].copy_from_slice(&[1, 0, 0, 2]);
        payload[4] = 0;
        assert_eq!(
            transcript.ingest_record(TlsRecord {
                content_type: 22,
                version: 0x0303,
                payload: &payload,
            }),
            Err(TlsHandshakeError::IncompleteMessage)
        );
    }

    #[test]
    fn tls13_record_protector_round_trips_with_tls_inner_type() {
        let secret = [0x42_u8; 32];
        let traffic = Tls13TrafficKey::from_traffic_secret(&secret).expect("traffic key");
        assert_ne!(traffic.key(), [0; 32]);
        assert_ne!(traffic.iv(), [0; 12]);
        let mut sender = Tls13RecordProtector::new(traffic);
        let mut receiver = Tls13RecordProtector::new(traffic);
        let mut wire = [0_u8; 5 + MAX_TLS_RECORD_BYTES];
        let length = sender
            .seal(23, b"bounded Argus response", &mut wire)
            .expect("sealed record");
        assert_eq!(&wire[..3], &[23, 0x03, 0x03]);
        assert_eq!(sender.sequence(), 1);

        let mut plaintext = [0_u8; MAX_TLS13_PLAINTEXT_BYTES + 1];
        let record = receiver
            .open(&wire[..length], &mut plaintext)
            .expect("opened record");
        assert_eq!(record.content_type(), 23);
        assert_eq!(record.payload(), b"bounded Argus response");
        assert_eq!(receiver.sequence(), 1);
    }

    #[test]
    fn tls13_record_protector_poisoned_after_authentication_failure() {
        let traffic = Tls13TrafficKey::from_traffic_secret(&[7_u8; 32]).expect("traffic key");
        let mut sender = Tls13RecordProtector::new(traffic);
        let mut receiver = Tls13RecordProtector::new(traffic);
        let mut wire = [0_u8; 128];
        let length = sender
            .seal(22, b"handshake", &mut wire)
            .expect("sealed record");
        wire[length - 1] ^= 1;
        let mut plaintext = [0_u8; 64];
        assert_eq!(
            receiver.open(&wire[..length], &mut plaintext),
            Err(TlsRecordCryptoError::AuthenticationFailed)
        );
        assert!(receiver.is_poisoned());
        assert_eq!(
            receiver.open(&wire[..length], &mut plaintext),
            Err(TlsRecordCryptoError::Poisoned)
        );
    }

    #[test]
    fn chacha20_block_matches_rfc8439_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(chacha20_block(&key, 1, &nonce), expected);
    }

    #[test]
    fn poly1305_matches_rfc8439_vector() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let mut mac = Poly1305::new(&key);
        mac.update(b"Cryptographic Forum Research Group");
        assert_eq!(
            mac.finish(),
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9,
            ]
        );
    }
}
