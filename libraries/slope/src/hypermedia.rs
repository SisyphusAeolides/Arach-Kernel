//! Bounded HTTPS lease types shared by Argus, Push, and Boulder's future
//! transport broker.
//!
//! These values are intentionally data-only. They do not expose a socket,
//! packet buffer, NIC register, or cryptographic key to a client. A broker
//! mints an [`HttpLease`] only after it has accepted the exact HTTPS origin and
//! bounded work budget; the client can then submit only matching requests over
//! a capability-validated IPC endpoint.

pub const MAX_HTTP_HOST_BYTES: usize = 48;
pub const MAX_HTTP_PATH_BYTES: usize = 128;
pub const MAX_HTTP_REQUEST_BYTES: u16 = 2_048;
pub const MAX_HTTP_RESPONSE_BYTES: u16 = 32 * 1024;
pub const MAX_TCP_SEGMENTS: u8 = 32;
pub const TLS_SHA256_BYTES: usize = 32;
pub const HTTP_IPC_VERSION: u16 = 1;
pub const ARGUS_ENDPOINT_VERSION: u16 = 1;
pub const ARGUS_ENDPOINT_OWNER: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HypermediaError {
    NotHttps,
    InvalidHost,
    InvalidPath,
    InvalidBudget,
    InvalidLease,
    LeaseExpired,
    LeaseMismatch,
}

/// A broker-published certificate pin for one exact HTTPS origin.  This is
/// deliberately an authority record rather than a certificate parser: the
/// network broker owns DER parsing, chain validation, and cryptographic work;
/// Argus receives only the resulting SHA-256 identity and cannot substitute a
/// different host, generation, or trust decision.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsTrustAnchor {
    origin: HttpsOrigin,
    certificate_sha256: [u8; TLS_SHA256_BYTES],
    generation: u32,
}

impl TlsTrustAnchor {
    /// Imports a trust decision made by the authenticated Boulder/Hermes
    /// broker. A zero fingerprint or generation is never a valid authority.
    pub unsafe fn from_broker(
        origin: HttpsOrigin,
        certificate_sha256: [u8; TLS_SHA256_BYTES],
        generation: u32,
    ) -> Result<Self, HypermediaError> {
        if generation == 0 || certificate_sha256 == [0; TLS_SHA256_BYTES] {
            return Err(HypermediaError::InvalidLease);
        }
        Ok(Self {
            origin,
            certificate_sha256,
            generation,
        })
    }

    pub const fn origin(self) -> HttpsOrigin {
        self.origin
    }

    pub const fn certificate_sha256(self) -> [u8; TLS_SHA256_BYTES] {
        self.certificate_sha256
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// Accepts only the exact certificate identity and origin selected by the
    /// broker. No caller-provided fingerprint can widen this authority.
    pub fn permits(
        self,
        origin: HttpsOrigin,
        certificate_sha256: [u8; TLS_SHA256_BYTES],
        generation: u32,
    ) -> Result<TlsPeerIdentity, TlsTrustError> {
        if generation != self.generation {
            return Err(TlsTrustError::GenerationMismatch);
        }
        if origin != self.origin {
            return Err(TlsTrustError::OriginMismatch);
        }
        if certificate_sha256 != self.certificate_sha256 {
            return Err(TlsTrustError::CertificateMismatch);
        }
        Ok(TlsPeerIdentity {
            origin,
            certificate_sha256,
            generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsPeerIdentity {
    origin: HttpsOrigin,
    certificate_sha256: [u8; TLS_SHA256_BYTES],
    generation: u32,
}

impl TlsPeerIdentity {
    pub const fn origin(self) -> HttpsOrigin {
        self.origin
    }

    pub const fn certificate_sha256(self) -> [u8; TLS_SHA256_BYTES] {
        self.certificate_sha256
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsTrustError {
    GenerationMismatch,
    OriginMismatch,
    CertificateMismatch,
}

/// Work admitted for one brokered HTTPS transaction. The transport must yield
/// after at most `yield_every_segments` reassembly steps, allowing the service
/// calculus to retain preemption points even during a TLS exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpBudget {
    pub request_bytes: u16,
    pub response_bytes: u16,
    pub max_segments: u8,
    pub yield_every_segments: u8,
}

impl HttpBudget {
    pub const DEFAULT: Self = Self {
        request_bytes: 1_024,
        response_bytes: 16 * 1024,
        max_segments: 16,
        yield_every_segments: 1,
    };

    pub const fn is_valid(self) -> bool {
        self.request_bytes != 0
            && self.request_bytes <= MAX_HTTP_REQUEST_BYTES
            && self.response_bytes != 0
            && self.response_bytes <= MAX_HTTP_RESPONSE_BYTES
            && self.max_segments != 0
            && self.max_segments <= MAX_TCP_SEGMENTS
            && self.yield_every_segments != 0
            && self.yield_every_segments <= self.max_segments
    }
}

/// A canonical HTTPS origin. Host bytes are lower-level ASCII data so the
/// parser never allocates, normalizes Unicode, or consults ambient DNS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpsOrigin {
    host: [u8; MAX_HTTP_HOST_BYTES],
    host_length: u8,
}

impl HttpsOrigin {
    pub fn new(host: &[u8]) -> Result<Self, HypermediaError> {
        if host.is_empty() || host.len() > MAX_HTTP_HOST_BYTES {
            return Err(HypermediaError::InvalidHost);
        }
        let mut previous_dot = true;
        for byte in host {
            let valid = byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'.';
            if !valid || (*byte == b'.' && previous_dot) {
                return Err(HypermediaError::InvalidHost);
            }
            previous_dot = *byte == b'.';
        }
        if previous_dot || host[0] == b'-' || host[host.len() - 1] == b'-' {
            return Err(HypermediaError::InvalidHost);
        }
        let mut output = Self {
            host: [0; MAX_HTTP_HOST_BYTES],
            host_length: host.len() as u8,
        };
        for (index, byte) in host.iter().copied().enumerate() {
            output.host[index] = byte.to_ascii_lowercase();
        }
        Ok(output)
    }

    pub fn host(&self) -> &[u8] {
        &self.host[..usize::from(self.host_length)]
    }
}

/// One HTTPS request that can be sent only by a matching unexpired lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpsRequest {
    origin: HttpsOrigin,
    path: [u8; MAX_HTTP_PATH_BYTES],
    path_length: u8,
    budget: HttpBudget,
}

impl HttpsRequest {
    pub fn new(
        origin: HttpsOrigin,
        path: &[u8],
        budget: HttpBudget,
    ) -> Result<Self, HypermediaError> {
        if path.is_empty()
            || path.len() > MAX_HTTP_PATH_BYTES
            || path[0] != b'/'
            || !budget.is_valid()
        {
            return Err(if budget.is_valid() {
                HypermediaError::InvalidPath
            } else {
                HypermediaError::InvalidBudget
            });
        }
        if path
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || *byte == b'#')
        {
            return Err(HypermediaError::InvalidPath);
        }
        let mut output = Self {
            origin,
            path: [0; MAX_HTTP_PATH_BYTES],
            path_length: path.len() as u8,
            budget,
        };
        output.path[..path.len()].copy_from_slice(path);
        Ok(output)
    }

    /// Parses only canonical `https://host/path` locations. Plain HTTP, user
    /// info, ports, fragments, and implicit schemes fail closed.
    pub fn parse_location(location: &[u8], budget: HttpBudget) -> Result<Self, HypermediaError> {
        let remainder = location
            .strip_prefix(b"https://")
            .ok_or(HypermediaError::NotHttps)?;
        let split = remainder
            .iter()
            .position(|byte| *byte == b'/')
            .unwrap_or(remainder.len());
        let origin = HttpsOrigin::new(&remainder[..split])?;
        let path = if split == remainder.len() {
            b"/".as_slice()
        } else {
            &remainder[split..]
        };
        Self::new(origin, path, budget)
    }

    pub const fn origin(&self) -> HttpsOrigin {
        self.origin
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..usize::from(self.path_length)]
    }

    pub const fn budget(&self) -> HttpBudget {
        self.budget
    }
}

/// Opaque HTTPS authority imported from Push/Boulder. The raw capability is
/// private, so Argus cannot reinterpret it as a generic network capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpLease {
    capability: u64,
    generation: u32,
    origin: HttpsOrigin,
    budget: HttpBudget,
    expiry_epoch: u64,
}

impl HttpLease {
    /// Imports an exact broker-issued authority.
    ///
    /// # Safety
    ///
    /// Every field must come from Push's authenticated reply after Boulder has
    /// retained the corresponding transport/TLS state.
    pub const unsafe fn from_broker(
        capability: u64,
        generation: u32,
        origin: HttpsOrigin,
        budget: HttpBudget,
        expiry_epoch: u64,
    ) -> Result<Self, HypermediaError> {
        if capability == 0 || generation == 0 || expiry_epoch == 0 || !budget.is_valid() {
            return Err(HypermediaError::InvalidLease);
        }
        Ok(Self {
            capability,
            generation,
            origin,
            budget,
            expiry_epoch,
        })
    }

    pub fn permits(
        &self,
        request: HttpsRequest,
        current_epoch: u64,
    ) -> Result<(), HypermediaError> {
        if self.capability == 0 || self.generation == 0 {
            return Err(HypermediaError::InvalidLease);
        }
        if current_epoch >= self.expiry_epoch {
            return Err(HypermediaError::LeaseExpired);
        }
        if request.origin != self.origin
            || request.budget.request_bytes > self.budget.request_bytes
            || request.budget.response_bytes > self.budget.response_bytes
            || request.budget.max_segments > self.budget.max_segments
            || request.budget.yield_every_segments > self.budget.yield_every_segments
        {
            return Err(HypermediaError::LeaseMismatch);
        }
        Ok(())
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn expiry_epoch(&self) -> u64 {
        self.expiry_epoch
    }

    /// Creates the fixed-layout request record that Hermes may copy across a
    /// capability-scoped Argus mapping. The record contains no socket or NIC
    /// authority; the broker must still validate it against this exact lease.
    pub fn to_ipc_request(
        &self,
        request: HttpsRequest,
        current_epoch: u64,
        sequence: u32,
    ) -> Result<HttpIpcRequest, HypermediaError> {
        self.permits(request, current_epoch)?;
        let mut wire = HttpIpcRequest::empty();
        wire.version = HTTP_IPC_VERSION;
        wire.capability = self.capability;
        wire.generation = self.generation;
        wire.sequence = sequence;
        wire.expiry_epoch = self.expiry_epoch;
        wire.host_length = request.origin.host_length;
        wire.path_length = request.path_length;
        wire.host[..usize::from(wire.host_length)].copy_from_slice(request.origin.host());
        wire.path[..usize::from(wire.path_length)].copy_from_slice(request.path());
        wire.request_bytes = request.budget.request_bytes;
        wire.response_bytes = request.budget.response_bytes;
        wire.max_segments = request.budget.max_segments;
        wire.yield_every_segments = request.budget.yield_every_segments;
        Ok(wire)
    }

    pub fn authorize_ipc(
        &self,
        wire: &HttpIpcRequest,
        current_epoch: u64,
    ) -> Result<HttpsRequest, HypermediaError> {
        if wire.version != HTTP_IPC_VERSION
            || wire.capability != self.capability
            || wire.generation != self.generation
            || wire.expiry_epoch != self.expiry_epoch
        {
            return Err(HypermediaError::LeaseMismatch);
        }
        let request = wire.request()?;
        self.permits(request, current_epoch)?;
        Ok(request)
    }
}

/// Fixed-layout Argus request envelope for a future authenticated shared
/// mapping. It is deliberately larger than `ChannelMessage::payload` so the
/// entire canonical host/path is carried without truncation or allocation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpIpcRequest {
    pub version: u16,
    pub request_bytes: u16,
    pub response_bytes: u16,
    pub max_segments: u8,
    pub yield_every_segments: u8,
    pub capability: u64,
    pub generation: u32,
    pub sequence: u32,
    pub expiry_epoch: u64,
    host_length: u8,
    path_length: u8,
    reserved: [u8; 2],
    host: [u8; MAX_HTTP_HOST_BYTES],
    path: [u8; MAX_HTTP_PATH_BYTES],
}

impl HttpIpcRequest {
    const fn empty() -> Self {
        Self {
            version: 0,
            request_bytes: 0,
            response_bytes: 0,
            max_segments: 0,
            yield_every_segments: 0,
            capability: 0,
            generation: 0,
            sequence: 0,
            expiry_epoch: 0,
            host_length: 0,
            path_length: 0,
            reserved: [0; 2],
            host: [0; MAX_HTTP_HOST_BYTES],
            path: [0; MAX_HTTP_PATH_BYTES],
        }
    }

    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    pub fn request(&self) -> Result<HttpsRequest, HypermediaError> {
        if self.version != HTTP_IPC_VERSION
            || self.reserved != [0; 2]
            || self.host_length == 0
            || usize::from(self.host_length) > MAX_HTTP_HOST_BYTES
            || self.path_length == 0
            || usize::from(self.path_length) > MAX_HTTP_PATH_BYTES
        {
            return Err(HypermediaError::InvalidLease);
        }
        let origin = HttpsOrigin::new(&self.host[..usize::from(self.host_length)])?;
        HttpsRequest::new(
            origin,
            &self.path[..usize::from(self.path_length)],
            HttpBudget {
                request_bytes: self.request_bytes,
                response_bytes: self.response_bytes,
                max_segments: self.max_segments,
                yield_every_segments: self.yield_every_segments,
            },
        )
    }
}

const _: () = assert!(core::mem::size_of::<HttpIpcRequest>() == 216);

/// Authority for one Argus-to-Hermes endpoint and its retained shared
/// mapping.  The two handles are opaque broker values; neither is a pointer
/// and neither can be used to open a raw socket.  Revocation is performed by
/// [`ArgusEndpointSession`] before the mapping is released by Boulder.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgusEndpointLease {
    pub version: u16,
    pub owner: u8,
    pub reserved: u8,
    pub endpoint_capability: u64,
    pub mapping_capability: u64,
    pub generation: u32,
    pub mapping_generation: u32,
    pub expiry_epoch: u64,
}

impl ArgusEndpointLease {
    /// Imports the exact endpoint and mapping authorities returned by Hermes.
    ///
    /// # Safety
    ///
    /// Every value must originate from the authenticated broker response and
    /// refer to the same retained mapping generation.
    pub const unsafe fn from_broker(
        endpoint_capability: u64,
        mapping_capability: u64,
        generation: u32,
        mapping_generation: u32,
        expiry_epoch: u64,
    ) -> Result<Self, EndpointError> {
        if endpoint_capability == 0
            || mapping_capability == 0
            || generation == 0
            || mapping_generation == 0
            || expiry_epoch == 0
        {
            return Err(EndpointError::InvalidLease);
        }
        Ok(Self {
            version: ARGUS_ENDPOINT_VERSION,
            owner: ARGUS_ENDPOINT_OWNER,
            reserved: 0,
            endpoint_capability,
            mapping_capability,
            generation,
            mapping_generation,
            expiry_epoch,
        })
    }

    pub const fn valid_for(self, current_epoch: u64) -> bool {
        self.version == ARGUS_ENDPOINT_VERSION
            && self.owner == ARGUS_ENDPOINT_OWNER
            && self.reserved == 0
            && self.endpoint_capability != 0
            && self.mapping_capability != 0
            && self.generation != 0
            && self.mapping_generation != 0
            && current_epoch < self.expiry_epoch
    }
}

/// Envelope copied through a capability-scoped Hermes mapping.  The nested
/// request remains independently checked against the HTTPS lease; the outer
/// fields prevent a request from being replayed through another endpoint or
/// mapping generation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgusIpcRequest {
    pub version: u16,
    pub reserved: u16,
    pub endpoint_capability: u64,
    pub mapping_capability: u64,
    pub generation: u32,
    pub mapping_generation: u32,
    pub request: HttpIpcRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointError {
    InvalidLease,
    WrongOwner,
    Expired,
    Revoked,
    InvalidRequest,
    WrongEndpoint,
    WrongMapping,
    WrongGeneration,
    Sequence,
    Busy,
    NotInFlight,
}

impl ArgusEndpointLease {
    fn authorize_request(
        self,
        request: HttpIpcRequest,
        current_epoch: u64,
    ) -> Result<ArgusIpcRequest, EndpointError> {
        if self.version != ARGUS_ENDPOINT_VERSION || self.reserved != 0 {
            return Err(EndpointError::InvalidLease);
        }
        if self.owner != ARGUS_ENDPOINT_OWNER {
            return Err(EndpointError::WrongOwner);
        }
        if current_epoch >= self.expiry_epoch {
            return Err(EndpointError::Expired);
        }
        if request.version != HTTP_IPC_VERSION || request.sequence == 0 {
            return Err(EndpointError::InvalidRequest);
        }
        Ok(ArgusIpcRequest {
            version: ARGUS_ENDPOINT_VERSION,
            reserved: 0,
            endpoint_capability: self.endpoint_capability,
            mapping_capability: self.mapping_capability,
            generation: self.generation,
            mapping_generation: self.mapping_generation,
            request,
        })
    }
}

/// Stateful endpoint gate used by the broker.  It permits one request at a
/// time, requires the exact monotonically increasing sequence, and makes
/// revocation terminal.  The actual shared-memory mapping is owned by the
/// kernel; this value is the service-side admission state for that mapping.
pub struct ArgusEndpointSession {
    lease: ArgusEndpointLease,
    next_sequence: u32,
    in_flight: bool,
    revoked: bool,
}

impl ArgusEndpointSession {
    pub const fn new(lease: ArgusEndpointLease) -> Self {
        Self {
            lease,
            next_sequence: 1,
            in_flight: false,
            revoked: false,
        }
    }

    pub const fn lease(&self) -> ArgusEndpointLease {
        self.lease
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn prepare(
        &self,
        request: HttpIpcRequest,
        current_epoch: u64,
    ) -> Result<ArgusIpcRequest, EndpointError> {
        if self.revoked {
            return Err(EndpointError::Revoked);
        }
        if self.in_flight {
            return Err(EndpointError::Busy);
        }
        if request.sequence != self.next_sequence {
            return Err(EndpointError::Sequence);
        }
        self.lease.authorize_request(request, current_epoch)
    }

    pub fn commit(&mut self, envelope: ArgusIpcRequest) -> Result<(), EndpointError> {
        if self.revoked {
            return Err(EndpointError::Revoked);
        }
        self.validate_envelope(envelope)?;
        if self.in_flight {
            return Err(EndpointError::Busy);
        }
        self.in_flight = true;
        Ok(())
    }

    pub fn complete(&mut self, sequence: u32) -> Result<(), EndpointError> {
        if !self.in_flight {
            return Err(EndpointError::NotInFlight);
        }
        if sequence != self.next_sequence {
            return Err(EndpointError::Sequence);
        }
        self.in_flight = false;
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.in_flight = false;
    }

    fn validate_envelope(&self, envelope: ArgusIpcRequest) -> Result<(), EndpointError> {
        if envelope.version != ARGUS_ENDPOINT_VERSION || envelope.reserved != 0 {
            return Err(EndpointError::InvalidRequest);
        }
        if envelope.endpoint_capability != self.lease.endpoint_capability {
            return Err(EndpointError::WrongEndpoint);
        }
        if envelope.mapping_capability != self.lease.mapping_capability {
            return Err(EndpointError::WrongMapping);
        }
        if envelope.generation != self.lease.generation {
            return Err(EndpointError::WrongGeneration);
        }
        if envelope.mapping_generation != self.lease.mapping_generation {
            return Err(EndpointError::WrongGeneration);
        }
        if envelope.request.sequence != self.next_sequence {
            return Err(EndpointError::Sequence);
        }
        Ok(())
    }
}

const _: () = assert!(core::mem::size_of::<ArgusEndpointLease>() == 40);
const _: () = assert!(core::mem::size_of::<ArgusIpcRequest>() == 248);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_canonical_https_locations_become_requests() {
        let request =
            HttpsRequest::parse_location(b"https://Example.COM/docs/start", HttpBudget::DEFAULT)
                .expect("HTTPS request");
        assert_eq!(request.origin().host(), b"example.com");
        assert_eq!(request.path(), b"/docs/start");
        assert_eq!(
            HttpsRequest::parse_location(b"http://example.com/", HttpBudget::DEFAULT),
            Err(HypermediaError::NotHttps)
        );
        assert!(
            HttpsRequest::parse_location(b"https://example.com:443/", HttpBudget::DEFAULT).is_err()
        );
    }

    #[test]
    fn tls_anchor_accepts_only_the_broker_pinned_peer_generation() {
        let origin = HttpsOrigin::new(b"example.com").expect("origin");
        let fingerprint = [0x5a; TLS_SHA256_BYTES];
        // SAFETY: synthetic values model the authenticated broker reply.
        let anchor =
            unsafe { TlsTrustAnchor::from_broker(origin, fingerprint, 7).expect("trust anchor") };
        let peer = anchor.permits(origin, fingerprint, 7).expect("pinned peer");
        assert_eq!(peer.origin(), origin);
        assert_eq!(peer.certificate_sha256(), fingerprint);
        assert_eq!(peer.generation(), 7);
        assert_eq!(
            anchor.permits(origin, [0x59; TLS_SHA256_BYTES], 7),
            Err(TlsTrustError::CertificateMismatch)
        );
        assert_eq!(
            anchor.permits(origin, fingerprint, 8),
            Err(TlsTrustError::GenerationMismatch)
        );
    }

    #[test]
    fn tls_anchor_rejects_zero_fingerprint_and_cross_origin_use() {
        let origin = HttpsOrigin::new(b"example.com").expect("origin");
        // SAFETY: zero fingerprints are intentionally tested as invalid input.
        assert_eq!(
            unsafe { TlsTrustAnchor::from_broker(origin, [0; TLS_SHA256_BYTES], 1) },
            Err(HypermediaError::InvalidLease)
        );
        let other = HttpsOrigin::new(b"other.example").expect("other origin");
        // SAFETY: synthetic values model an authenticated broker reply.
        let anchor = unsafe {
            TlsTrustAnchor::from_broker(origin, [1; TLS_SHA256_BYTES], 1).expect("anchor")
        };
        assert_eq!(
            anchor.permits(other, [1; TLS_SHA256_BYTES], 1),
            Err(TlsTrustError::OriginMismatch)
        );
    }

    #[test]
    fn lease_cannot_amplify_origin_budget_or_lifetime() {
        let origin = HttpsOrigin::new(b"example.com").expect("origin");
        let request = HttpsRequest::new(origin, b"/", HttpBudget::DEFAULT).expect("request");
        // SAFETY: the test uses a synthetic nonzero broker token.
        let lease = unsafe {
            HttpLease::from_broker(7, 3, origin, HttpBudget::DEFAULT, 10).expect("lease")
        };
        assert_eq!(lease.permits(request, 9), Ok(()));
        assert_eq!(
            lease.permits(request, 10),
            Err(HypermediaError::LeaseExpired)
        );

        let other = HttpsRequest::parse_location(b"https://other.example/", HttpBudget::DEFAULT)
            .expect("other request");
        assert_eq!(lease.permits(other, 1), Err(HypermediaError::LeaseMismatch));
    }

    #[test]
    fn ipc_request_round_trip_is_bound_to_the_exact_lease() {
        let origin = HttpsOrigin::new(b"example.com").expect("origin");
        let request = HttpsRequest::new(origin, b"/docs", HttpBudget::DEFAULT).expect("request");
        // SAFETY: this test models a broker-issued opaque capability.
        let lease = unsafe {
            HttpLease::from_broker(9, 4, origin, HttpBudget::DEFAULT, 30).expect("lease")
        };
        let wire = lease.to_ipc_request(request, 10, 77).expect("wire request");
        assert_eq!(wire.sequence(), 77);
        assert_eq!(lease.authorize_ipc(&wire, 10), Ok(request));
        assert_eq!(
            lease.authorize_ipc(
                &HttpIpcRequest {
                    generation: 5,
                    ..wire
                },
                10,
            ),
            Err(HypermediaError::LeaseMismatch)
        );
        assert_eq!(wire.request(), Ok(request));
    }

    #[test]
    fn endpoint_session_binds_mapping_serializes_and_revokes() {
        let origin = HttpsOrigin::new(b"example.com").expect("origin");
        let request = HttpsRequest::new(origin, b"/docs", HttpBudget::DEFAULT).expect("request");
        // SAFETY: these values model authenticated Hermes authorities.
        let endpoint =
            unsafe { ArgusEndpointLease::from_broker(11, 12, 4, 9, 30) }.expect("endpoint lease");
        let http = unsafe {
            HttpLease::from_broker(13, 4, origin, HttpBudget::DEFAULT, 30).expect("HTTP lease")
        };
        let wire = http.to_ipc_request(request, 10, 1).expect("wire request");
        let mut session = ArgusEndpointSession::new(endpoint);
        let envelope = session.prepare(wire, 10).expect("prepared envelope");
        session.commit(envelope).expect("committed envelope");
        assert_eq!(session.prepare(wire, 10), Err(EndpointError::Busy));
        session.complete(1).expect("completed request");
        let second = http.to_ipc_request(request, 10, 2).expect("second request");
        let envelope = session.prepare(second, 10).expect("second envelope");
        session.commit(envelope).expect("second commit");
        session.revoke();
        assert!(session.is_revoked());
        assert_eq!(session.complete(2), Err(EndpointError::NotInFlight));
        assert_eq!(session.prepare(second, 10), Err(EndpointError::Revoked));

        let mut pending_session = ArgusEndpointSession::new(endpoint);
        let pending = pending_session.prepare(wire, 10).expect("pending envelope");
        pending_session.revoke();
        assert_eq!(pending_session.commit(pending), Err(EndpointError::Revoked));
    }

    #[test]
    fn endpoint_rejects_stale_mapping_and_replay_sequence() {
        let origin = HttpsOrigin::new(b"example.com").expect("origin");
        let request = HttpsRequest::new(origin, b"/", HttpBudget::DEFAULT).expect("request");
        // SAFETY: synthetic broker values for the contract test.
        let endpoint =
            unsafe { ArgusEndpointLease::from_broker(21, 22, 5, 6, 20) }.expect("endpoint lease");
        let http = unsafe {
            HttpLease::from_broker(23, 5, origin, HttpBudget::DEFAULT, 20).expect("HTTP lease")
        };
        let wire = http.to_ipc_request(request, 1, 1).expect("wire request");
        let mut session = ArgusEndpointSession::new(endpoint);
        let envelope = session.prepare(wire, 1).expect("envelope");
        assert_eq!(session.commit(envelope), Ok(()));
        session.complete(1).expect("complete");
        let wire = http
            .to_ipc_request(request, 1, 2)
            .expect("wire sequence two");
        let envelope = session.prepare(wire, 1).expect("envelope sequence two");
        assert_eq!(
            session.commit(ArgusIpcRequest {
                mapping_generation: 99,
                ..envelope
            }),
            Err(EndpointError::WrongGeneration)
        );
        session.commit(envelope).expect("commit");
        assert_eq!(session.commit(envelope), Err(EndpointError::Busy));
    }
}
