//! Measured Intel 8254x link-layer initialization.
//!
//! Arach owns the e1000 MMIO aperture and DMA descriptor rings.  This
//! module deliberately exposes Ethernet frames only to a future in-kernel
//! transport broker: user space never receives NIC registers, descriptor
//! addresses, or PCI configuration authority.

use core::sync::atomic::{Ordering, compiler_fence};

use crate::mmio::{MmioAccessError, MmioWindow};
use crate::sync::SpinLock;

pub const INTEL_VENDOR_ID: u16 = 0x8086;
pub const QEMU_E1000_DEVICE_ID: u16 = 0x100e;
pub const RING_LENGTH: usize = 8;
pub const FRAME_BYTES: usize = 2048;
const BOOTSTRAP_DNS_NAME: &[u8] = b"example.com";
const RESET_POLL_BUDGET: usize = 1_000_000;
const LOCAL_NETWORK_POLL_BUDGET: usize = 1_000_000;

const CTRL: usize = 0x0000;
const STATUS: usize = 0x0008;
const ICR: usize = 0x00c0;
const IMC: usize = 0x00d8;
const RCTL: usize = 0x0100;
const TCTL: usize = 0x0400;
const TIPG: usize = 0x0410;
const RAL0: usize = 0x5400;
const RAH0: usize = 0x5404;
const RDBAL: usize = 0x2800;
const RDBAH: usize = 0x2804;
const RDLEN: usize = 0x2808;
const RDH: usize = 0x2810;
const RDT: usize = 0x2818;
const TDBAL: usize = 0x3800;
const TDBAH: usize = 0x3804;
const TDLEN: usize = 0x3808;
const TDH: usize = 0x3810;
const TDT: usize = 0x3818;

const CTRL_RST: u32 = 1 << 26;
const STATUS_LINK_UP: u32 = 1 << 1;
const RCTL_ENABLE: u32 = 1 << 1;
const RCTL_BROADCAST_ACCEPT: u32 = 1 << 15;
const RCTL_STRIP_CRC: u32 = 1 << 26;
const TCTL_ENABLE: u32 = 1 << 1;
const TCTL_PAD_SHORT_PACKETS: u32 = 1 << 3;
const TCTL_COLLISION_THRESHOLD: u32 = 0x0f << 4;
const TCTL_COLLISION_DISTANCE: u32 = 0x40 << 12;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveDescriptor {
    pub buffer_address: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

impl ReceiveDescriptor {
    pub const EMPTY: Self = Self {
        buffer_address: 0,
        length: 0,
        checksum: 0,
        status: 0,
        errors: 0,
        special: 0,
    };
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitDescriptor {
    pub buffer_address: u64,
    pub length: u16,
    pub checksum_offset: u8,
    pub command: u8,
    pub status: u8,
    pub checksum_start: u8,
    pub special: u16,
}

impl TransmitDescriptor {
    pub const EMPTY: Self = Self {
        buffer_address: 0,
        length: 0,
        checksum_offset: 0,
        command: 0,
        status: 0,
        checksum_start: 0,
        special: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaRings {
    pub receive_descriptors: u64,
    pub transmit_descriptors: u64,
}

impl DmaRings {
    pub const fn new(receive_descriptors: u64, transmit_descriptors: u64) -> Result<Self, Error> {
        if receive_descriptors == 0
            || transmit_descriptors == 0
            || receive_descriptors & 0xf != 0
            || transmit_descriptors & 0xf != 0
        {
            return Err(Error::InvalidDmaLayout);
        }
        Ok(Self {
            receive_descriptors,
            transmit_descriptors,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInfo {
    pub mac_address: [u8; 6],
    pub link_up: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DhcpOffer {
    pub address: [u8; 4],
    pub server_identifier: [u8; 4],
}

/// Network parameters retained by Arach after a successful DHCP exchange.
///
/// This is deliberately a data-only snapshot.  It is consumable by the future
/// kernel-owned transport broker, but does not hand any NIC or packet authority
/// to user space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkConfiguration {
    pub address: [u8; 4],
    pub subnet_mask: Option<[u8; 4]>,
    pub router: Option<[u8; 4]>,
    pub dns_server: Option<[u8; 4]>,
    /// The router's Ethernet address, obtained by a bounded ARP exchange.
    /// A missing value means DHCP did not provide a router or it did not
    /// answer before the kernel's poll budget expired.
    pub gateway_hardware_address: Option<[u8; 6]>,
    /// True only after the resolved gateway returned a matching ICMP echo
    /// reply over the configured IPv4 path.
    pub gateway_echo_reply: bool,
    /// Hardware address resolved for the DHCP-provided DNS server.
    pub dns_hardware_address: Option<[u8; 6]>,
    /// A bounded A-record bootstrap probe. This is not a trust decision: TLS
    /// must validate its peer independently of any DNS result.
    pub dns_probe_address: Option<[u8; 4]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Mmio,
    InvalidDmaLayout,
    InvalidMac,
    ResetTimeout,
    Offline,
    Busy,
    InvalidFrame,
    ReceiveError,
    DhcpDenied,
}

impl From<MmioAccessError> for Error {
    fn from(_: MmioAccessError) -> Self {
        Self::Mmio
    }
}

struct Controller {
    mmio: MmioWindow,
    receive_descriptors: *mut ReceiveDescriptor,
    transmit_descriptors: *mut TransmitDescriptor,
    receive_buffers: *mut u8,
    transmit_buffers: *mut u8,
    receive_next: usize,
    transmit_next: usize,
}

// SAFETY: the sole global controller is accessed only under the controller
// spin lock. Its MMIO mapping and static DMA arena live for the kernel's
// lifetime after boot publication.
unsafe impl Send for Controller {}

static CONTROLLER: SpinLock<Option<Controller>> = SpinLock::new(None);
static NETWORK_CONFIGURATION: SpinLock<Option<NetworkConfiguration>> = SpinLock::new(None);

/// Programs one 8254x device with the fixed-size rings owned by Arach.
///
/// The caller must have already measured the exact PCI function, proved its
/// BAR aperture, retained the DMA storage for the device lifetime, and enabled
/// bus mastering only for that storage.
pub fn initialize(mmio: &MmioWindow, rings: DmaRings) -> Result<LinkInfo, Error> {
    if core::mem::size_of::<ReceiveDescriptor>() != 16
        || core::mem::size_of::<TransmitDescriptor>() != 16
    {
        return Err(Error::InvalidDmaLayout);
    }

    mmio.write_u32(IMC, u32::MAX)?;
    let _ = mmio.read_u32(ICR)?;
    let mac_address = read_mac(mmio)?;
    mmio.write_u32(CTRL, mmio.read_u32(CTRL)? | CTRL_RST)?;
    for _ in 0..RESET_POLL_BUDGET {
        if mmio.read_u32(CTRL)? & CTRL_RST == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    if mmio.read_u32(CTRL)? & CTRL_RST != 0 {
        return Err(Error::ResetTimeout);
    }

    write_mac(mmio, mac_address)?;
    configure_receive(mmio, rings.receive_descriptors)?;
    configure_transmit(mmio, rings.transmit_descriptors)?;
    compiler_fence(Ordering::SeqCst);
    Ok(LinkInfo {
        mac_address,
        link_up: mmio.read_u32(STATUS)? & STATUS_LINK_UP != 0,
    })
}

/// Stops DMA before the PCI bus-master lease or MMIO aperture is released.
pub fn quiesce(mmio: &MmioWindow) -> Result<(), Error> {
    mmio.write_u32(IMC, u32::MAX)?;
    mmio.write_u32(RCTL, 0)?;
    mmio.write_u32(TCTL, 0)?;
    compiler_fence(Ordering::SeqCst);
    let _ = mmio.read_u32(ICR)?;
    Ok(())
}

/// Publishes the initialized controller to Arach's future socket broker.
///
/// # Safety
///
/// The caller must provide pointers into static, coherent DMA storage that
/// remains valid until the kernel shuts the device down. The e1000 must be
/// initialized with descriptor ring physical addresses for exactly this
/// storage, and no other controller may be published.
pub unsafe fn publish(
    mmio: MmioWindow,
    receive_descriptors: *mut ReceiveDescriptor,
    transmit_descriptors: *mut TransmitDescriptor,
    receive_buffers: *mut u8,
    transmit_buffers: *mut u8,
) {
    let mut controller = CONTROLLER.lock();
    assert!(controller.is_none(), "e1000 controller already published");
    assert!(!receive_descriptors.is_null());
    assert!(!transmit_descriptors.is_null());
    assert!(!receive_buffers.is_null());
    assert!(!transmit_buffers.is_null());
    *controller = Some(Controller {
        mmio,
        receive_descriptors,
        transmit_descriptors,
        receive_buffers,
        transmit_buffers,
        receive_next: 0,
        transmit_next: 0,
    });
}

/// Sends one bounded Ethernet frame through the kernel-owned e1000 ring.
pub fn send(frame: &[u8]) -> Result<(), Error> {
    if !(14..=FRAME_BYTES).contains(&frame.len()) {
        return Err(Error::InvalidFrame);
    }
    let mut controller = CONTROLLER.lock();
    let controller = controller.as_mut().ok_or(Error::Offline)?;
    let slot = controller.transmit_next;
    // SAFETY: publication checked the fixed static ring and buffer pointers;
    // the controller spin lock serializes producers, and slot is bounded.
    unsafe {
        let descriptor = controller.transmit_descriptors.add(slot);
        if core::ptr::read_volatile(core::ptr::addr_of!((*descriptor).status)) & 1 == 0 {
            return Err(Error::Busy);
        }
        let destination = controller
            .transmit_buffers
            .add(slot.checked_mul(FRAME_BYTES).ok_or(Error::InvalidFrame)?);
        destination.copy_from_nonoverlapping(frame.as_ptr(), frame.len());
        core::ptr::write_volatile(
            descriptor,
            TransmitDescriptor {
                buffer_address: (*descriptor).buffer_address,
                length: frame.len() as u16,
                checksum_offset: 0,
                // EOP | insert FCS | report status.
                command: 0x0b,
                status: 0,
                checksum_start: 0,
                special: 0,
            },
        );
    }
    compiler_fence(Ordering::SeqCst);
    controller.transmit_next = (slot + 1) % RING_LENGTH;
    controller
        .mmio
        .write_u32(TDT, controller.transmit_next as u32)?;
    Ok(())
}

/// Copies one complete received Ethernet frame into the caller's bounded
/// buffer. Ok(None) means the kernel-owned ring has no completed frame.
pub fn receive(output: &mut [u8]) -> Result<Option<usize>, Error> {
    let mut controller = CONTROLLER.lock();
    let controller = controller.as_mut().ok_or(Error::Offline)?;
    let slot = controller.receive_next;
    // SAFETY: publication checked the fixed static ring and buffer pointers;
    // the controller spin lock serializes consumers, and slot is bounded.
    unsafe {
        let descriptor = controller.receive_descriptors.add(slot);
        let observed = core::ptr::read_volatile(descriptor);
        if observed.status & 1 == 0 {
            return Ok(None);
        }
        if observed.errors != 0
            || !(14..=FRAME_BYTES).contains(&usize::from(observed.length))
            || usize::from(observed.length) > output.len()
        {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*descriptor).status), 0);
            controller.mmio.write_u32(RDT, slot as u32)?;
            controller.receive_next = (slot + 1) % RING_LENGTH;
            return Err(Error::ReceiveError);
        }
        let source = controller
            .receive_buffers
            .add(slot.checked_mul(FRAME_BYTES).ok_or(Error::ReceiveError)?);
        output[..usize::from(observed.length)]
            .as_mut_ptr()
            .copy_from_nonoverlapping(source, usize::from(observed.length));
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*descriptor).status), 0);
        compiler_fence(Ordering::SeqCst);
        controller.mmio.write_u32(RDT, slot as u32)?;
        controller.receive_next = (slot + 1) % RING_LENGTH;
        Ok(Some(usize::from(observed.length)))
    }
}

/// Acquires and retains a DHCP lease for Arach's future transport broker.
///
/// The exchange is bounded and runs entirely through Arach-owned DMA rings.
/// It intentionally does not expose a raw socket or device capability to Crest
/// or Argus.
pub fn acquire_dhcp(
    mac_address: [u8; 6],
    transaction_id: u32,
) -> Result<Option<NetworkConfiguration>, Error> {
    let mut discover = [0_u8; 320];
    let discover_length = build_dhcp_discover(&mut discover, mac_address, transaction_id)?;
    send(&discover[..discover_length])?;

    let Some(offer) = wait_for_dhcp_reply(mac_address, transaction_id, 2)? else {
        return Ok(None);
    };
    let offer = DhcpOffer {
        address: offer.address,
        server_identifier: offer.server_identifier.ok_or(Error::InvalidFrame)?,
    };

    let mut request = [0_u8; 320];
    let request_length = build_dhcp_request(&mut request, mac_address, transaction_id, offer)?;
    send(&request[..request_length])?;

    let Some(acknowledgement) = wait_for_dhcp_reply(mac_address, transaction_id, 5)? else {
        return Ok(None);
    };
    let mut configuration = NetworkConfiguration {
        address: acknowledgement.address,
        subnet_mask: acknowledgement.subnet_mask,
        router: acknowledgement.router,
        dns_server: acknowledgement.dns_server,
        gateway_hardware_address: None,
        gateway_echo_reply: false,
        dns_hardware_address: None,
        dns_probe_address: None,
    };
    if let Some(router) = configuration.router {
        configuration.gateway_hardware_address =
            resolve_arp(mac_address, configuration.address, router)?;
        if let Some(gateway_hardware_address) = configuration.gateway_hardware_address {
            configuration.gateway_echo_reply = probe_gateway_icmp(
                mac_address,
                gateway_hardware_address,
                configuration.address,
                router,
                transaction_id as u16,
            )?;
        }
    }
    if let Some(dns_server) = configuration.dns_server {
        configuration.dns_hardware_address =
            resolve_arp(mac_address, configuration.address, dns_server)?;
        if let Some(dns_hardware_address) = configuration.dns_hardware_address {
            configuration.dns_probe_address = resolve_dns_a(
                mac_address,
                dns_hardware_address,
                configuration.address,
                dns_server,
                transaction_id.rotate_left(13) as u16,
                BOOTSTRAP_DNS_NAME,
            )?;
        }
    }
    *NETWORK_CONFIGURATION.lock() = Some(configuration);
    Ok(Some(configuration))
}

/// Returns the currently retained network configuration, if DHCP succeeded.
///
/// This is the only network-state read boundary available before a transport
/// broker is implemented; it grants neither packet injection nor raw NIC
/// access.
pub fn network_configuration() -> Option<NetworkConfiguration> {
    *NETWORK_CONFIGURATION.lock()
}

fn wait_for_dhcp_reply(
    mac_address: [u8; 6],
    transaction_id: u32,
    expected_message_type: u8,
) -> Result<Option<DhcpReply>, Error> {
    let mut received = [0_u8; FRAME_BYTES];
    for _ in 0..LOCAL_NETWORK_POLL_BUDGET {
        match receive(&mut received) {
            Ok(Some(length)) => {
                if let Some(reply) =
                    parse_dhcp_reply(&received[..length], mac_address, transaction_id)
                {
                    if reply.message_type == 6 {
                        return Err(Error::DhcpDenied);
                    }
                    if reply.message_type == expected_message_type {
                        return Ok(Some(reply));
                    }
                }
            }
            Ok(None) => core::hint::spin_loop(),
            Err(Error::ReceiveError) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// Resolves an IPv4 next-hop through one bounded ARP exchange.
///
/// ARP remains entirely inside the e1000 broker: user space receives neither
/// Ethernet addresses nor a way to inject raw layer-two frames.
fn resolve_arp(
    mac_address: [u8; 6],
    local_address: [u8; 4],
    target_address: [u8; 4],
) -> Result<Option<[u8; 6]>, Error> {
    let mut request = [0_u8; 42];
    build_arp_request(&mut request, mac_address, local_address, target_address)?;
    send(&request)?;

    let mut received = [0_u8; FRAME_BYTES];
    for _ in 0..LOCAL_NETWORK_POLL_BUDGET {
        match receive(&mut received) {
            Ok(Some(length)) => {
                if let Some(hardware_address) = parse_arp_reply(
                    &received[..length],
                    mac_address,
                    local_address,
                    target_address,
                ) {
                    return Ok(Some(hardware_address));
                }
            }
            Ok(None) => core::hint::spin_loop(),
            Err(Error::ReceiveError) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn build_arp_request(
    output: &mut [u8],
    mac_address: [u8; 6],
    local_address: [u8; 4],
    target_address: [u8; 4],
) -> Result<(), Error> {
    if output.len() != 42 {
        return Err(Error::InvalidFrame);
    }
    output.fill(0);
    output[..6].fill(0xff);
    output[6..12].copy_from_slice(&mac_address);
    output[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    output[14..16].copy_from_slice(&1_u16.to_be_bytes());
    output[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    output[18] = 6;
    output[19] = 4;
    output[20..22].copy_from_slice(&1_u16.to_be_bytes());
    output[22..28].copy_from_slice(&mac_address);
    output[28..32].copy_from_slice(&local_address);
    output[38..42].copy_from_slice(&target_address);
    Ok(())
}

fn parse_arp_reply(
    frame: &[u8],
    mac_address: [u8; 6],
    local_address: [u8; 4],
    target_address: [u8; 4],
) -> Option<[u8; 6]> {
    if frame.len() < 42
        || frame[..6] != mac_address
        || frame[12..14] != 0x0806_u16.to_be_bytes()
        || frame[14..16] != 1_u16.to_be_bytes()
        || frame[16..18] != 0x0800_u16.to_be_bytes()
        || frame[18] != 6
        || frame[19] != 4
        || frame[20..22] != 2_u16.to_be_bytes()
        || frame[28..32] != target_address
        || frame[38..42] != local_address
    {
        return None;
    }
    let hardware_address = [
        frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
    ];
    if hardware_address == [0; 6]
        || hardware_address == [0xff; 6]
        || hardware_address[0] & 1 != 0
        || frame[6..12] != hardware_address
    {
        return None;
    }
    Some(hardware_address)
}

/// Sends one IPv4 ICMP echo request through the resolved gateway and accepts
/// only its exact reply. This establishes the privileged data-plane path
/// needed before the socket broker attempts DNS or TCP.
fn probe_gateway_icmp(
    mac_address: [u8; 6],
    gateway_hardware_address: [u8; 6],
    local_address: [u8; 4],
    gateway_address: [u8; 4],
    identifier: u16,
) -> Result<bool, Error> {
    let mut request = [0_u8; 42];
    build_icmp_echo_request(
        &mut request,
        mac_address,
        gateway_hardware_address,
        local_address,
        gateway_address,
        identifier,
    )?;
    send(&request)?;

    let mut received = [0_u8; FRAME_BYTES];
    for _ in 0..LOCAL_NETWORK_POLL_BUDGET {
        match receive(&mut received) {
            Ok(Some(length)) => {
                if parse_icmp_echo_reply(
                    &received[..length],
                    mac_address,
                    gateway_hardware_address,
                    local_address,
                    gateway_address,
                    identifier,
                ) {
                    return Ok(true);
                }
            }
            Ok(None) => core::hint::spin_loop(),
            Err(Error::ReceiveError) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn build_icmp_echo_request(
    output: &mut [u8],
    mac_address: [u8; 6],
    gateway_hardware_address: [u8; 6],
    local_address: [u8; 4],
    gateway_address: [u8; 4],
    identifier: u16,
) -> Result<(), Error> {
    const ETHERNET: usize = 14;
    const IPV4: usize = 20;
    const ICMP: usize = 8;
    if output.len() != ETHERNET + IPV4 + ICMP {
        return Err(Error::InvalidFrame);
    }
    output.fill(0);
    output[..6].copy_from_slice(&gateway_hardware_address);
    output[6..12].copy_from_slice(&mac_address);
    output[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = ETHERNET;
    output[ip] = 0x45;
    output[ip + 8] = 64;
    output[ip + 9] = 1;
    output[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(IPV4 + ICMP)
            .map_err(|_| Error::InvalidFrame)?
            .to_be_bytes(),
    );
    output[ip + 6..ip + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
    output[ip + 12..ip + 16].copy_from_slice(&local_address);
    output[ip + 16..ip + 20].copy_from_slice(&gateway_address);
    let ip_checksum = ipv4_checksum(&output[ip..ip + IPV4]);
    output[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    let icmp = ip + IPV4;
    output[icmp] = 8;
    output[icmp + 4..icmp + 6].copy_from_slice(&identifier.to_be_bytes());
    output[icmp + 6..icmp + 8].copy_from_slice(&1_u16.to_be_bytes());
    let icmp_checksum = internet_checksum(&output[icmp..icmp + ICMP]);
    output[icmp + 2..icmp + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(())
}

fn parse_icmp_echo_reply(
    frame: &[u8],
    mac_address: [u8; 6],
    gateway_hardware_address: [u8; 6],
    local_address: [u8; 4],
    gateway_address: [u8; 4],
    identifier: u16,
) -> bool {
    const ETHERNET: usize = 14;
    const IPV4: usize = 20;
    const ICMP: usize = 8;
    if frame.len() < ETHERNET + IPV4 + ICMP
        || frame[..6] != mac_address
        || frame[6..12] != gateway_hardware_address
        || frame[12..14] != 0x0800_u16.to_be_bytes()
        || frame[14] != 0x45
        || frame[23] != 1
        || ipv4_checksum(&frame[14..34]) != 0
        || frame[26..30] != gateway_address
        || frame[30..34] != local_address
    {
        return false;
    }
    let total_length = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    if total_length != IPV4 + ICMP || ETHERNET + total_length > frame.len() {
        return false;
    }
    let icmp = ETHERNET + IPV4;
    frame[icmp] == 0
        && frame[icmp + 1] == 0
        && internet_checksum(&frame[icmp..icmp + ICMP]) == 0
        && frame[icmp + 4..icmp + 6] == identifier.to_be_bytes()
        && frame[icmp + 6..icmp + 8] == 1_u16.to_be_bytes()
}

/// Resolves one A record through the DHCP-provided DNS service. The result is
/// retained only as a transport bootstrap observation; it is not a substitute
/// for the hostname authentication required by TLS.
fn resolve_dns_a(
    mac_address: [u8; 6],
    dns_hardware_address: [u8; 6],
    local_address: [u8; 4],
    dns_address: [u8; 4],
    transaction_id: u16,
    name: &[u8],
) -> Result<Option<[u8; 4]>, Error> {
    let mut request = [0_u8; 128];
    let request_length = build_dns_query(
        &mut request,
        mac_address,
        dns_hardware_address,
        local_address,
        dns_address,
        transaction_id,
        name,
    )?;
    send(&request[..request_length])?;

    let mut received = [0_u8; FRAME_BYTES];
    for _ in 0..LOCAL_NETWORK_POLL_BUDGET {
        match receive(&mut received) {
            Ok(Some(length)) => {
                if let Some(address) = parse_dns_a_response(
                    &received[..length],
                    mac_address,
                    dns_hardware_address,
                    local_address,
                    dns_address,
                    transaction_id,
                ) {
                    return Ok(Some(address));
                }
            }
            Ok(None) => core::hint::spin_loop(),
            Err(Error::ReceiveError) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn build_dns_query(
    output: &mut [u8],
    mac_address: [u8; 6],
    dns_hardware_address: [u8; 6],
    local_address: [u8; 4],
    dns_address: [u8; 4],
    transaction_id: u16,
    name: &[u8],
) -> Result<usize, Error> {
    const ETHERNET: usize = 14;
    const IPV4: usize = 20;
    const UDP: usize = 8;
    const DNS_HEADER: usize = 12;
    const DNS_SOURCE_PORT: u16 = 49_152;
    let name_length = dns_name_wire_length(name).ok_or(Error::InvalidFrame)?;
    let dns_length = DNS_HEADER
        .checked_add(name_length)
        .and_then(|length| length.checked_add(4))
        .ok_or(Error::InvalidFrame)?;
    let total = ETHERNET
        .checked_add(IPV4)
        .and_then(|length| length.checked_add(UDP))
        .and_then(|length| length.checked_add(dns_length))
        .ok_or(Error::InvalidFrame)?;
    if total > output.len() || total > FRAME_BYTES {
        return Err(Error::InvalidFrame);
    }
    output[..total].fill(0);
    output[..6].copy_from_slice(&dns_hardware_address);
    output[6..12].copy_from_slice(&mac_address);
    output[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

    let ip = ETHERNET;
    output[ip] = 0x45;
    output[ip + 8] = 64;
    output[ip + 9] = 17;
    output[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(UDP + dns_length)
            .map_err(|_| Error::InvalidFrame)?
            .to_be_bytes(),
    );
    output[ip + 6..ip + 8].copy_from_slice(&0x4000_u16.to_be_bytes());
    output[ip + 12..ip + 16].copy_from_slice(&local_address);
    output[ip + 16..ip + 20].copy_from_slice(&dns_address);
    let ip_checksum = ipv4_checksum(&output[ip..ip + IPV4]);
    output[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = ip + IPV4;
    output[udp..udp + 2].copy_from_slice(&DNS_SOURCE_PORT.to_be_bytes());
    output[udp + 2..udp + 4].copy_from_slice(&53_u16.to_be_bytes());
    output[udp + 4..udp + 6].copy_from_slice(
        &u16::try_from(UDP + dns_length)
            .map_err(|_| Error::InvalidFrame)?
            .to_be_bytes(),
    );

    let dns = udp + UDP;
    output[dns..dns + 2].copy_from_slice(&transaction_id.to_be_bytes());
    output[dns + 2..dns + 4].copy_from_slice(&0x0100_u16.to_be_bytes());
    output[dns + 4..dns + 6].copy_from_slice(&1_u16.to_be_bytes());
    let question = dns + DNS_HEADER;
    let name_end = write_dns_name(&mut output[question..question + name_length], name)?;
    if name_end != name_length {
        return Err(Error::InvalidFrame);
    }
    output[question + name_length..question + name_length + 2]
        .copy_from_slice(&1_u16.to_be_bytes());
    output[question + name_length + 2..question + name_length + 4]
        .copy_from_slice(&1_u16.to_be_bytes());
    let checksum = udp_checksum(local_address, dns_address, &output[udp..total]);
    output[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    Ok(total)
}

fn parse_dns_a_response(
    frame: &[u8],
    mac_address: [u8; 6],
    dns_hardware_address: [u8; 6],
    local_address: [u8; 4],
    dns_address: [u8; 4],
    transaction_id: u16,
) -> Option<[u8; 4]> {
    const ETHERNET: usize = 14;
    const IPV4: usize = 20;
    const UDP: usize = 8;
    const DNS_HEADER: usize = 12;
    const DNS_SOURCE_PORT: u16 = 49_152;
    if frame.len() < ETHERNET + IPV4 + UDP + DNS_HEADER
        || frame[..6] != mac_address
        || frame[6..12] != dns_hardware_address
        || frame[12..14] != 0x0800_u16.to_be_bytes()
        || frame[14] != 0x45
        || frame[23] != 17
        || ipv4_checksum(&frame[14..34]) != 0
        || frame[26..30] != dns_address
        || frame[30..34] != local_address
    {
        return None;
    }
    let total_length = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    if total_length < IPV4 + UDP + DNS_HEADER || ETHERNET + total_length > frame.len() {
        return None;
    }
    let udp = ETHERNET + IPV4;
    if frame[udp..udp + 2] != 53_u16.to_be_bytes()
        || frame[udp + 2..udp + 4] != DNS_SOURCE_PORT.to_be_bytes()
    {
        return None;
    }
    let udp_length = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
    if udp_length < UDP + DNS_HEADER || udp_length > total_length - IPV4 {
        return None;
    }
    let udp_end = udp + udp_length;
    let checksum = u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]);
    if checksum != 0 && !udp_checksum_is_valid(dns_address, local_address, &frame[udp..udp_end]) {
        return None;
    }

    let dns = udp + UDP;
    if frame[dns..dns + 2] != transaction_id.to_be_bytes() {
        return None;
    }
    let flags = u16::from_be_bytes([frame[dns + 2], frame[dns + 3]]);
    if flags & 0x8000 == 0 || flags & 0x780f != 0 {
        return None;
    }
    let questions = usize::from(u16::from_be_bytes([frame[dns + 4], frame[dns + 5]]));
    let answers = usize::from(u16::from_be_bytes([frame[dns + 6], frame[dns + 7]]));
    if questions != 1 || answers > 16 {
        return None;
    }
    let mut cursor = dns + DNS_HEADER;
    cursor = skip_dns_name(frame, cursor, udp_end)?;
    if cursor.checked_add(4)? > udp_end
        || frame[cursor..cursor + 2] != 1_u16.to_be_bytes()
        || frame[cursor + 2..cursor + 4] != 1_u16.to_be_bytes()
    {
        return None;
    }
    cursor += 4;
    for _ in 0..answers {
        cursor = skip_dns_name(frame, cursor, udp_end)?;
        if cursor.checked_add(10)? > udp_end {
            return None;
        }
        let record_type = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]);
        let record_class = u16::from_be_bytes([frame[cursor + 2], frame[cursor + 3]]);
        let data_length = usize::from(u16::from_be_bytes([frame[cursor + 8], frame[cursor + 9]]));
        cursor += 10;
        let data_end = cursor.checked_add(data_length)?;
        if data_end > udp_end {
            return None;
        }
        if record_type == 1 && record_class == 1 && data_length == 4 {
            return Some([
                frame[cursor],
                frame[cursor + 1],
                frame[cursor + 2],
                frame[cursor + 3],
            ]);
        }
        cursor = data_end;
    }
    None
}

fn dns_name_wire_length(name: &[u8]) -> Option<usize> {
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut length = 1_usize;
    let mut label_length = 0_usize;
    for byte in name.iter().copied().chain(core::iter::once(b'.')) {
        if byte == b'.' {
            if label_length == 0 || label_length > 63 {
                return None;
            }
            length = length.checked_add(1 + label_length)?;
            label_length = 0;
        } else if byte.is_ascii_alphanumeric() || byte == b'-' {
            label_length = label_length.checked_add(1)?;
        } else {
            return None;
        }
    }
    Some(length)
}

fn write_dns_name(output: &mut [u8], name: &[u8]) -> Result<usize, Error> {
    let expected = dns_name_wire_length(name).ok_or(Error::InvalidFrame)?;
    if output.len() != expected {
        return Err(Error::InvalidFrame);
    }
    let mut source = 0_usize;
    let mut destination = 0_usize;
    while source < name.len() {
        let label_start = source;
        while source < name.len() && name[source] != b'.' {
            source += 1;
        }
        let label_length = source - label_start;
        output[destination] = label_length as u8;
        destination += 1;
        output[destination..destination + label_length].copy_from_slice(&name[label_start..source]);
        destination += label_length;
        source += usize::from(source < name.len());
    }
    output[destination] = 0;
    Ok(destination + 1)
}

fn skip_dns_name(frame: &[u8], mut cursor: usize, end: usize) -> Option<usize> {
    for _ in 0..128 {
        let length = *frame.get(cursor)?;
        if length == 0 {
            let next = cursor.checked_add(1)?;
            return (next <= end).then_some(next);
        }
        if length & 0xc0 == 0xc0 {
            let next = cursor.checked_add(2)?;
            return (next <= end).then_some(next);
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        cursor = cursor.checked_add(1 + usize::from(length))?;
        if cursor > end {
            return None;
        }
    }
    None
}

fn build_dhcp_discover(
    output: &mut [u8],
    mac_address: [u8; 6],
    transaction_id: u32,
) -> Result<usize, Error> {
    const ETHERNET: usize = 14;
    const IPV4: usize = 20;
    const UDP: usize = 8;
    const BOOTP: usize = 236;
    const COOKIE: usize = 4;
    const OPTIONS: usize = 9;
    let dhcp_length = BOOTP + COOKIE + OPTIONS;
    let total = ETHERNET + IPV4 + UDP + dhcp_length;
    if total > output.len() {
        return Err(Error::InvalidFrame);
    }
    output[..total].fill(0);
    output[..6].fill(0xff);
    output[6..12].copy_from_slice(&mac_address);
    output[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

    let ip = ETHERNET;
    output[ip] = 0x45;
    output[ip + 8] = 64;
    output[ip + 9] = 17;
    output[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(IPV4 + UDP + dhcp_length)
            .map_err(|_| Error::InvalidFrame)?
            .to_be_bytes(),
    );
    output[ip + 6..ip + 8].copy_from_slice(&0x8000_u16.to_be_bytes());
    output[ip + 16..ip + 20].fill(0xff);
    let checksum = ipv4_checksum(&output[ip..ip + IPV4]);
    output[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());

    let udp = ip + IPV4;
    output[udp..udp + 2].copy_from_slice(&68_u16.to_be_bytes());
    output[udp + 2..udp + 4].copy_from_slice(&67_u16.to_be_bytes());
    output[udp + 4..udp + 6].copy_from_slice(
        &u16::try_from(UDP + dhcp_length)
            .map_err(|_| Error::InvalidFrame)?
            .to_be_bytes(),
    );

    let dhcp = udp + UDP;
    output[dhcp] = 1;
    output[dhcp + 1] = 1;
    output[dhcp + 2] = 6;
    output[dhcp + 4..dhcp + 8].copy_from_slice(&transaction_id.to_be_bytes());
    output[dhcp + 10..dhcp + 12].copy_from_slice(&0x8000_u16.to_be_bytes());
    output[dhcp + 28..dhcp + 34].copy_from_slice(&mac_address);
    output[dhcp + BOOTP..dhcp + BOOTP + COOKIE].copy_from_slice(&[99, 130, 83, 99]);
    output[dhcp + BOOTP + COOKIE..dhcp + BOOTP + COOKIE + OPTIONS]
        .copy_from_slice(&[53, 1, 1, 55, 4, 1, 3, 6, 255]);
    Ok(total)
}

fn build_dhcp_request(
    output: &mut [u8],
    mac_address: [u8; 6],
    transaction_id: u32,
    offer: DhcpOffer,
) -> Result<usize, Error> {
    const ETHERNET: usize = 14;
    const IPV4: usize = 20;
    const UDP: usize = 8;
    const BOOTP: usize = 236;
    const COOKIE: usize = 4;
    const OPTIONS: usize = 21;
    let dhcp_length = BOOTP + COOKIE + OPTIONS;
    let total = ETHERNET + IPV4 + UDP + dhcp_length;
    if total > output.len() {
        return Err(Error::InvalidFrame);
    }
    output[..total].fill(0);
    output[..6].fill(0xff);
    output[6..12].copy_from_slice(&mac_address);
    output[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

    let ip = ETHERNET;
    output[ip] = 0x45;
    output[ip + 8] = 64;
    output[ip + 9] = 17;
    output[ip + 2..ip + 4].copy_from_slice(
        &u16::try_from(IPV4 + UDP + dhcp_length)
            .map_err(|_| Error::InvalidFrame)?
            .to_be_bytes(),
    );
    output[ip + 6..ip + 8].copy_from_slice(&0x8000_u16.to_be_bytes());
    output[ip + 16..ip + 20].fill(0xff);
    let checksum = ipv4_checksum(&output[ip..ip + IPV4]);
    output[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());

    let udp = ip + IPV4;
    output[udp..udp + 2].copy_from_slice(&68_u16.to_be_bytes());
    output[udp + 2..udp + 4].copy_from_slice(&67_u16.to_be_bytes());
    output[udp + 4..udp + 6].copy_from_slice(
        &u16::try_from(UDP + dhcp_length)
            .map_err(|_| Error::InvalidFrame)?
            .to_be_bytes(),
    );

    let dhcp = udp + UDP;
    output[dhcp] = 1;
    output[dhcp + 1] = 1;
    output[dhcp + 2] = 6;
    output[dhcp + 4..dhcp + 8].copy_from_slice(&transaction_id.to_be_bytes());
    output[dhcp + 10..dhcp + 12].copy_from_slice(&0x8000_u16.to_be_bytes());
    output[dhcp + 28..dhcp + 34].copy_from_slice(&mac_address);
    output[dhcp + BOOTP..dhcp + BOOTP + COOKIE].copy_from_slice(&[99, 130, 83, 99]);
    output[dhcp + BOOTP + COOKIE..dhcp + BOOTP + COOKIE + OPTIONS].copy_from_slice(&[
        53,
        1,
        3, // DHCPREQUEST
        50,
        4,
        offer.address[0],
        offer.address[1],
        offer.address[2],
        offer.address[3],
        54,
        4,
        offer.server_identifier[0],
        offer.server_identifier[1],
        offer.server_identifier[2],
        offer.server_identifier[3],
        55,
        4,
        1,
        3,
        6,
        255,
    ]);
    Ok(total)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DhcpReply {
    message_type: u8,
    address: [u8; 4],
    server_identifier: Option<[u8; 4]>,
    subnet_mask: Option<[u8; 4]>,
    router: Option<[u8; 4]>,
    dns_server: Option<[u8; 4]>,
}

fn parse_dhcp_reply(frame: &[u8], mac_address: [u8; 6], transaction_id: u32) -> Option<DhcpReply> {
    if frame.len() < 14 + 20 + 8 + 240
        || frame[12..14] != 0x0800_u16.to_be_bytes()
        || frame[14] >> 4 != 4
        || frame[14] & 0x0f != 5
        || frame[23] != 17
    {
        return None;
    }
    let total_length = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    if total_length < 20 + 8 + 240 || total_length + 14 > frame.len() {
        return None;
    }
    if ipv4_checksum(&frame[14..34]) != 0 {
        return None;
    }
    let udp = 34;
    if frame[udp..udp + 2] != 67_u16.to_be_bytes()
        || frame[udp + 2..udp + 4] != 68_u16.to_be_bytes()
    {
        return None;
    }
    let udp_length = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
    if udp_length < 8 + 240 || udp_length > total_length - 20 {
        return None;
    }
    let dhcp = udp + 8;
    if frame[dhcp] != 2
        || frame[dhcp + 1] != 1
        || frame[dhcp + 2] != 6
        || frame[dhcp + 4..dhcp + 8] != transaction_id.to_be_bytes()
        || frame[dhcp + 28..dhcp + 34] != mac_address
        || frame[dhcp + 236..dhcp + 240] != [99, 130, 83, 99]
    {
        return None;
    }
    let mut option = dhcp + 240;
    let end = dhcp + udp_length - 8;
    let mut message_type = None;
    let mut server_identifier = None;
    let mut subnet_mask = None;
    let mut router = None;
    let mut dns_server = None;
    while option < end {
        match frame[option] {
            0 => option += 1,
            255 => break,
            kind => {
                let length = *frame.get(option + 1)? as usize;
                let value = frame.get(option + 2..option + 2 + length)?;
                match (kind, value) {
                    (53, [kind]) => {
                        message_type = Some(*kind);
                    }
                    (54, [a, b, c, d]) => server_identifier = Some([*a, *b, *c, *d]),
                    (1, [a, b, c, d]) => subnet_mask = Some([*a, *b, *c, *d]),
                    (3, [a, b, c, d, ..]) => router = Some([*a, *b, *c, *d]),
                    (6, [a, b, c, d, ..]) => dns_server = Some([*a, *b, *c, *d]),
                    _ => {}
                }
                option += 2 + length;
            }
        }
    }
    let message_type = message_type?;
    if !matches!(message_type, 2 | 5 | 6) {
        return None;
    }
    Some(DhcpReply {
        message_type,
        address: [
            frame[dhcp + 16],
            frame[dhcp + 17],
            frame[dhcp + 18],
            frame[dhcp + 19],
        ],
        server_identifier,
        subnet_mask,
        router,
        dns_server,
    })
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_finish(checksum_accumulate(0, bytes))
}

fn udp_checksum(source_address: [u8; 4], destination_address: [u8; 4], udp: &[u8]) -> u16 {
    let length = match u16::try_from(udp.len()) {
        Ok(length) => length,
        Err(_) => return 0,
    };
    let mut sum = checksum_accumulate(0, &source_address);
    sum = checksum_accumulate(sum, &destination_address);
    sum = checksum_accumulate(sum, &[0, 17]);
    sum = checksum_accumulate(sum, &length.to_be_bytes());
    let checksum = checksum_finish(checksum_accumulate(sum, udp));
    if checksum == 0 { u16::MAX } else { checksum }
}

fn udp_checksum_is_valid(
    source_address: [u8; 4],
    destination_address: [u8; 4],
    udp: &[u8],
) -> bool {
    let length = match u16::try_from(udp.len()) {
        Ok(length) => length,
        Err(_) => return false,
    };
    let mut sum = checksum_accumulate(0, &source_address);
    sum = checksum_accumulate(sum, &destination_address);
    sum = checksum_accumulate(sum, &[0, 17]);
    sum = checksum_accumulate(sum, &length.to_be_bytes());
    checksum_finish(checksum_accumulate(sum, udp)) == 0
}

fn checksum_accumulate(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([pair[0], pair[1]])));
    }
    if let Some(byte) = pairs.remainder().first() {
        sum = sum.wrapping_add(u32::from(*byte) << 8);
    }
    sum
}

fn checksum_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn read_mac(mmio: &MmioWindow) -> Result<[u8; 6], Error> {
    let low = mmio.read_u32(RAL0)?;
    let high = mmio.read_u32(RAH0)?;
    let mac = [
        low as u8,
        (low >> 8) as u8,
        (low >> 16) as u8,
        (low >> 24) as u8,
        high as u8,
        (high >> 8) as u8,
    ];
    if mac == [0; 6] || mac == [0xff; 6] || mac[0] & 1 != 0 {
        return Err(Error::InvalidMac);
    }
    Ok(mac)
}

fn write_mac(mmio: &MmioWindow, mac: [u8; 6]) -> Result<(), Error> {
    let low = u32::from(mac[0])
        | (u32::from(mac[1]) << 8)
        | (u32::from(mac[2]) << 16)
        | (u32::from(mac[3]) << 24);
    let high = u32::from(mac[4]) | (u32::from(mac[5]) << 8) | (1 << 31);
    mmio.write_u32(RAL0, low)?;
    mmio.write_u32(RAH0, high)?;
    Ok(())
}

fn configure_receive(mmio: &MmioWindow, address: u64) -> Result<(), Error> {
    let ring_bytes = u32::try_from(RING_LENGTH * core::mem::size_of::<ReceiveDescriptor>())
        .map_err(|_| Error::InvalidDmaLayout)?;
    mmio.write_u32(RDBAL, address as u32)?;
    mmio.write_u32(RDBAH, (address >> 32) as u32)?;
    mmio.write_u32(RDLEN, ring_bytes)?;
    mmio.write_u32(RDH, 0)?;
    mmio.write_u32(RDT, (RING_LENGTH - 1) as u32)?;
    mmio.write_u32(RCTL, RCTL_ENABLE | RCTL_BROADCAST_ACCEPT | RCTL_STRIP_CRC)?;
    Ok(())
}

fn configure_transmit(mmio: &MmioWindow, address: u64) -> Result<(), Error> {
    let ring_bytes = u32::try_from(RING_LENGTH * core::mem::size_of::<TransmitDescriptor>())
        .map_err(|_| Error::InvalidDmaLayout)?;
    mmio.write_u32(TDBAL, address as u32)?;
    mmio.write_u32(TDBAH, (address >> 32) as u32)?;
    mmio.write_u32(TDLEN, ring_bytes)?;
    mmio.write_u32(TDH, 0)?;
    mmio.write_u32(TDT, 0)?;
    mmio.write_u32(
        TCTL,
        TCTL_ENABLE | TCTL_PAD_SHORT_PACKETS | TCTL_COLLISION_THRESHOLD | TCTL_COLLISION_DISTANCE,
    )?;
    mmio.write_u32(TIPG, 0x0060_200a)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const TEST_TRANSACTION: u32 = 0x1020_3040;

    #[test]
    fn descriptor_abi_is_the_hardware_ring_width() {
        assert_eq!(core::mem::size_of::<ReceiveDescriptor>(), 16);
        assert_eq!(core::mem::size_of::<TransmitDescriptor>(), 16);
        assert_eq!(RING_LENGTH * core::mem::size_of::<ReceiveDescriptor>(), 128);
        assert_eq!(
            RING_LENGTH * core::mem::size_of::<TransmitDescriptor>(),
            128
        );
    }

    #[test]
    fn dma_rings_require_nonzero_sixteen_byte_addresses() {
        assert!(matches!(
            DmaRings::new(0, 0x2000),
            Err(Error::InvalidDmaLayout)
        ));
        assert!(matches!(
            DmaRings::new(0x1001, 0x2000),
            Err(Error::InvalidDmaLayout)
        ));
        assert_eq!(
            DmaRings::new(0x1000, 0x2000),
            Ok(DmaRings {
                receive_descriptors: 0x1000,
                transmit_descriptors: 0x2000,
            })
        );
    }

    #[test]
    fn discover_and_request_frames_are_bounded_and_identifiable() {
        let mut discover = [0_u8; 320];
        let length =
            build_dhcp_discover(&mut discover, TEST_MAC, TEST_TRANSACTION).expect("discover");
        assert_eq!(&discover[..6], &[0xff; 6]);
        assert_eq!(&discover[6..12], &TEST_MAC);
        assert_eq!(&discover[12..14], &0x0800_u16.to_be_bytes());
        assert_eq!(&discover[42 + 4..42 + 8], &TEST_TRANSACTION.to_be_bytes());
        assert_eq!(
            &discover[length - 9..length],
            &[53, 1, 1, 55, 4, 1, 3, 6, 255]
        );

        let mut request = [0_u8; 320];
        let length = build_dhcp_request(
            &mut request,
            TEST_MAC,
            TEST_TRANSACTION,
            DhcpOffer {
                address: [10, 0, 2, 15],
                server_identifier: [10, 0, 2, 2],
            },
        )
        .expect("request");
        assert_eq!(
            &request[length - 21..length],
            &[
                53, 1, 3, 50, 4, 10, 0, 2, 15, 54, 4, 10, 0, 2, 2, 55, 4, 1, 3, 6, 255,
            ]
        );
    }

    #[test]
    fn dhcp_reply_requires_matching_identity_and_has_network_parameters() {
        let mut frame = [0_u8; 320];
        let length = reply_frame(&mut frame, TEST_MAC, TEST_TRANSACTION, 5);
        assert_eq!(
            parse_dhcp_reply(&frame[..length], TEST_MAC, TEST_TRANSACTION),
            Some(DhcpReply {
                message_type: 5,
                address: [10, 0, 2, 15],
                server_identifier: Some([10, 0, 2, 2]),
                subnet_mask: Some([255, 255, 255, 0]),
                router: Some([10, 0, 2, 2]),
                dns_server: Some([10, 0, 2, 3]),
            })
        );
        assert_eq!(
            parse_dhcp_reply(&frame[..length], [0; 6], TEST_TRANSACTION),
            None
        );
    }

    #[test]
    fn arp_gateway_exchange_requires_exact_local_and_remote_identity() {
        let local_address = [10, 0, 2, 15];
        let gateway_address = [10, 0, 2, 2];
        let gateway_hardware_address = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let mut request = [0_u8; 42];
        build_arp_request(&mut request, TEST_MAC, local_address, gateway_address)
            .expect("ARP request");
        assert_eq!(&request[..6], &[0xff; 6]);
        assert_eq!(&request[6..12], &TEST_MAC);
        assert_eq!(&request[12..14], &0x0806_u16.to_be_bytes());
        assert_eq!(&request[28..32], &local_address);
        assert_eq!(&request[38..42], &gateway_address);

        let mut reply = request;
        reply[..6].copy_from_slice(&TEST_MAC);
        reply[6..12].copy_from_slice(&gateway_hardware_address);
        reply[20..22].copy_from_slice(&2_u16.to_be_bytes());
        reply[22..28].copy_from_slice(&gateway_hardware_address);
        reply[28..32].copy_from_slice(&gateway_address);
        reply[32..38].copy_from_slice(&TEST_MAC);
        reply[38..42].copy_from_slice(&local_address);
        assert_eq!(
            parse_arp_reply(&reply, TEST_MAC, local_address, gateway_address),
            Some(gateway_hardware_address)
        );
        reply[6] ^= 1;
        assert_eq!(
            parse_arp_reply(&reply, TEST_MAC, local_address, gateway_address),
            None
        );
    }

    #[test]
    fn icmp_gateway_reply_requires_the_exact_packet_identity() {
        let local_address = [10, 0, 2, 15];
        let gateway_address = [10, 0, 2, 2];
        let gateway_hardware_address = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let identifier = 0x2345;
        let mut request = [0_u8; 42];
        build_icmp_echo_request(
            &mut request,
            TEST_MAC,
            gateway_hardware_address,
            local_address,
            gateway_address,
            identifier,
        )
        .expect("ICMP request");
        assert_eq!(&request[..6], &gateway_hardware_address);
        assert_eq!(&request[6..12], &TEST_MAC);
        assert_eq!(&request[26..30], &local_address);
        assert_eq!(&request[30..34], &gateway_address);
        assert_eq!(internet_checksum(&request[34..42]), 0);

        let mut reply = request;
        reply[..6].copy_from_slice(&TEST_MAC);
        reply[6..12].copy_from_slice(&gateway_hardware_address);
        reply[26..30].copy_from_slice(&gateway_address);
        reply[30..34].copy_from_slice(&local_address);
        reply[24..26].fill(0);
        let ip_checksum = ipv4_checksum(&reply[14..34]);
        reply[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        reply[34] = 0;
        reply[36..38].fill(0);
        let icmp_checksum = internet_checksum(&reply[34..42]);
        reply[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
        assert!(parse_icmp_echo_reply(
            &reply,
            TEST_MAC,
            gateway_hardware_address,
            local_address,
            gateway_address,
            identifier
        ));
        reply[41] ^= 1;
        assert!(!parse_icmp_echo_reply(
            &reply,
            TEST_MAC,
            gateway_hardware_address,
            local_address,
            gateway_address,
            identifier
        ));
    }

    #[test]
    fn dns_query_and_response_bind_dns_transport_identity() {
        let local_address = [10, 0, 2, 15];
        let dns_address = [10, 0, 2, 3];
        let dns_hardware_address = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x03];
        let transaction_id = 0x3456;
        let mut query = [0_u8; 128];
        let query_length = build_dns_query(
            &mut query,
            TEST_MAC,
            dns_hardware_address,
            local_address,
            dns_address,
            transaction_id,
            BOOTSTRAP_DNS_NAME,
        )
        .expect("DNS query");
        assert_eq!(&query[..6], &dns_hardware_address);
        assert_eq!(&query[6..12], &TEST_MAC);
        assert_eq!(&query[42..44], &transaction_id.to_be_bytes());
        assert_eq!(&query[40..42], &0x2399_u16.to_be_bytes());
        assert_eq!(
            &query[54..67],
            &[
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );
        assert!(udp_checksum_is_valid(
            local_address,
            dns_address,
            &query[34..query_length]
        ));

        let mut response = [0_u8; 128];
        response[..query_length].copy_from_slice(&query[..query_length]);
        let answer = query_length;
        response[..6].copy_from_slice(&TEST_MAC);
        response[6..12].copy_from_slice(&dns_hardware_address);
        response[16..18].copy_from_slice(&73_u16.to_be_bytes());
        response[26..30].copy_from_slice(&dns_address);
        response[30..34].copy_from_slice(&local_address);
        response[24..26].fill(0);
        let ip_checksum = ipv4_checksum(&response[14..34]);
        response[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        response[34..36].copy_from_slice(&53_u16.to_be_bytes());
        response[36..38].copy_from_slice(&49_152_u16.to_be_bytes());
        response[38..40].copy_from_slice(&53_u16.to_be_bytes());
        response[40..42].fill(0);
        response[42 + 2..42 + 4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[42 + 6..42 + 8].copy_from_slice(&1_u16.to_be_bytes());
        response[answer..answer + 16]
            .copy_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let response_length = answer + 16;
        let checksum = udp_checksum(dns_address, local_address, &response[34..response_length]);
        response[40..42].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(
            parse_dns_a_response(
                &response[..response_length],
                TEST_MAC,
                dns_hardware_address,
                local_address,
                dns_address,
                transaction_id,
            ),
            Some([93, 184, 216, 34])
        );
        response[43] ^= 1;
        assert_eq!(
            parse_dns_a_response(
                &response[..response_length],
                TEST_MAC,
                dns_hardware_address,
                local_address,
                dns_address,
                transaction_id,
            ),
            None
        );
    }

    fn reply_frame(
        output: &mut [u8; 320],
        mac_address: [u8; 6],
        transaction_id: u32,
        message_type: u8,
    ) -> usize {
        const ETHERNET: usize = 14;
        const IPV4: usize = 20;
        const UDP: usize = 8;
        const BOOTP: usize = 236;
        const COOKIE: usize = 4;
        const OPTIONS: [u8; 28] = [
            53, 1, 5, 54, 4, 10, 0, 2, 2, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 2, 2, 6, 4, 10, 0,
            2, 3, 255,
        ];
        let dhcp_length = BOOTP + COOKIE + OPTIONS.len();
        let total = ETHERNET + IPV4 + UDP + dhcp_length;
        output[..total].fill(0);
        output[..6].copy_from_slice(&mac_address);
        output[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]);
        output[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());

        let ip = ETHERNET;
        output[ip] = 0x45;
        output[ip + 8] = 64;
        output[ip + 9] = 17;
        output[ip + 2..ip + 4].copy_from_slice(
            &u16::try_from(IPV4 + UDP + dhcp_length)
                .unwrap()
                .to_be_bytes(),
        );
        output[ip + 12..ip + 16].copy_from_slice(&[10, 0, 2, 2]);
        output[ip + 16..ip + 20].fill(0xff);
        let checksum = ipv4_checksum(&output[ip..ip + IPV4]);
        output[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());

        let udp = ip + IPV4;
        output[udp..udp + 2].copy_from_slice(&67_u16.to_be_bytes());
        output[udp + 2..udp + 4].copy_from_slice(&68_u16.to_be_bytes());
        output[udp + 4..udp + 6]
            .copy_from_slice(&u16::try_from(UDP + dhcp_length).unwrap().to_be_bytes());

        let dhcp = udp + UDP;
        output[dhcp] = 2;
        output[dhcp + 1] = 1;
        output[dhcp + 2] = 6;
        output[dhcp + 4..dhcp + 8].copy_from_slice(&transaction_id.to_be_bytes());
        output[dhcp + 16..dhcp + 20].copy_from_slice(&[10, 0, 2, 15]);
        output[dhcp + 28..dhcp + 34].copy_from_slice(&mac_address);
        output[dhcp + BOOTP..dhcp + BOOTP + COOKIE].copy_from_slice(&[99, 130, 83, 99]);
        let mut options = OPTIONS;
        options[2] = message_type;
        output[dhcp + BOOTP + COOKIE..dhcp + BOOTP + COOKIE + options.len()]
            .copy_from_slice(&options);
        total
    }
}
