//! Process-wide UDP discovery endpoint (port 22223) shared by the client scanner and the server.
//!
//! Exactly ONE socket per process owns the discovery port. A dedicated OS thread receives packets and
//! dispatches them by their `magic` field:
//! * `LANSHARE_BEACON_V2`  -> stored in a short-lived cache read by `scan_lan_for_hosts`
//! * `LANSHARE_PROBE_V2`   -> forwarded to the running server (if hosting)
//! * `LANSHARE_REVCONN_V2` -> forwarded to the running server (if hosting)
//!
//! Sending everything (beacons, probes, reverse-connect requests) from this same socket keeps the
//! source port at 22223, so stateful firewalls (`nf_conntrack`, Windows Firewall) treat the peer's
//! replies to 22223 as `ESTABLISHED` traffic.

use crate::network::verify_ring_beacon_tag;
use crate::protocol::{
    DiscoveryBeacon, DiscoveryProbe, ReverseConnectRequest, BEACON_MAGIC, DEFAULT_UDP_PORT,
    PROBE_MAGIC, REVERSE_MAGIC,
};
use crate::security::is_private_lan_ip;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;

fn lock_mutex<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

const MAX_CACHED_BEACONS: usize = 256;
const BEACON_CACHE_TTL: Duration = Duration::from_secs(60);

/// A beacon received from the network (not yet verified against any LAN secret).
#[derive(Debug, Clone)]
pub struct ReceivedBeacon {
    pub beacon: DiscoveryBeacon,
    pub src: IpAddr,
    pub src_port: u16,
    pub received_at: Instant,
}

/// Control packets forwarded to the active server.
#[derive(Debug)]
pub enum ControlPacket {
    Probe(DiscoveryProbe, SocketAddr),
    Reverse(ReverseConnectRequest, SocketAddr),
}

struct ServerRegistration {
    id: u64,
    tx: UnboundedSender<ControlPacket>,
    host_name: String,
    tcp_port: u16,
}

pub struct DiscoveryService {
    send_sock: UdpSocket,
    local_port: u16,
    control_sock: UdpSocket,
    control_port: u16,
    beacons: Mutex<HashMap<(IpAddr, u16, u16), ReceivedBeacon>>,
    recent_ips: Mutex<HashMap<IpAddr, Instant>>,
    recent_addrs: Mutex<HashMap<SocketAddr, Instant>>,
    server: Mutex<Option<ServerRegistration>>,
    next_id: AtomicU64,
}

#[derive(Deserialize)]
struct MagicOnly {
    magic: String,
}

static SERVICE: OnceLock<Option<DiscoveryService>> = OnceLock::new();

/// Returns the process-wide discovery service, starting it on first use.
pub fn service() -> Option<&'static DiscoveryService> {
    SERVICE.get_or_init(DiscoveryService::start).as_ref()
}

impl DiscoveryService {
    fn spawn_recv_thread(name: &str, recv_sock: UdpSocket) -> Option<()> {
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match recv_sock.recv_from(&mut buf) {
                        Ok((len, src)) => {
                            if let Some(svc) = service() {
                                svc.handle_packet(&buf[..len], src);
                            }
                        }
                        // Windows reports ICMP "port unreachable" as WSAECONNRESET on the next recv;
                        // back off briefly instead of spinning.
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
            .ok()
            .map(|_| ())
    }

    fn start() -> Option<Self> {
        let sock = Self::bind_discovery_socket()?;
        let local_port = sock.local_addr().ok()?.port();
        let recv_sock = sock.try_clone().ok()?;

        // Exclusive per-instance UDP control socket so multiple LanShare processes on the same host
        // can each receive unicast probes and ReverseConnectRequest packets without SO_REUSEPORT/SO_REUSEADDR hijacking.
        let control_sock = Self::bind_control_socket().or_else(|| sock.try_clone().ok())?;
        let control_port = control_sock.local_addr().ok()?.port();

        Self::spawn_recv_thread("lanshare-discovery", recv_sock)?;
        if control_port != local_port {
            if let Ok(ctrl_recv) = control_sock.try_clone() {
                let _ = Self::spawn_recv_thread("lanshare-discovery-ctrl", ctrl_recv);
            }
        }

        Some(Self {
            send_sock: sock,
            local_port,
            control_sock,
            control_port,
            beacons: Mutex::new(HashMap::new()),
            recent_ips: Mutex::new(HashMap::new()),
            recent_addrs: Mutex::new(HashMap::new()),
            server: Mutex::new(None),
            next_id: AtomicU64::new(1),
        })
    }

    fn bind_control_socket() -> Option<UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .ok()?;
        let _ = socket.set_broadcast(true);
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        socket.bind(&socket2::SockAddr::from(addr)).ok()?;
        Some(socket.into())
    }

    fn bind_discovery_socket() -> Option<UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .ok()?;
        let _ = socket.set_reuse_address(true);
        #[cfg(unix)]
        {
            let optval: libc::c_int = 1;
            // SAFETY: `socket` is a valid open file descriptor owned by this scope,
            // and `optval` points to an initialized `c_int` of `size_of_val(&optval)` bytes.
            unsafe {
                let _ = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }
        let _ = socket.set_broadcast(true);
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_UDP_PORT);
        if socket.bind(&socket2::SockAddr::from(addr)).is_err() {
            let fallback = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
            socket.bind(&socket2::SockAddr::from(fallback)).ok()?;
        }
        let std_sock: std::net::UdpSocket = socket.into();
        Some(std_sock)
    }

    pub fn record_authenticated_peer_ip(&self, ip: IpAddr) {
        if !is_private_lan_ip(&ip) {
            return;
        }
        let mut map = lock_mutex(&self.recent_ips);
        if map.len() >= 256 {
            map.retain(|_, time| time.elapsed() < Duration::from_secs(120));
        }
        if map.len() < 256 || map.contains_key(&ip) {
            map.insert(ip, Instant::now());
        }
    }

    pub fn record_authenticated_peer_addr(&self, addr: SocketAddr) {
        if !is_private_lan_ip(&addr.ip()) || addr.port() < 1024 {
            return;
        }
        self.record_authenticated_peer_ip(addr.ip());
        let mut map = lock_mutex(&self.recent_addrs);
        if map.len() >= 256 {
            map.retain(|_, time| time.elapsed() < Duration::from_secs(120));
        }
        if map.len() < 256 || map.contains_key(&addr) {
            map.insert(addr, Instant::now());
        }
    }

    fn handle_packet(&self, data: &[u8], src: SocketAddr) {
        if !is_private_lan_ip(&src.ip()) || src.port() < 1024 {
            return;
        }
        let Ok(header) = serde_json::from_slice::<MagicOnly>(data) else {
            return;
        };

        match header.magic.as_str() {
            BEACON_MAGIC => {
                if let Ok(beacon) = serde_json::from_slice::<DiscoveryBeacon>(data) {
                    if beacon.port < 1024 {
                        return;
                    }
                    let mut map = lock_mutex(&self.beacons);
                    if map.len() >= MAX_CACHED_BEACONS {
                        map.retain(|_, b| b.received_at.elapsed() < BEACON_CACHE_TTL);
                    }
                    let key = (src.ip(), beacon.port, src.port());
                    if map.len() < MAX_CACHED_BEACONS || map.contains_key(&key) {
                        map.insert(
                            key,
                            ReceivedBeacon {
                                beacon,
                                src: src.ip(),
                                src_port: src.port(),
                                received_at: Instant::now(),
                            },
                        );
                    }
                }
            }
            PROBE_MAGIC => {
                if let Ok(probe) = serde_json::from_slice::<DiscoveryProbe>(data) {
                    self.forward(ControlPacket::Probe(probe, src));
                }
            }
            REVERSE_MAGIC => {
                if let Ok(req) = serde_json::from_slice::<ReverseConnectRequest>(data) {
                    self.forward(ControlPacket::Reverse(req, src));
                }
            }
            _ => {}
        }
    }

    fn forward(&self, pkt: ControlPacket) {
        if let Some(reg) = lock_mutex(&self.server).as_ref() {
            let _ = reg.tx.send(pkt);
        }
    }

    /// Sends a datagram from the shared discovery socket (errors are ignored; UDP is best-effort).
    pub fn send_to(&self, data: &[u8], target: SocketAddr) {
        let _ = self.send_sock.send_to(data, target);
    }

    /// Sends a datagram from this process's exclusive UDP control socket so replies return
    /// directly to this instance even when multiple LanShare processes share port 22223.
    pub fn send_from_control(&self, data: &[u8], target: SocketAddr) {
        let _ = self.control_sock.send_to(data, target);
    }

    /// Sends a datagram from both the shared discovery socket (`:22223`) and the exclusive
    /// control socket, matching firewall pinholes opened on either source port.
    pub fn send_from_both(&self, data: &[u8], target: SocketAddr) {
        let _ = self.send_sock.send_to(data, target);
        if self.control_port != self.local_port {
            let _ = self.control_sock.send_to(data, target);
        }
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn control_port(&self) -> u16 {
        self.control_port
    }

    /// Returns beacons received at or after `since`.
    pub fn beacons_since(&self, since: Instant) -> Vec<ReceivedBeacon> {
        lock_mutex(&self.beacons)
            .values()
            .filter(|b| b.received_at >= since)
            .cloned()
            .collect()
    }

    /// Returns the UDP source port last seen on HMAC-verified beacons from `(ip, tcp_port)` for `secret`,
    /// falling back to `22223`. Prevents unauthenticated or different-key LAN packets from hijacking Reverse TCP.
    pub fn peer_udp_port_for_secret(&self, ip: IpAddr, tcp_port: u16, secret: &str) -> u16 {
        let clean = secret.trim();
        if clean.is_empty() {
            return DEFAULT_UDP_PORT;
        }
        lock_mutex(&self.beacons)
            .values()
            .filter(|b| {
                b.src == ip
                    && b.beacon.port == tcp_port
                    && b.src_port >= 1024
                    && verify_ring_beacon_tag(
                        &b.beacon.host_name,
                        b.beacon.port,
                        &b.beacon.nonce,
                        clean,
                        &b.beacon.ring_tag,
                    )
            })
            .max_by_key(|b| b.received_at)
            .map(|b| b.src_port)
            .unwrap_or(DEFAULT_UDP_PORT)
    }

    /// Returns the UDP source port last seen on beacons from `(ip, tcp_port)`, falling back to `22223`.
    pub fn peer_udp_port(&self, ip: IpAddr, tcp_port: u16) -> u16 {
        lock_mutex(&self.beacons)
            .values()
            .filter(|b| b.src == ip && b.beacon.port == tcp_port && b.src_port >= 1024)
            .max_by_key(|b| b.received_at)
            .map(|b| b.src_port)
            .unwrap_or(DEFAULT_UDP_PORT)
    }

    /// Unique `(ip, udp_port)` endpoints of recently heard beacons whose `ring_tag` is verified for `secret`.
    pub fn recent_beacon_udp_targets_for_secret(
        &self,
        within: Duration,
        secret: &str,
    ) -> Vec<SocketAddr> {
        let clean = secret.trim();
        if clean.is_empty() {
            return Vec::new();
        }
        let mut addrs: Vec<SocketAddr> = lock_mutex(&self.beacons)
            .values()
            .filter(|b| {
                b.received_at.elapsed() < within
                    && b.src_port >= 1024
                    && verify_ring_beacon_tag(
                        &b.beacon.host_name,
                        b.beacon.port,
                        &b.beacon.nonce,
                        clean,
                        &b.beacon.ring_tag,
                    )
            })
            .map(|b| SocketAddr::new(b.src, b.src_port))
            .collect();
        addrs.sort();
        addrs.dedup();
        addrs
    }

    /// Source IPs of any authenticated peers seen recently (used to keep firewall pinholes open).
    pub fn recent_peer_ips(&self, within: Duration) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = lock_mutex(&self.recent_ips)
            .iter()
            .filter(|(_, time)| time.elapsed() < within)
            .map(|(ip, _)| *ip)
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }

    /// Source `SocketAddr`s of authenticated peers seen recently (preserves per-instance UDP ports).
    pub fn recent_peer_addrs(&self, within: Duration) -> Vec<SocketAddr> {
        let mut addrs: Vec<SocketAddr> = lock_mutex(&self.recent_addrs)
            .iter()
            .filter(|(_, time)| time.elapsed() < within)
            .map(|(addr, _)| *addr)
            .collect();
        addrs.sort();
        addrs.dedup();
        addrs
    }

    /// Registers the running server so it receives probes / reverse-connect requests.
    /// Returns an id that must be passed to `unregister_server`.
    pub fn register_server(
        &self,
        tx: UnboundedSender<ControlPacket>,
        host_name: String,
        tcp_port: u16,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        *lock_mutex(&self.server) = Some(ServerRegistration {
            id,
            tx,
            host_name,
            tcp_port,
        });
        id
    }

    /// Unregisters the server only if it is still the one identified by `id`.
    pub fn unregister_server(&self, id: u64) {
        let mut guard = lock_mutex(&self.server);
        if guard.as_ref().map(|r| r.id) == Some(id) {
            *guard = None;
        }
    }

    /// Host name and TCP port of the server running in this process, if any.
    pub fn local_server(&self) -> Option<(String, u16)> {
        lock_mutex(&self.server)
            .as_ref()
            .map(|r| (r.host_name.clone(), r.tcp_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_service_registration_and_unregistration() {
        let svc = service().expect("discovery service should start");
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let id = svc.register_server(tx, "TestHost".to_string(), 22222);

        let local = svc.local_server();
        assert_eq!(local, Some(("TestHost".to_string(), 22222)));

        svc.unregister_server(id);
        assert_eq!(svc.local_server(), None);
    }

    #[test]
    fn test_discovery_service_tracks_per_instance_udp_ports() {
        let svc = service().expect("discovery service should start");
        assert_ne!(svc.control_port(), 0);

        let beacon1 = DiscoveryBeacon::new("MultiHost".to_string(), 22222, "ring-a-secret");
        let beacon2 = DiscoveryBeacon::new("MultiHost".to_string(), 43867, "ring-b-secret");
        let ip: IpAddr = "192.168.0.199".parse().unwrap();

        svc.handle_packet(
            &serde_json::to_vec(&beacon1).unwrap(),
            SocketAddr::new(ip, 50101),
        );
        svc.handle_packet(
            &serde_json::to_vec(&beacon2).unwrap(),
            SocketAddr::new(ip, 50102),
        );

        assert_eq!(svc.peer_udp_port(ip, 22222), 50101);
        assert_eq!(svc.peer_udp_port(ip, 43867), 50102);
        assert_eq!(svc.peer_udp_port(ip, 55555), DEFAULT_UDP_PORT);

        // Rogue / wrong-secret beacon claiming the same (ip, tcp_port) from another UDP source port
        // must NOT hijack peer_udp_port_for_secret or recent_beacon_udp_targets_for_secret.
        let rogue_beacon = DiscoveryBeacon::new("MultiHost".to_string(), 43867, "wrong-secret");
        svc.handle_packet(
            &serde_json::to_vec(&rogue_beacon).unwrap(),
            SocketAddr::new(ip, 59999),
        );
        // Privileged UDP source port (< 1024) is ignored completely
        svc.handle_packet(
            &serde_json::to_vec(&beacon2).unwrap(),
            SocketAddr::new(ip, 53),
        );

        assert_eq!(
            svc.peer_udp_port_for_secret(ip, 43867, "ring-b-secret"),
            50102
        );
        assert_eq!(
            svc.peer_udp_port_for_secret(ip, 43867, "wrong-secret"),
            59999
        );
        assert_eq!(
            svc.peer_udp_port_for_secret(ip, 43867, "unknown-secret"),
            DEFAULT_UDP_PORT
        );
        let verified_targets =
            svc.recent_beacon_udp_targets_for_secret(Duration::from_secs(60), "ring-b-secret");
        assert!(verified_targets.contains(&SocketAddr::new(ip, 50102)));
        assert!(!verified_targets.contains(&SocketAddr::new(ip, 59999)));
        assert!(!verified_targets.contains(&SocketAddr::new(ip, 53)));
    }
}
