use crate::network::{
    compute_tls_auth_token, get_broadcast_bindings, get_computer_name, make_client_tls_config,
    read_frame, verify_tls_server_auth_token, write_frame,
};
use crate::protocol::*;
use crate::security::{
    ensure_safe_client_dest_path, ensure_safe_client_dir, is_private_lan_ip, is_symlink_or_reparse,
    sanitize_client_relative_path,
};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub ip: String,
    pub port: u16,
    pub password: String,
    pub peer_name: Option<String>,
}

impl ConnectionContext {
    pub fn new(
        ip: impl Into<String>,
        port: u16,
        password: impl Into<String>,
        peer_name: Option<String>,
    ) -> Self {
        let normalized_name = peer_name
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty());
        Self {
            ip: ip.into(),
            port,
            password: password.into(),
            peer_name: normalized_name,
        }
    }
}

/// Retry and stall-detection policy for resilient file and folder transfers.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    pub tcp_connect_timeout: Duration,
    pub reverse_tcp_timeout: Duration,
    pub io_timeout: Duration,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    /// Maximum reconnect attempts after a recoverable network drop; `None` waits indefinitely.
    pub max_attempts: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            tcp_connect_timeout: Duration::from_millis(2000),
            reverse_tcp_timeout: Duration::from_millis(3800),
            io_timeout: Duration::from_secs(20),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            max_attempts: None,
        }
    }
}

enum TransferError {
    Fatal(String),
    Recoverable(String),
}

impl TransferError {
    fn into_message(self) -> String {
        match self {
            Self::Fatal(m) | Self::Recoverable(m) => m,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub selected_target: String,
    pub file_name: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub speed_mbps: f32,
    pub is_finished: bool,
    pub current_file: usize,
    pub total_files: usize,
    pub log_message: Option<String>,
}

pub type ClientTlsStream = TlsStream<TcpStream>;

/// Actively scans the LAN for hosts sharing with the same LAN secret.
/// Sends a deduplicated UDP `DiscoveryProbe` per broadcast domain from this instance's
/// exclusive control socket (`control_sock`) and collects jittered unicast replies and
/// cached V3 AEAD-encrypted beacons without any ARP or TCP port-scanning.
pub async fn scan_lan_for_hosts(
    timeout_dur: Duration,
    ring_secret: Option<&str>,
) -> Vec<DiscoveredPeer> {
    const MAX_DISCOVERED_PEERS: usize = 512;
    let mut discovered: HashMap<String, DiscoveredPeer> = HashMap::new();
    let clean_secret = ring_secret.map(|s| s.trim()).filter(|s| !s.is_empty());

    let svc = crate::discovery::service();

    let mut probed_udp_targets = std::collections::HashSet::<SocketAddr>::new();
    let probe_bytes_opt =
        clean_secret.and_then(|secret| serde_json::to_vec(&DiscoveryProbe::new(secret)).ok());
    if let (Some(s), Some(probe_bytes)) = (svc, probe_bytes_opt.as_ref()) {
        for binding in get_broadcast_bindings(DEFAULT_UDP_PORT) {
            for target in binding.targets {
                if probed_udp_targets.insert(target) {
                    s.send_from_both(probe_bytes, target);
                }
            }
        }
        // Punch Linux nf_conntrack pinholes for up to 16 active local ARP neighbors on our physical subnet
        for ip in crate::network::get_local_arp_neighbors_capped(16) {
            let target = SocketAddr::new(ip.into(), DEFAULT_UDP_PORT);
            if probed_udp_targets.insert(target) {
                s.send_from_both(probe_bytes, target);
            }
        }
        for ip in s.recent_peer_ips(Duration::from_secs(60)) {
            let target = SocketAddr::new(ip, DEFAULT_UDP_PORT);
            if probed_udp_targets.insert(target) {
                s.send_from_both(probe_bytes, target);
            }
        }
        for target in s.recent_peer_addrs(Duration::from_secs(60)) {
            if probed_udp_targets.insert(target) {
                s.send_from_both(probe_bytes, target);
            }
        }
        if let Some(secret) = clean_secret {
            for target in s.recent_beacon_udp_targets_for_secret(Duration::from_secs(60), secret) {
                if probed_udp_targets.insert(target) {
                    s.send_from_both(probe_bytes, target);
                }
            }
        }
    }

    let scan_start = Instant::now();
    let query_since = scan_start
        .checked_sub(Duration::from_secs(30))
        .unwrap_or(scan_start);

    while scan_start.elapsed() < timeout_dur {
        // Collect and decrypt V3 beacons from DiscoveryService cache
        if let (Some(s), Some(secret)) = (svc, clean_secret) {
            for b in s.beacons_since(query_since) {
                if is_private_lan_ip(&b.src) && discovered.len() < MAX_DISCOVERED_PEERS {
                    let Some(payload) = b.beacon.decrypt(secret) else {
                        continue;
                    };
                    s.record_authenticated_peer_ip(b.src);
                    if b.src_port >= 1024 && b.src_port != DEFAULT_UDP_PORT {
                        let peer_udp_target = SocketAddr::new(b.src, b.src_port);
                        if probed_udp_targets.insert(peer_udp_target) {
                            if let Some(ref probe_bytes) = probe_bytes_opt {
                                s.send_from_both(probe_bytes, peer_udp_target);
                            }
                        }
                    }

                    let host_name = sanitize_discovered_host_name(&payload.host_name);
                    let key = format!("{}:{}", b.src, payload.port);
                    discovered.insert(
                        key,
                        DiscoveredPeer {
                            host_name,
                            ip: b.src.to_string(),
                            port: payload.port,
                            last_seen: b.received_at,
                        },
                    );
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Include self if currently hosting on this machine
    if let Some((my_name, my_port)) = svc.and_then(|s| s.local_server()) {
        let all_ips = crate::network::get_all_local_lan_ips();
        let my_ip = all_ips
            .first()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        let key = format!("{}:{}", my_ip, my_port);
        discovered.entry(key).or_insert(DiscoveredPeer {
            host_name: my_name,
            ip: my_ip,
            port: my_port,
            last_seen: Instant::now(),
        });
    }

    let mut list: Vec<DiscoveredPeer> = discovered.into_values().collect();
    list.sort_by_key(|a| a.host_name.to_lowercase());
    // Deduplicate same host_name on same port if multiple interfaces responded
    list.dedup_by(|a, b| a.host_name == b.host_name && a.port == b.port && a.ip == b.ip);
    list
}

/// Runs the encrypted TLS client handshake and mutual channel-bound token authentication over an established `TcpStream`.
async fn perform_tls_client_handshake_step(
    tcp_stream: TcpStream,
    password: &str,
) -> Result<(ClientTlsStream, HandshakeResponse), TransferError> {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    let config = make_client_tls_config();
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from("lanshare.local")
        .map_err(|e| TransferError::Fatal(format!("Invalid DNS name: {:?}", e)))?
        .to_owned();

    let mut tls_stream = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connector.connect(server_name, tcp_stream),
    )
    .await
    .map_err(|_| TransferError::Recoverable("TLS handshake timed out.".to_string()))?
    .map_err(|e| TransferError::Recoverable(format!("TLS handshake failed: {}", e)))?;

    // Compute channel-bound authentication token
    let auth_token = compute_tls_auth_token(tls_stream.get_ref().1, password)
        .map_err(|e| TransferError::Fatal(format!("Channel auth token generation error: {}", e)))?;

    // Send HandshakeRequest
    let req = HandshakeRequest {
        auth_token,
        client_name: get_computer_name(),
    };

    let req_bytes = serde_json::to_vec(&req).map_err(|e| TransferError::Fatal(e.to_string()))?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, write_frame(&mut tls_stream, &req_bytes))
        .await
        .map_err(|_| TransferError::Recoverable("Handshake write timed out.".to_string()))?
        .map_err(|e| TransferError::Recoverable(format!("Network write error: {}", e)))?;

    // Read HandshakeResponse
    let resp_bytes = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_frame(&mut tls_stream))
        .await
        .map_err(|_| TransferError::Recoverable("Handshake response timed out.".to_string()))?
        .map_err(|e| TransferError::Recoverable(format!("Network read error: {}", e)))?;

    let resp: HandshakeResponse = serde_json::from_slice(&resp_bytes)
        .map_err(|e| TransferError::Fatal(format!("Invalid handshake response: {}", e)))?;

    if !resp.authenticated {
        return Err(TransferError::Fatal(resp.message));
    }

    // Mutually authenticate the server in constant time using a distinct TLS exporter label
    if !verify_tls_server_auth_token(tls_stream.get_ref().1, password, &resp.server_auth_token) {
        let _ = tls_stream.shutdown().await;
        return Err(TransferError::Fatal(
            "Server authentication failed: remote host did not prove knowledge of the LAN secret."
                .to_string(),
        ));
    }

    Ok((tls_stream, resp))
}

async fn connect_via_reverse_tcp_step(
    target_ip: IpAddr,
    udp_port: u16,
    password: &str,
    accept_timeout: Duration,
) -> Result<(ClientTlsStream, HandshakeResponse), TransferError> {
    // Try binding default TCP port 22222 first (reuses the well-known firewall-allowed port if client isn't hosting).
    // Fall back to an ephemeral port if 22222 is in use.
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", DEFAULT_TCP_PORT)).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind("0.0.0.0:0").await.map_err(|e| {
            TransferError::Recoverable(format!(
                "Failed to bind reverse TCP callback listener: {}",
                e
            ))
        })?,
    };
    let callback_port = listener
        .local_addr()
        .map_err(|e| TransferError::Recoverable(e.to_string()))?
        .port();

    let rev_req = ReverseConnectRequest::new(get_computer_name(), callback_port, password);
    let req_bytes =
        serde_json::to_vec(&rev_req).map_err(|e| TransferError::Fatal(e.to_string()))?;
    let udp_target = SocketAddr::new(target_ip, udp_port);

    // Send from the shared discovery service so source port is guaranteed to be 22223,
    // matching the host's nf_conntrack / stateful firewall pinhole.
    let svc = crate::discovery::service();

    let send_trigger = async {
        for _ in 0..4 {
            if let Some(s) = svc {
                s.send_from_both(&req_bytes, udp_target);
                if udp_port != DEFAULT_UDP_PORT {
                    s.send_from_both(&req_bytes, SocketAddr::new(target_ip, DEFAULT_UDP_PORT));
                }
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        std::future::pending::<()>().await;
    };

    let accept_fut = async {
        loop {
            let (tcp_stream, peer_addr) = listener
                .accept()
                .await
                .map_err(|e| format!("Reverse TCP accept error: {}", e))?;
            if peer_addr.ip() == target_ip {
                return Ok::<TcpStream, String>(tcp_stream);
            }
        }
    };

    let tcp_stream = tokio::select! {
        _ = send_trigger => unreachable!(),
        res = tokio::time::timeout(accept_timeout, accept_fut) => {
            match res {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(TransferError::Recoverable(e)),
                Err(_) => return Err(TransferError::Recoverable(
                    "Connection timed out (host firewall may be blocking connections).".to_string()
                )),
            }
        }
    };

    perform_tls_client_handshake_step(tcp_stream, password).await
}

/// Fallback when direct TCP connection to a host times out because the host's firewall (e.g. Linux `ufw`/`firewalld`)
/// blocks inbound TCP on port 22222. Opens a local TCP callback listener, sends a signed `ReverseConnectRequest`
/// over UDP `:22223` (through the host's UDP `nf_conntrack` pinhole), and runs the TLS client handshake on the
/// incoming TCP connection from the host.
pub async fn connect_via_reverse_tcp(
    target_ip: IpAddr,
    udp_port: u16,
    password: &str,
) -> Result<(ClientTlsStream, HandshakeResponse), String> {
    connect_via_reverse_tcp_step(target_ip, udp_port, password, Duration::from_millis(3800))
        .await
        .map_err(TransferError::into_message)
}

async fn connect_to_host_step(
    ip: &str,
    port: u16,
    password: &str,
    policy: ReconnectPolicy,
) -> Result<(ClientTlsStream, HandshakeResponse), TransferError> {
    let host_str = ip.trim();
    if host_str.is_empty() {
        return Err(TransferError::Fatal(
            "Please enter a host IP or hostname.".to_string(),
        ));
    }

    let target = if host_str.contains(':') {
        host_str.to_string()
    } else {
        format!("{}:{}", host_str, port)
    };

    let resolved_addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&target)
        .await
        .map_err(|e| TransferError::Recoverable(format!("Could not resolve '{}': {}", target, e)))?
        .collect();

    if resolved_addrs.is_empty() {
        return Err(TransferError::Recoverable(format!(
            "No address found for '{}'",
            target
        )));
    }

    let addr = resolved_addrs
        .into_iter()
        .find(|a| is_private_lan_ip(&a.ip()))
        .ok_or_else(|| {
            TransferError::Fatal(format!(
                "Security restriction: '{}' does not resolve to a private LAN IP address.",
                target
            ))
        })?;

    // 1. Try direct TCP connection first
    match tokio::time::timeout(policy.tcp_connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(tcp_stream)) => {
            return perform_tls_client_handshake_step(tcp_stream, password).await;
        }
        _ if !policy.reverse_tcp_timeout.is_zero() => {
            // 2. Direct TCP timed out or was refused (e.g. Linux ufw/firewalld blocking inbound TCP 22222 or ephemeral server port).
            // Only attempt Reverse TCP if we have a verified UDP beacon from this peer (or confirm via a quick unicast UDP probe
            // when the peer is on our local L2 subnet, in case the user waited >5m after scanning).
            // For cross-subnet / VPN Direct IP connections where no UDP beacon exists, skip Reverse TCP cleanly.
            let mut has_verified_udp = crate::discovery::service()
                .map(|s| s.has_verified_beacon(addr.ip(), addr.port(), password))
                .unwrap_or(false);

            if !has_verified_udp
                && !addr.ip().is_loopback()
                && crate::network::is_same_local_subnet(addr.ip())
            {
                if let Some(s) = crate::discovery::service() {
                    let probe = DiscoveryProbe::new(password);
                    if let Ok(bytes) = serde_json::to_vec(&probe) {
                        s.send_from_both(&bytes, SocketAddr::new(addr.ip(), DEFAULT_UDP_PORT));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    has_verified_udp = s.has_verified_beacon(addr.ip(), addr.port(), password);
                }
            }

            if has_verified_udp {
                let target_udp_port = crate::discovery::service()
                    .map(|s| s.peer_udp_port_for_secret(addr.ip(), addr.port(), password))
                    .unwrap_or(DEFAULT_UDP_PORT);

                if let Some(s) = crate::discovery::service() {
                    let probe = DiscoveryProbe::new(password);
                    if let Ok(bytes) = serde_json::to_vec(&probe) {
                        s.send_from_both(&bytes, SocketAddr::new(addr.ip(), target_udp_port));
                        if target_udp_port != DEFAULT_UDP_PORT {
                            s.send_from_both(&bytes, SocketAddr::new(addr.ip(), DEFAULT_UDP_PORT));
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;

                // Automatically attempt Reverse TCP traversal via the host's UDP control endpoint!
                match connect_via_reverse_tcp_step(
                    addr.ip(),
                    target_udp_port,
                    password,
                    policy.reverse_tcp_timeout,
                )
                .await
                {
                    Ok(res) => return Ok(res),
                    Err(TransferError::Fatal(e)) => return Err(TransferError::Fatal(e)),
                    Err(TransferError::Recoverable(_)) => {}
                }
            }
        }
        _ => {}
    }

    Err(TransferError::Recoverable(format!(
        "Connection timed out to {}. If the host has a strict firewall enabled, allow TCP port {} / UDP port {}.",
        addr.ip(),
        addr.port(),
        DEFAULT_UDP_PORT
    )))
}

/// Connects to a host, establishes encrypted TLS session, and authenticates with the LAN secret.
/// Automatically falls back to Reverse TCP over UDP `:22223` if the host's firewall blocks inbound TCP `:22222`.
pub async fn connect_to_host(
    ip: &str,
    port: u16,
    password: &str,
) -> Result<(ClientTlsStream, HandshakeResponse), String> {
    connect_to_host_step(ip, port, password, ReconnectPolicy::default())
        .await
        .map_err(TransferError::into_message)
}

/// Detailed failure information from requesting a remote directory listing.
#[derive(Debug, Clone)]
pub struct DirectoryListingError {
    pub message: String,
    pub connection_lost: bool,
}

/// Queries the remote server for file/folder listing of a relative subpath,
/// enforcing a timeout and distinguishing transport/connection failures from server errors.
/// Returns `(entries, optional_notice)`.
pub async fn request_directory_listing_with_notice_checked(
    stream: &mut ClientTlsStream,
    subpath: &str,
) -> Result<(Vec<FileEntry>, Option<String>), DirectoryListingError> {
    const LISTING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let cmd = ClientCommand::ListDirectory {
        subpath: subpath.to_string(),
    };
    let cmd_bytes = serde_json::to_vec(&cmd).map_err(|e| DirectoryListingError {
        message: e.to_string(),
        connection_lost: false,
    })?;

    match tokio::time::timeout(LISTING_TIMEOUT, write_frame(stream, &cmd_bytes)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return Err(DirectoryListingError {
                message: format!("Host is no longer available ({})", e),
                connection_lost: true,
            });
        }
        Err(_) => {
            return Err(DirectoryListingError {
                message: "Host is not responding (connection timed out)".to_string(),
                connection_lost: true,
            });
        }
    }

    let resp_bytes = match tokio::time::timeout(LISTING_TIMEOUT, read_frame(stream)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => {
            return Err(DirectoryListingError {
                message: format!("Host is no longer available ({})", e),
                connection_lost: true,
            });
        }
        Err(_) => {
            return Err(DirectoryListingError {
                message: "Host is not responding (connection timed out)".to_string(),
                connection_lost: true,
            });
        }
    };

    let resp: ServerCommandResponse =
        serde_json::from_slice(&resp_bytes).map_err(|e| DirectoryListingError {
            message: format!("Invalid response from host ({})", e),
            connection_lost: true,
        })?;

    match resp {
        ServerCommandResponse::DirectoryListing {
            entries, notice, ..
        } => Ok((entries, notice)),
        ServerCommandResponse::Error { message } => Err(DirectoryListingError {
            message,
            connection_lost: false,
        }),
        _ => Err(DirectoryListingError {
            message: "Unexpected server response".to_string(),
            connection_lost: false,
        }),
    }
}

/// Queries the remote server for file/folder listing of a relative subpath,
/// enforcing a timeout and distinguishing transport/connection failures from server errors.
pub async fn request_directory_listing_checked(
    stream: &mut ClientTlsStream,
    subpath: &str,
) -> Result<Vec<FileEntry>, DirectoryListingError> {
    request_directory_listing_with_notice_checked(stream, subpath)
        .await
        .map(|(entries, _)| entries)
}

/// Queries the remote server for file/folder listing of a relative subpath.
pub async fn request_directory_listing(
    stream: &mut ClientTlsStream,
    subpath: &str,
) -> Result<Vec<FileEntry>, String> {
    request_directory_listing_checked(stream, subpath)
        .await
        .map_err(|e| e.message)
}

/// Downloads a single remote file and saves it inside `dest_file_path`.
#[derive(Debug)]
pub struct FolderProgressTracker {
    pub total_bytes: u64,
    pub completed_bytes_before_file: u64,
    pub start_time: Instant,
    pub last_speed_instant: Instant,
    pub last_speed_bytes: u64,
    pub smoothed_speed_mbps: f32,
}

fn sanitize_discovered_host_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "UnknownHost".to_string()
    } else {
        cleaned
    }
}

/// Finds a discovered peer matching `expected_name` on a different LAN IP (for DHCP address changes).
pub fn find_matching_peer_in_list(
    peers: &[DiscoveredPeer],
    expected_name: &str,
    current_ip: &str,
) -> Option<DiscoveredPeer> {
    let trimmed = expected_name.trim();
    if trimmed.is_empty() || trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    peers
        .iter()
        .find(|p| p.host_name.eq_ignore_ascii_case(trimmed) && p.ip != current_ip)
        .cloned()
}

fn find_peer_in_discovery_beacons(
    expected_name: &str,
    current_ip: &str,
    secret: &str,
) -> Option<DiscoveredPeer> {
    let trimmed = expected_name.trim();
    let clean_secret = secret.trim();
    if trimmed.is_empty() || clean_secret.is_empty() || trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    let svc = crate::discovery::service()?;
    let now = Instant::now();
    let since = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
    let mut candidates = Vec::new();
    for b in svc.beacons_since(since) {
        if !is_private_lan_ip(&b.src) {
            continue;
        }
        let Some(payload) = b.beacon.decrypt(clean_secret) else {
            continue;
        };
        candidates.push(DiscoveredPeer {
            host_name: sanitize_discovered_host_name(&payload.host_name),
            ip: b.src.to_string(),
            port: payload.port,
            last_seen: b.received_at,
        });
    }
    find_matching_peer_in_list(&candidates, trimmed, current_ip)
}

async fn find_reassigned_peer_by_name(
    expected_name: &str,
    current_ip: &str,
    secret: &str,
    run_active_scan: bool,
) -> Option<DiscoveredPeer> {
    if let Some(peer) = find_peer_in_discovery_beacons(expected_name, current_ip, secret) {
        return Some(peer);
    }
    if run_active_scan {
        let scanned = scan_lan_for_hosts(Duration::from_millis(1200), Some(secret)).await;
        return find_matching_peer_in_list(&scanned, expected_name, current_ip);
    }
    None
}

fn format_retry_delay(d: Duration) -> String {
    if d.as_secs() >= 1 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis().max(1))
    }
}

async fn wait_for_retry_or_cancel(
    delay: Duration,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    if *cancel_rx.borrow() {
        return Err("Transfer cancelled by user.".to_string());
    }
    tokio::select! {
        _ = tokio::time::sleep(delay) => {
            if *cancel_rx.borrow() {
                Err("Transfer cancelled by user.".to_string())
            } else {
                Ok(())
            }
        }
        _ = cancel_rx.changed() => Err("Transfer cancelled by user.".to_string()),
    }
}

async fn write_frame_with_cancel_timeout(
    stream: &mut ClientTlsStream,
    data: &[u8],
    io_timeout: Duration,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), TransferError> {
    if *cancel_rx.borrow() {
        let _ = stream.shutdown().await;
        return Err(TransferError::Fatal(
            "Transfer cancelled by user.".to_string(),
        ));
    }
    tokio::select! {
        _ = cancel_rx.changed() => {
            let _ = stream.shutdown().await;
            Err(TransferError::Fatal("Transfer cancelled by user.".to_string()))
        }
        res = tokio::time::timeout(io_timeout, write_frame(stream, data)) => match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(TransferError::Recoverable(format!("Network write error: {}", e))),
            Err(_) => Err(TransferError::Recoverable("Network write timed out.".to_string())),
        }
    }
}

async fn read_frame_with_cancel_timeout(
    stream: &mut ClientTlsStream,
    io_timeout: Duration,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<Vec<u8>, TransferError> {
    if *cancel_rx.borrow() {
        let _ = stream.shutdown().await;
        return Err(TransferError::Fatal(
            "Transfer cancelled by user.".to_string(),
        ));
    }
    tokio::select! {
        _ = cancel_rx.changed() => {
            let _ = stream.shutdown().await;
            Err(TransferError::Fatal("Transfer cancelled by user.".to_string()))
        }
        res = tokio::time::timeout(io_timeout, read_frame(stream)) => match res {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(e)) => Err(TransferError::Recoverable(format!("Network read error: {}", e))),
            Err(_) => Err(TransferError::Recoverable("Network read timed out.".to_string())),
        }
    }
}

/// Progress snapshot parameters displayed while waiting for the network/host to return.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectProgressContext<'a> {
    pub selected_target: &'a str,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub file_index: usize,
    pub total_files: usize,
    pub after_drop: bool,
}

/// Connects (or reconnects) to `ctx`, waiting patiently across temporary network/host outages
/// according to `policy`, and checking LAN discovery for DHCP IP changes if `ctx.peer_name` is set.
pub async fn connect_with_wait(
    ctx: &mut ConnectionContext,
    policy: ReconnectPolicy,
    progress_tx: Option<&UnboundedSender<TransferProgress>>,
    status: ReconnectProgressContext<'_>,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(ClientTlsStream, HandshakeResponse), String> {
    let mut attempt: u32 = 0;

    loop {
        if *cancel_rx.borrow() {
            return Err("Transfer cancelled by user.".to_string());
        }

        let conn_res = tokio::select! {
            _ = cancel_rx.changed() => {
                return Err("Transfer cancelled by user.".to_string());
            }
            res = connect_to_host_step(&ctx.ip, ctx.port, &ctx.password, policy) => res,
        };

        match conn_res {
            Ok((stream, resp)) => {
                if ctx.peer_name.is_none()
                    && !resp.server_name.trim().is_empty()
                    && resp.server_name.trim().parse::<IpAddr>().is_err()
                {
                    ctx.peer_name = Some(resp.server_name.clone());
                }
                return Ok((stream, resp));
            }
            Err(TransferError::Fatal(msg)) => return Err(msg),
            Err(TransferError::Recoverable(reason)) => {
                if let Some(max) = policy.max_attempts {
                    if attempt >= max {
                        return Err(reason);
                    }
                }

                // Periodically check LAN discovery if the peer may have acquired a new DHCP IP
                if attempt > 0 && attempt % 3 == 2 {
                    if let Some(expected_name) = ctx.peer_name.clone() {
                        if let Some(candidate) = find_reassigned_peer_by_name(
                            &expected_name,
                            &ctx.ip,
                            &ctx.password,
                            true,
                        )
                        .await
                        {
                            let probe_res = tokio::select! {
                                _ = cancel_rx.changed() => {
                                    return Err("Transfer cancelled by user.".to_string());
                                }
                                res = connect_to_host_step(&candidate.ip, candidate.port, &ctx.password, policy) => res,
                            };
                            match probe_res {
                                Ok((stream, resp))
                                    if resp.server_name.eq_ignore_ascii_case(&expected_name) =>
                                {
                                    ctx.ip = candidate.ip.clone();
                                    ctx.port = candidate.port;
                                    if let Some(tx) = progress_tx {
                                        let _ = tx.send(TransferProgress {
                                            selected_target: status.selected_target.to_string(),
                                            file_name: format!(
                                                "Reconnected to '{}' at new IP {}",
                                                expected_name, ctx.ip
                                            ),
                                            bytes_done: status.bytes_done,
                                            bytes_total: status.bytes_total,
                                            speed_mbps: 0.0,
                                            is_finished: false,
                                            current_file: status.file_index,
                                            total_files: status.total_files,
                                            log_message: Some(format!(
                                                "Host '{}' moved to new LAN IP {}:{} (DHCP); resuming transfer.",
                                                expected_name, ctx.ip, ctx.port
                                            )),
                                        });
                                    }
                                    return Ok((stream, resp));
                                }
                                Err(TransferError::Fatal(msg)) => return Err(msg),
                                _ => {}
                            }
                        }
                    }
                }

                attempt = attempt.saturating_add(1);
                let shift = attempt.saturating_sub(1).min(5);
                let base_ms = policy.initial_backoff.as_millis().max(1);
                let delay = Duration::from_millis(
                    (base_ms.saturating_mul(1u128 << shift))
                        .min(policy.max_backoff.as_millis().max(base_ms))
                        as u64,
                );

                if let Some(tx) = progress_tx {
                    let prefix = if status.after_drop {
                        "Network interrupted"
                    } else {
                        "Waiting for network/host"
                    };
                    let log_message = if attempt <= 3 || attempt.is_multiple_of(10) {
                        Some(format!(
                            "{} ({}). Retrying in {} (attempt #{}) — {}",
                            prefix,
                            ctx.ip,
                            format_retry_delay(delay),
                            attempt,
                            reason
                        ))
                    } else {
                        None
                    };
                    let _ = tx.send(TransferProgress {
                        selected_target: status.selected_target.to_string(),
                        file_name: format!(
                            "{} ({}). Reconnecting in {} (attempt #{})...",
                            prefix,
                            ctx.ip,
                            format_retry_delay(delay),
                            attempt
                        ),
                        bytes_done: status.bytes_done,
                        bytes_total: status.bytes_total,
                        speed_mbps: 0.0,
                        is_finished: false,
                        current_file: status.file_index,
                        total_files: status.total_files,
                        log_message,
                    });
                }

                wait_for_retry_or_cancel(delay, cancel_rx).await?;
            }
        }
    }
}

/// Recursively downloads an entire remote folder, resuming any partial files and skipping existing complete files.
pub async fn download_folder_recursively(
    stream: &mut ClientTlsStream,
    conn_ctx: Option<&ConnectionContext>,
    subpath: &str,
    local_dest_root: &Path,
    progress_tx: Option<UnboundedSender<TransferProgress>>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let mut owned_ctx = conn_ctx.cloned();
    download_folder_recursively_with_policy(
        stream,
        owned_ctx.as_mut(),
        ReconnectPolicy::default(),
        subpath,
        local_dest_root,
        progress_tx,
        cancel_rx,
    )
    .await
}

/// Recursively downloads an entire remote folder using a configurable reconnect/timeout policy.
pub async fn download_folder_recursively_with_policy(
    stream: &mut ClientTlsStream,
    mut conn_ctx: Option<&mut ConnectionContext>,
    policy: ReconnectPolicy,
    subpath: &str,
    local_dest_root: &Path,
    progress_tx: Option<UnboundedSender<TransferProgress>>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    if *cancel_rx.borrow() {
        let _ = stream.shutdown().await;
        return Err("Transfer cancelled by user.".to_string());
    }

    let cmd = ClientCommand::GetDirectoryManifest {
        subpath: subpath.to_string(),
    };
    let cmd_bytes = serde_json::to_vec(&cmd).map_err(|e| e.to_string())?;
    let fallback_label = subpath.to_string();
    let mut reconnect_attempt: u32 = 0;

    let (root_name, files) = loop {
        if let Err(err) =
            write_frame_with_cancel_timeout(stream, &cmd_bytes, policy.io_timeout, &mut cancel_rx)
                .await
        {
            match err {
                TransferError::Fatal(msg) => return Err(msg),
                TransferError::Recoverable(reason) => {
                    if let Some(ctx) = conn_ctx.as_deref_mut() {
                        if let Some(max) = policy.max_attempts {
                            if reconnect_attempt >= max {
                                return Err(reason);
                            }
                            reconnect_attempt += 1;
                        }
                        let (new_stream, _) = connect_with_wait(
                            ctx,
                            policy,
                            progress_tx.as_ref(),
                            ReconnectProgressContext {
                                selected_target: &fallback_label,
                                bytes_done: 0,
                                bytes_total: 0,
                                file_index: 0,
                                total_files: 0,
                                after_drop: true,
                            },
                            &mut cancel_rx,
                        )
                        .await?;
                        *stream = new_stream;
                        continue;
                    }
                    return Err(reason);
                }
            }
        }

        let mut all_files = Vec::new();
        let mut final_root_name = String::new();
        let mut chunk_read_failed = None;

        loop {
            let resp_bytes =
                match read_frame_with_cancel_timeout(stream, policy.io_timeout, &mut cancel_rx)
                    .await
                {
                    Ok(b) => b,
                    Err(TransferError::Fatal(msg)) => return Err(msg),
                    Err(TransferError::Recoverable(reason)) => {
                        chunk_read_failed = Some(reason);
                        break;
                    }
                };

            let resp: ServerCommandResponse =
                serde_json::from_slice(&resp_bytes).map_err(|e| e.to_string())?;

            match resp {
                ServerCommandResponse::DirectoryManifest {
                    root_folder_name,
                    mut files,
                    has_more,
                } => {
                    if final_root_name.is_empty() {
                        final_root_name = root_folder_name;
                    }
                    all_files.append(&mut files);
                    if !has_more {
                        break;
                    }
                }
                ServerCommandResponse::Error { message } => return Err(message),
                _ => return Err("Unexpected server response".to_string()),
            }
        }

        if let Some(reason) = chunk_read_failed {
            if let Some(ctx) = conn_ctx.as_deref_mut() {
                if let Some(max) = policy.max_attempts {
                    if reconnect_attempt >= max {
                        return Err(reason);
                    }
                    reconnect_attempt += 1;
                }
                let (new_stream, _) = connect_with_wait(
                    ctx,
                    policy,
                    progress_tx.as_ref(),
                    ReconnectProgressContext {
                        selected_target: &fallback_label,
                        bytes_done: 0,
                        bytes_total: 0,
                        file_index: 0,
                        total_files: 0,
                        after_drop: true,
                    },
                    &mut cancel_rx,
                )
                .await?;
                *stream = new_stream;
                continue;
            }
            return Err(reason);
        }

        break (final_root_name, all_files);
    };

    let folder_total_bytes: u64 = files
        .iter()
        .fold(0u64, |acc, f| acc.saturating_add(f.file_size));
    let target_base_dir = sanitize_client_relative_path(local_dest_root, &root_name)?;
    ensure_safe_client_dir(&target_base_dir)?;
    let folder_label = root_name.clone();

    let total_files = files.len();
    let mut tracker = FolderProgressTracker {
        total_bytes: folder_total_bytes,
        completed_bytes_before_file: 0,
        start_time: Instant::now(),
        last_speed_instant: Instant::now(),
        last_speed_bytes: 0,
        smoothed_speed_mbps: 0.0,
    };

    for (idx, manifest_entry) in files.iter().enumerate() {
        if *cancel_rx.borrow() {
            let _ = stream.shutdown().await;
            return Err("Transfer cancelled by user.".to_string());
        }

        let local_file_path =
            sanitize_client_relative_path(&target_base_dir, &manifest_entry.relative_path)?;
        let remote_file_path = if subpath.is_empty() {
            manifest_entry.relative_path.clone()
        } else {
            format!(
                "{}/{}",
                subpath.trim_matches('/'),
                manifest_entry.relative_path
            )
        };

        download_single_file_with_policy(
            stream,
            conn_ctx.as_deref_mut(),
            policy,
            &folder_label,
            &remote_file_path,
            &local_file_path,
            progress_tx.clone(),
            idx + 1,
            total_files,
            cancel_rx.clone(),
            Some(&mut tracker),
        )
        .await?;

        tracker.completed_bytes_before_file = tracker
            .completed_bytes_before_file
            .saturating_add(manifest_entry.file_size);
    }

    if let Some(ref tx) = progress_tx {
        let final_bytes = if folder_total_bytes > 0 {
            folder_total_bytes
        } else {
            total_files.max(1) as u64
        };
        let _ = tx.send(TransferProgress {
            selected_target: folder_label,
            file_name: format!("Folder '{}' (all files complete)", root_name),
            bytes_done: final_bytes,
            bytes_total: final_bytes,
            speed_mbps: tracker.smoothed_speed_mbps,
            is_finished: true,
            current_file: total_files,
            total_files,
            log_message: Some(format!(
                "Finished downloading folder '{}' ({} files total)",
                root_name, total_files
            )),
        });
    }

    Ok(())
}

/// Supports byte-range resuming if a local file already exists, and automatic
/// reconnection retries if the network stream is temporarily interrupted.
#[allow(clippy::too_many_arguments)]
pub async fn download_single_file(
    stream: &mut ClientTlsStream,
    conn_ctx: Option<&ConnectionContext>,
    selected_target: &str,
    subpath: &str,
    dest_file_path: &Path,
    progress_tx: Option<UnboundedSender<TransferProgress>>,
    file_index: usize,
    total_files: usize,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let mut owned_ctx = conn_ctx.cloned();
    download_single_file_with_policy(
        stream,
        owned_ctx.as_mut(),
        ReconnectPolicy::default(),
        selected_target,
        subpath,
        dest_file_path,
        progress_tx,
        file_index,
        total_files,
        cancel_rx,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn download_single_file_internal(
    stream: &mut ClientTlsStream,
    conn_ctx: Option<&ConnectionContext>,
    selected_target: &str,
    subpath: &str,
    dest_file_path: &Path,
    progress_tx: Option<UnboundedSender<TransferProgress>>,
    file_index: usize,
    total_files: usize,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    folder_tracker: Option<&mut FolderProgressTracker>,
) -> Result<(), String> {
    let mut owned_ctx = conn_ctx.cloned();
    download_single_file_with_policy(
        stream,
        owned_ctx.as_mut(),
        ReconnectPolicy::default(),
        selected_target,
        subpath,
        dest_file_path,
        progress_tx,
        file_index,
        total_files,
        cancel_rx,
        folder_tracker,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn download_single_file_with_policy(
    stream: &mut ClientTlsStream,
    mut conn_ctx: Option<&mut ConnectionContext>,
    policy: ReconnectPolicy,
    selected_target: &str,
    subpath: &str,
    dest_file_path: &Path,
    progress_tx: Option<UnboundedSender<TransferProgress>>,
    file_index: usize,
    total_files: usize,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    mut folder_tracker: Option<&mut FolderProgressTracker>,
) -> Result<(), String> {
    ensure_safe_client_dest_path(dest_file_path)?;

    let mut reconnect_attempts: u32 = 0;

    loop {
        if *cancel_rx.borrow() {
            let _ = stream.shutdown().await;
            return Err("Transfer cancelled by user.".to_string());
        }

        // Verify destination path is not a symlink/reparse point and inspect existing local file size for resume offset
        ensure_safe_client_dest_path(dest_file_path)?;
        let local_len = match std::fs::symlink_metadata(dest_file_path) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    return Err("Security error: Refusing to follow symbolic link or reparse point at destination.".to_string());
                }
                meta.len()
            }
            Err(_) => 0,
        };

        let cmd = ClientCommand::DownloadFile {
            subpath: subpath.to_string(),
            resume_offset: local_len,
        };
        let cmd_bytes = serde_json::to_vec(&cmd).map_err(|e| e.to_string())?;

        if let Err(err) =
            write_frame_with_cancel_timeout(stream, &cmd_bytes, policy.io_timeout, &mut cancel_rx)
                .await
        {
            match err {
                TransferError::Fatal(msg) => return Err(msg),
                TransferError::Recoverable(reason) => {
                    if let Some(ctx) = conn_ctx.as_deref_mut() {
                        if let Some(max) = policy.max_attempts {
                            if reconnect_attempts >= max {
                                return Err(reason);
                            }
                            reconnect_attempts += 1;
                        }
                        let (done_ui, tot_ui) = match folder_tracker {
                            Some(ref tr) if tr.total_bytes > 0 => {
                                (tr.completed_bytes_before_file + local_len, tr.total_bytes)
                            }
                            _ => (local_len, local_len),
                        };
                        let (new_stream, _) = connect_with_wait(
                            ctx,
                            policy,
                            progress_tx.as_ref(),
                            ReconnectProgressContext {
                                selected_target,
                                bytes_done: done_ui,
                                bytes_total: tot_ui,
                                file_index,
                                total_files,
                                after_drop: true,
                            },
                            &mut cancel_rx,
                        )
                        .await?;
                        *stream = new_stream;
                        continue;
                    }
                    return Err(reason);
                }
            }
        }

        let resp_bytes =
            match read_frame_with_cancel_timeout(stream, policy.io_timeout, &mut cancel_rx).await {
                Ok(b) => b,
                Err(TransferError::Fatal(msg)) => return Err(msg),
                Err(TransferError::Recoverable(reason)) => {
                    if let Some(ctx) = conn_ctx.as_deref_mut() {
                        if let Some(max) = policy.max_attempts {
                            if reconnect_attempts >= max {
                                return Err(reason);
                            }
                            reconnect_attempts += 1;
                        }
                        let (done_ui, tot_ui) = match folder_tracker {
                            Some(ref tr) if tr.total_bytes > 0 => {
                                (tr.completed_bytes_before_file + local_len, tr.total_bytes)
                            }
                            _ => (local_len, local_len),
                        };
                        let (new_stream, _) = connect_with_wait(
                            ctx,
                            policy,
                            progress_tx.as_ref(),
                            ReconnectProgressContext {
                                selected_target,
                                bytes_done: done_ui,
                                bytes_total: tot_ui,
                                file_index,
                                total_files,
                                after_drop: true,
                            },
                            &mut cancel_rx,
                        )
                        .await?;
                        *stream = new_stream;
                        continue;
                    }
                    return Err(reason);
                }
            };

        let resp: ServerCommandResponse =
            serde_json::from_slice(&resp_bytes).map_err(|e| e.to_string())?;

        let (file_name, remaining_size, total_size, start_offset, has_digest_trailer) = match resp {
            ServerCommandResponse::DownloadReady {
                file_name,
                remaining_size,
                total_size,
                start_offset,
                has_digest_trailer,
            } => (
                file_name,
                remaining_size,
                total_size,
                start_offset,
                has_digest_trailer,
            ),
            ServerCommandResponse::Error { message } => return Err(message),
            _ => return Err("Unexpected server response".to_string()),
        };

        // File is already fully present on client!
        if remaining_size == 0 {
            if let Some(ref tx) = progress_tx {
                let is_folder_batch = folder_tracker.is_some();
                let (bytes_done, bytes_total, speed) = if let Some(ref tr) = folder_tracker {
                    let done = tr.completed_bytes_before_file.saturating_add(total_size);
                    let tot = if tr.total_bytes > 0 {
                        tr.total_bytes
                    } else {
                        total_files as u64
                    };
                    let d = if tr.total_bytes > 0 {
                        done
                    } else {
                        file_index as u64
                    };
                    (d, tot, tr.smoothed_speed_mbps)
                } else {
                    (total_size, total_size, 0.0)
                };
                if !is_folder_batch || file_index >= total_files {
                    let _ = tx.send(TransferProgress {
                        selected_target: selected_target.to_string(),
                        file_name: format!("{} (already complete)", file_name),
                        bytes_done,
                        bytes_total,
                        speed_mbps: speed,
                        is_finished: file_index >= total_files,
                        current_file: file_index,
                        total_files,
                        log_message: if is_folder_batch {
                            None
                        } else {
                            Some(format!(
                                "Skipped '{}' (already exists on client with full size)",
                                file_name
                            ))
                        },
                    });
                }
            }
            return Ok(());
        }

        // Re-verify destination is not a symlink/reparse point right before opening for writing
        ensure_safe_client_dest_path(dest_file_path)?;

        if start_offset > 0 {
            let local_len = tokio::fs::metadata(dest_file_path)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            if local_len != start_offset {
                return Err(format!(
                    "Resume offset mismatch for '{}': expected {} local bytes, found {}.",
                    file_name, start_offset, local_len
                ));
            }
        }

        // Open local file with symlink protection: truncate if start_offset == 0, append if start_offset > 0
        let std_dest = {
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).write(true);
            if start_offset == 0 {
                opts.truncate(true);
            } else {
                opts.append(true);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc::O_NOFOLLOW);
            }
            opts.open(dest_file_path)
        }
        .map_err(|e| format!("Failed to open destination file: {}", e))?;
        let mut dest_file = tokio::fs::File::from_std(std_dest);

        let mut remaining = remaining_size;
        let mut buffer = vec![0u8; 64 * 1024];
        let mut last_progress_emit = Instant::now();
        let mut last_speed_instant = Instant::now();
        let mut last_speed_bytes = total_size - remaining_size;
        let mut single_file_speed_mbps = 0.0f32;
        let mut stream_interrupted = false;
        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);

        while remaining > 0 {
            if *cancel_rx.borrow() {
                let _ = stream.shutdown().await;
                return Err("Transfer cancelled by user.".to_string());
            }
            let to_read = remaining.min(buffer.len() as u64) as usize;
            let read_res = tokio::select! {
                _ = cancel_rx.changed() => {
                    let _ = stream.shutdown().await;
                    return Err("Transfer cancelled by user.".to_string());
                }
                res = tokio::time::timeout(policy.io_timeout, stream.read(&mut buffer[..to_read])) => res,
            };
            match read_res {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                    stream_interrupted = true;
                    break;
                }
                Ok(Ok(n)) => {
                    hasher.update(&buffer[..n]);
                    dest_file
                        .write_all(&buffer[..n])
                        .await
                        .map_err(|e| format!("Disk write error: {}", e))?;

                    remaining -= n as u64;

                    if let Some(ref tx) = progress_tx {
                        let current_file_done = total_size - remaining;

                        // Recalculate throughput at a slower, stabilized frequency (~1000ms) with smoothing
                        if let Some(ref mut tr) = folder_tracker {
                            let cur_total_done = tr
                                .completed_bytes_before_file
                                .saturating_add(current_file_done);
                            let elapsed = tr.last_speed_instant.elapsed();
                            if elapsed >= Duration::from_millis(1000)
                                || (remaining == 0 && file_index == total_files)
                            {
                                let dt = elapsed.as_secs_f32();
                                let db = cur_total_done.saturating_sub(tr.last_speed_bytes);
                                if dt >= 0.2 {
                                    let inst_spd = (db as f32 / (1024.0 * 1024.0)) / dt;
                                    tr.smoothed_speed_mbps = if tr.smoothed_speed_mbps > 0.0 {
                                        tr.smoothed_speed_mbps * 0.7 + inst_spd * 0.3
                                    } else {
                                        inst_spd
                                    };
                                    tr.last_speed_instant = Instant::now();
                                    tr.last_speed_bytes = cur_total_done;
                                }
                            }
                        } else {
                            let elapsed = last_speed_instant.elapsed();
                            if elapsed >= Duration::from_millis(1000) || remaining == 0 {
                                let dt = elapsed.as_secs_f32();
                                let db = current_file_done.saturating_sub(last_speed_bytes);
                                if dt >= 0.2 {
                                    let inst_spd = (db as f32 / (1024.0 * 1024.0)) / dt;
                                    single_file_speed_mbps = if single_file_speed_mbps > 0.0 {
                                        single_file_speed_mbps * 0.7 + inst_spd * 0.3
                                    } else {
                                        inst_spd
                                    };
                                    last_speed_instant = Instant::now();
                                    last_speed_bytes = current_file_done;
                                }
                            }
                        }

                        // Emit intermediate progress updates every ~250ms; final completion emits after integrity verification.
                        let should_emit = remaining > 0
                            && last_progress_emit.elapsed() >= Duration::from_millis(250);

                        if should_emit {
                            last_progress_emit = Instant::now();
                            let (rep_done, rep_total, rep_speed) =
                                if let Some(ref tr) = folder_tracker {
                                    let done = tr
                                        .completed_bytes_before_file
                                        .saturating_add(current_file_done);
                                    let tot = if tr.total_bytes > 0 {
                                        tr.total_bytes
                                    } else {
                                        total_files as u64
                                    };
                                    let d = if tr.total_bytes > 0 {
                                        done
                                    } else {
                                        file_index as u64
                                    };
                                    (d, tot, tr.smoothed_speed_mbps)
                                } else {
                                    (current_file_done, total_size, single_file_speed_mbps)
                                };

                            let _ = tx.send(TransferProgress {
                                selected_target: selected_target.to_string(),
                                file_name: file_name.clone(),
                                bytes_done: rep_done,
                                bytes_total: rep_total,
                                speed_mbps: rep_speed,
                                is_finished: false,
                                current_file: file_index,
                                total_files,
                                log_message: None,
                            });
                        }
                    }
                }
            }
        }

        let _ = dest_file.flush().await;

        if !stream_interrupted && remaining == 0 && has_digest_trailer {
            let mut trailer = [0u8; 32];
            let trailer_res = tokio::select! {
                _ = cancel_rx.changed() => {
                    let _ = stream.shutdown().await;
                    return Err("Transfer cancelled by user.".to_string());
                }
                res = tokio::time::timeout(policy.io_timeout, stream.read_exact(&mut trailer)) => res,
            };
            match trailer_res {
                Ok(Ok(_)) => {
                    let expected_digest = hasher.finish();
                    if expected_digest.as_ref() != trailer {
                        return Err(format!(
                            "Integrity verification failed for '{}': SHA-256 digest mismatch.",
                            file_name
                        ));
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    stream_interrupted = true;
                }
            }
        }

        if !stream_interrupted && remaining == 0 {
            if let Some(ref tx) = progress_tx {
                let is_folder_batch = folder_tracker.is_some();
                let (rep_done, rep_total, rep_speed) = if let Some(ref tr) = folder_tracker {
                    let done = tr.completed_bytes_before_file.saturating_add(total_size);
                    let tot = if tr.total_bytes > 0 {
                        tr.total_bytes
                    } else {
                        total_files as u64
                    };
                    let d = if tr.total_bytes > 0 {
                        done
                    } else {
                        file_index as u64
                    };
                    (d, tot, tr.smoothed_speed_mbps)
                } else {
                    (total_size, total_size, single_file_speed_mbps)
                };

                let _ = tx.send(TransferProgress {
                    selected_target: selected_target.to_string(),
                    file_name: file_name.clone(),
                    bytes_done: rep_done,
                    bytes_total: rep_total,
                    speed_mbps: rep_speed,
                    is_finished: file_index >= total_files,
                    current_file: file_index,
                    total_files,
                    log_message: if is_folder_batch {
                        None
                    } else {
                        Some(format!(
                            "Downloaded '{}' ({})",
                            file_name,
                            crate::core::format_file_size(total_size)
                        ))
                    },
                });
            }
            return Ok(());
        }

        if stream_interrupted {
            if *cancel_rx.borrow() {
                let _ = stream.shutdown().await;
                return Err("Transfer cancelled by user.".to_string());
            }
            if let Some(ctx) = conn_ctx.as_deref_mut() {
                if let Some(max) = policy.max_attempts {
                    if reconnect_attempts >= max {
                        return Err(
                            "Download stream interrupted. Partial file saved and can be resumed."
                                .to_string(),
                        );
                    }
                    reconnect_attempts += 1;
                }
                let current_done = total_size - remaining;
                let (done_ui, tot_ui) = match folder_tracker {
                    Some(ref tr) if tr.total_bytes > 0 => (
                        tr.completed_bytes_before_file + current_done,
                        tr.total_bytes,
                    ),
                    _ => (current_done, total_size),
                };
                let (new_stream, _) = connect_with_wait(
                    ctx,
                    policy,
                    progress_tx.as_ref(),
                    ReconnectProgressContext {
                        selected_target,
                        bytes_done: done_ui,
                        bytes_total: tot_ui,
                        file_index,
                        total_files,
                        after_drop: true,
                    },
                    &mut cancel_rx,
                )
                .await?;
                *stream = new_stream;
                continue;
            }
            return Err(
                "Download stream interrupted. Partial file saved and can be resumed.".to_string(),
            );
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{
        compute_tls_server_auth_token, generate_ephemeral_tls, make_server_tls_config,
    };
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn test_connect_to_host_rejects_public_ip() {
        let res = connect_to_host("8.8.8.8", DEFAULT_TCP_PORT, "secret-123").await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains("private LAN IP"));
    }

    #[tokio::test]
    async fn test_connect_to_host_rejects_rogue_server_without_valid_token() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (certs, key) = generate_ephemeral_tls().unwrap();
        let server_cfg = Arc::new(make_server_tls_config(certs, key).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(server_cfg);
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let _req_bytes = read_frame(&mut tls).await.unwrap();
            // Rogue server claims authenticated=true without knowing the Share-Ring secret
            let fake_resp = HandshakeResponse {
                authenticated: true,
                server_name: "Rogue-Host".to_string(),
                message: "Welcome!".to_string(),
                server_auth_token: vec![0xAA; 32],
            };
            let _ = write_frame(&mut tls, &serde_json::to_vec(&fake_resp).unwrap()).await;
        });

        let res = connect_to_host("127.0.0.1", addr.port(), "real-secret-42").await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains("Server authentication failed"));
    }

    #[tokio::test]
    async fn test_reverse_tcp_firewall_traversal() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (certs, key) = generate_ephemeral_tls().unwrap();
        let server_cfg = Arc::new(make_server_tls_config(certs, key).unwrap());
        let secret = "firewall-test-secret";

        // Simulate a host whose inbound TCP port is blocked, listening only on UDP for ReverseConnectRequest
        let host_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let host_udp_port = host_udp.local_addr().unwrap().port();
        let sec_owned = secret.to_string();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (len, src) = host_udp.recv_from(&mut buf).await.unwrap();
            let rev: ReverseConnectRequest = serde_json::from_slice(&buf[..len]).unwrap();
            let payload = rev
                .decrypt(&sec_owned)
                .expect("valid V3 ReverseConnectRequest");

            // Host initiates outbound TCP connection back to client's callback port
            let tcp = TcpStream::connect(SocketAddr::new(src.ip(), payload.tcp_port))
                .await
                .unwrap();
            let acceptor = TlsAcceptor::from(server_cfg);
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let req_bytes = read_frame(&mut tls).await.unwrap();
            let req: HandshakeRequest = serde_json::from_slice(&req_bytes).unwrap();
            assert!(crate::network::verify_tls_auth_token(
                tls.get_ref().1,
                &sec_owned,
                &req.auth_token
            ));
            let srv_tok =
                crate::network::compute_tls_server_auth_token(tls.get_ref().1, &sec_owned).unwrap();
            let resp = HandshakeResponse {
                authenticated: true,
                server_name: "Firewalled-Linux-Host".to_string(),
                message: "Connected".to_string(),
                server_auth_token: srv_tok,
            };
            let _ = write_frame(&mut tls, &serde_json::to_vec(&resp).unwrap()).await;
        });

        let res =
            connect_via_reverse_tcp("127.0.0.1".parse().unwrap(), host_udp_port, secret).await;
        assert!(res.is_ok());
        let (_, resp) = res.unwrap();
        assert_eq!(resp.server_name, "Firewalled-Linux-Host");
    }

    #[tokio::test]
    async fn test_download_rejects_corrupted_digest_and_bad_resume_offset() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let test_dir = std::env::temp_dir().join(format!("lanshare_cli_dl_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();
        let dest = test_dir.join("payload.bin");

        let (certs, key) = generate_ephemeral_tls().unwrap();
        let server_cfg = Arc::new(make_server_tls_config(certs, key).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let secret = "test-secret-ring-42";
        let sec_srv = secret.to_string();

        tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(server_cfg);
            // Connection 1: sends corrupted SHA-256 digest trailer
            let (tcp1, _) = listener.accept().await.unwrap();
            let mut tls1 = acceptor.accept(tcp1).await.unwrap();
            let _hs1 = read_frame(&mut tls1).await.unwrap();
            let tok1 = compute_tls_server_auth_token(tls1.get_ref().1, &sec_srv).unwrap();
            let hs_resp1 = HandshakeResponse {
                authenticated: true,
                server_name: "Srv".to_string(),
                message: "ok".to_string(),
                server_auth_token: tok1,
            };
            write_frame(&mut tls1, &serde_json::to_vec(&hs_resp1).unwrap())
                .await
                .unwrap();
            let _req1 = read_frame(&mut tls1).await.unwrap();
            let resp1 = ServerCommandResponse::DownloadReady {
                file_name: "payload.bin".to_string(),
                remaining_size: 16,
                total_size: 16,
                start_offset: 0,
                has_digest_trailer: true,
            };
            write_frame(&mut tls1, &serde_json::to_vec(&resp1).unwrap())
                .await
                .unwrap();
            tls1.write_all(&[0x42u8; 16]).await.unwrap();
            tls1.write_all(&[0x00u8; 32]).await.unwrap();
            let _ = tls1.shutdown().await;

            // Connection 2: sends bogus start_offset = 8 when local file has 16 bytes
            let (tcp2, _) = listener.accept().await.unwrap();
            let mut tls2 = acceptor.accept(tcp2).await.unwrap();
            let _hs2 = read_frame(&mut tls2).await.unwrap();
            let tok2 = compute_tls_server_auth_token(tls2.get_ref().1, &sec_srv).unwrap();
            let hs_resp2 = HandshakeResponse {
                authenticated: true,
                server_name: "Srv".to_string(),
                message: "ok".to_string(),
                server_auth_token: tok2,
            };
            write_frame(&mut tls2, &serde_json::to_vec(&hs_resp2).unwrap())
                .await
                .unwrap();
            let _req2 = read_frame(&mut tls2).await.unwrap();
            let resp2 = ServerCommandResponse::DownloadReady {
                file_name: "payload.bin".to_string(),
                remaining_size: 8,
                total_size: 16,
                start_offset: 8,
                has_digest_trailer: true,
            };
            write_frame(&mut tls2, &serde_json::to_vec(&resp2).unwrap())
                .await
                .unwrap();
        });

        let (mut client_stream, _) = connect_to_host("127.0.0.1", addr.port(), secret)
            .await
            .unwrap();
        let (_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let err = download_single_file_internal(
            &mut client_stream,
            None,
            "t",
            "share/payload.bin",
            &dest,
            None,
            1,
            1,
            cancel_rx.clone(),
            None,
        )
        .await
        .expect_err("corrupted digest trailer must fail");
        assert!(err.contains("SHA-256 digest mismatch"));

        let (mut client_stream2, _) = connect_to_host("127.0.0.1", addr.port(), secret)
            .await
            .unwrap();
        let err2 = download_single_file_internal(
            &mut client_stream2,
            None,
            "t",
            "share/payload.bin",
            &dest,
            None,
            1,
            1,
            cancel_rx,
            None,
        )
        .await
        .expect_err("start_offset mismatch must fail");
        assert!(err2.contains("Resume offset mismatch"));

        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[tokio::test]
    async fn test_indefinite_wait_recovers_after_outage_and_resumes() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let test_dir =
            std::env::temp_dir().join(format!("lanshare_cli_wait_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();
        let dest = test_dir.join("movie.bin");

        // Allocate an unused loopback port, then drop the listener to simulate an initial offline outage
        let temp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = temp_listener.local_addr().unwrap().port();
        drop(temp_listener);

        let (certs, key) = generate_ephemeral_tls().unwrap();
        let server_cfg = Arc::new(make_server_tls_config(certs, key).unwrap());
        let secret = "wait-outage-secret-42";
        let sec_srv = secret.to_string();

        let payload = [vec![0xABu8; 16], vec![0xCDu8; 32]].concat();
        let payload_srv = payload.clone();

        tokio::spawn(async move {
            // Simulate host offline for 60ms before coming online
            tokio::time::sleep(Duration::from_millis(60)).await;
            let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            let acceptor = TlsAcceptor::from(server_cfg);

            // Connection 1: serves first 16 bytes then drops abruptly mid-stream
            let (tcp1, _) = listener.accept().await.unwrap();
            let mut tls1 = acceptor.accept(tcp1).await.unwrap();
            let _hs1 = read_frame(&mut tls1).await.unwrap();
            let tok1 = compute_tls_server_auth_token(tls1.get_ref().1, &sec_srv).unwrap();
            let hs_resp1 = HandshakeResponse {
                authenticated: true,
                server_name: "Media-PC".to_string(),
                message: "ok".to_string(),
                server_auth_token: tok1,
            };
            write_frame(&mut tls1, &serde_json::to_vec(&hs_resp1).unwrap())
                .await
                .unwrap();
            let _req1 = read_frame(&mut tls1).await.unwrap();
            let resp1 = ServerCommandResponse::DownloadReady {
                file_name: "movie.bin".to_string(),
                remaining_size: 48,
                total_size: 48,
                start_offset: 0,
                has_digest_trailer: true,
            };
            write_frame(&mut tls1, &serde_json::to_vec(&resp1).unwrap())
                .await
                .unwrap();
            tls1.write_all(&payload_srv[..16]).await.unwrap();
            tls1.flush().await.unwrap();
            drop(tls1);

            // Brief outage between reconnects
            drop(listener);
            tokio::time::sleep(Duration::from_millis(60)).await;
            let listener2 = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

            // Connection 2: resumes from offset 16 and sends remaining 32 bytes + SHA-256 trailer
            let (tcp2, _) = listener2.accept().await.unwrap();
            let mut tls2 = acceptor.accept(tcp2).await.unwrap();
            let _hs2 = read_frame(&mut tls2).await.unwrap();
            let tok2 = compute_tls_server_auth_token(tls2.get_ref().1, &sec_srv).unwrap();
            let hs_resp2 = HandshakeResponse {
                authenticated: true,
                server_name: "Media-PC".to_string(),
                message: "ok".to_string(),
                server_auth_token: tok2,
            };
            write_frame(&mut tls2, &serde_json::to_vec(&hs_resp2).unwrap())
                .await
                .unwrap();
            let req2_bytes = read_frame(&mut tls2).await.unwrap();
            let req2: ClientCommand = serde_json::from_slice(&req2_bytes).unwrap();
            let resume_off = match req2 {
                ClientCommand::DownloadFile { resume_offset, .. } => resume_offset,
                _ => panic!("expected DownloadFile"),
            };
            assert_eq!(resume_off, 16);

            let rem = &payload_srv[16..];
            let resp2 = ServerCommandResponse::DownloadReady {
                file_name: "movie.bin".to_string(),
                remaining_size: rem.len() as u64,
                total_size: 48,
                start_offset: 16,
                has_digest_trailer: true,
            };
            write_frame(&mut tls2, &serde_json::to_vec(&resp2).unwrap())
                .await
                .unwrap();
            let digest = ring::digest::digest(&ring::digest::SHA256, rem);
            tls2.write_all(rem).await.unwrap();
            tls2.write_all(digest.as_ref()).await.unwrap();
            tls2.flush().await.unwrap();
            let _ = tls2.shutdown().await;
        });

        let policy = ReconnectPolicy {
            tcp_connect_timeout: Duration::from_millis(25),
            reverse_tcp_timeout: Duration::ZERO,
            io_timeout: Duration::from_millis(200),
            initial_backoff: Duration::from_millis(15),
            max_backoff: Duration::from_millis(30),
            max_attempts: None,
        };
        let mut ctx =
            ConnectionContext::new("127.0.0.1", port, secret, Some("Media-PC".to_string()));
        let (prog_tx, mut prog_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

        let (mut stream, resp) = connect_with_wait(
            &mut ctx,
            policy,
            Some(&prog_tx),
            ReconnectProgressContext {
                selected_target: "movie.bin",
                bytes_done: 0,
                bytes_total: 48,
                file_index: 1,
                total_files: 1,
                after_drop: false,
            },
            &mut cancel_rx,
        )
        .await
        .expect("connect_with_wait must succeed once host returns");
        assert_eq!(resp.server_name, "Media-PC");

        download_single_file_with_policy(
            &mut stream,
            Some(&mut ctx),
            policy,
            "movie.bin",
            "share/movie.bin",
            &dest,
            Some(prog_tx),
            1,
            1,
            cancel_rx,
            None,
        )
        .await
        .expect("resumed download must succeed after mid-stream outage");

        let saved = std::fs::read(&dest).unwrap();
        assert_eq!(saved, payload);

        let mut saw_waiting = false;
        while let Ok(p) = prog_rx.try_recv() {
            if p.file_name.contains("Waiting") || p.file_name.contains("interrupted") {
                saw_waiting = true;
            }
        }
        assert!(saw_waiting);

        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[tokio::test]
    async fn test_wait_aborts_on_cancel_and_wrong_secret_fails_fast() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // 1. Offline port with indefinite policy aborts immediately on cancel_tx
        let temp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = temp_listener.local_addr().unwrap().port();
        drop(temp_listener);

        let policy = ReconnectPolicy {
            tcp_connect_timeout: Duration::from_millis(20),
            reverse_tcp_timeout: Duration::ZERO,
            io_timeout: Duration::from_millis(100),
            initial_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(30),
            max_attempts: None,
        };
        let mut ctx = ConnectionContext::new("127.0.0.1", dead_port, "secret-1234", None);
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = cancel_tx.send(true);
        });

        let start = Instant::now();
        let err = connect_with_wait(
            &mut ctx,
            policy,
            None,
            ReconnectProgressContext {
                selected_target: "file.bin",
                bytes_done: 0,
                bytes_total: 100,
                file_index: 1,
                total_files: 1,
                after_drop: false,
            },
            &mut cancel_rx,
        )
        .await
        .expect_err("cancelled wait must return error promptly");
        assert!(err.contains("cancelled"));
        assert!(start.elapsed() < Duration::from_secs(2));

        // 2. Wrong secret / unauthenticated response must fail immediately (not retry forever)
        let (certs, key) = generate_ephemeral_tls().unwrap();
        let server_cfg = Arc::new(make_server_tls_config(certs, key).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let auth_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(server_cfg);
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let _ = read_frame(&mut tls).await.unwrap();
            let resp = HandshakeResponse {
                authenticated: false,
                server_name: "AuthSrv".to_string(),
                message: "Incorrect LAN secret or authentication error.".to_string(),
                server_auth_token: Vec::new(),
            };
            let _ = write_frame(&mut tls, &serde_json::to_vec(&resp).unwrap()).await;
        });

        let mut bad_ctx = ConnectionContext::new("127.0.0.1", auth_port, "wrong-secret", None);
        let (_tx2, mut cancel_rx2) = tokio::sync::watch::channel(false);
        let auth_err = connect_with_wait(
            &mut bad_ctx,
            policy,
            None,
            ReconnectProgressContext {
                selected_target: "file.bin",
                bytes_done: 0,
                bytes_total: 100,
                file_index: 1,
                total_files: 1,
                after_drop: false,
            },
            &mut cancel_rx2,
        )
        .await
        .expect_err("auth error must fail fast");
        assert!(auth_err.contains("Incorrect LAN secret"));
    }

    #[test]
    fn test_find_matching_peer_in_list_handles_dhcp_ip_change() {
        let peers = vec![
            DiscoveredPeer {
                host_name: "Other-PC".to_string(),
                ip: "192.168.1.15".to_string(),
                port: 22222,
                last_seen: Instant::now(),
            },
            DiscoveredPeer {
                host_name: "Studio-PC".to_string(),
                ip: "192.168.1.99".to_string(),
                port: 22222,
                last_seen: Instant::now(),
            },
        ];

        // Finds reassigned IP (case-insensitive hostname match)
        let matched = find_matching_peer_in_list(&peers, "studio-pc", "192.168.1.42")
            .expect("must detect new DHCP IP for same peer");
        assert_eq!(matched.ip, "192.168.1.99");

        // Ignores when IP hasn't changed or when expected_name is an IP literal
        assert!(find_matching_peer_in_list(&peers, "Studio-PC", "192.168.1.99").is_none());
        assert!(find_matching_peer_in_list(&peers, "192.168.1.42", "192.168.1.42").is_none());
        assert!(find_matching_peer_in_list(&peers, "", "192.168.1.42").is_none());
    }

    #[tokio::test]
    async fn test_connect_to_host_routes_reverse_tcp_to_peer_udp_control_port() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (certs, key) = generate_ephemeral_tls().unwrap();
        let server_cfg = Arc::new(make_server_tls_config(certs, key).unwrap());
        let secret = "multi-instance-diff-key";

        // Pick an unbound ephemeral TCP port (simulating an instance blocked by firewall)
        let probe_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blocked_tcp_port = probe_listener.local_addr().unwrap().port();
        drop(probe_listener);

        // Bind a dedicated per-instance UDP control socket (different from 22223)
        let host_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let host_udp_port = host_udp.local_addr().unwrap().port();

        // Send a DiscoveryBeacon from host_udp to the local DiscoveryService so it records host_udp_port
        let svc = crate::discovery::service().expect("discovery service should start");
        let beacon = DiscoveryBeacon::new("SecondInstance".to_string(), blocked_tcp_port, secret);
        let beacon_bytes = serde_json::to_vec(&beacon).unwrap();
        let target_ctrl = SocketAddr::new("127.0.0.1".parse().unwrap(), svc.control_port());
        host_udp.send_to(&beacon_bytes, target_ctrl).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            svc.peer_udp_port_for_secret("127.0.0.1".parse().unwrap(), blocked_tcp_port, secret),
            host_udp_port
        );

        let sec_owned = secret.to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (payload, src) = loop {
                let (len, src) = host_udp.recv_from(&mut buf).await.unwrap();
                if let Ok(rev) = serde_json::from_slice::<ReverseConnectRequest>(&buf[..len]) {
                    if let Some(payload) = rev.decrypt(&sec_owned) {
                        break (payload, src);
                    }
                }
            };

            let tcp = TcpStream::connect(SocketAddr::new(src.ip(), payload.tcp_port))
                .await
                .unwrap();
            let acceptor = TlsAcceptor::from(server_cfg);
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let req_bytes = read_frame(&mut tls).await.unwrap();
            let req: HandshakeRequest = serde_json::from_slice(&req_bytes).unwrap();
            assert!(crate::network::verify_tls_auth_token(
                tls.get_ref().1,
                &sec_owned,
                &req.auth_token
            ));
            let srv_tok =
                crate::network::compute_tls_server_auth_token(tls.get_ref().1, &sec_owned).unwrap();
            let resp = HandshakeResponse {
                authenticated: true,
                server_name: "SecondInstance".to_string(),
                message: "Connected".to_string(),
                server_auth_token: srv_tok,
            };
            let _ = write_frame(&mut tls, &serde_json::to_vec(&resp).unwrap()).await;
        });

        let policy = ReconnectPolicy {
            tcp_connect_timeout: Duration::from_millis(80),
            reverse_tcp_timeout: Duration::from_millis(2000),
            ..Default::default()
        };
        let (_, resp) = connect_to_host_step("127.0.0.1", blocked_tcp_port, secret, policy)
            .await
            .map_err(TransferError::into_message)
            .expect("Reverse TCP must reach per-instance UDP control port");
        assert_eq!(resp.server_name, "SecondInstance");
    }

    #[tokio::test]
    async fn test_direct_ip_without_verified_beacon_skips_reverse_tcp() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let probe_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unadvertised_port = probe_listener.local_addr().unwrap().port();
        drop(probe_listener);

        let policy = ReconnectPolicy {
            tcp_connect_timeout: Duration::from_millis(60),
            reverse_tcp_timeout: Duration::from_millis(1500),
            ..Default::default()
        };
        let start = Instant::now();
        let res = connect_to_host_step(
            "127.0.0.1",
            unadvertised_port,
            "unadvertised-vpn-secret",
            policy,
        )
        .await;
        assert!(res.is_err());
        // Should fail fast right after tcp_connect_timeout without waiting 1500ms for Reverse TCP
        assert!(start.elapsed() < Duration::from_millis(600));
    }
}
