use crate::core::{format_file_size, sort_shared_paths};
use crate::network::{
    compute_tls_server_auth_token, generate_ephemeral_tls, get_computer_name,
    make_server_tls_config, read_frame, verify_tls_auth_token, write_frame, MAX_FRAME_SIZE,
};
use crate::protocol::*;
use crate::security::*;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, Semaphore};
use tokio_rustls::TlsAcceptor;
use walkdir::WalkDir;

pub const MAX_CONCURRENT_CLIENTS: usize = 64;
pub const MAX_DIRECTORY_LISTING_ENTRIES: usize = 100_000;
pub const MANIFEST_BATCH_FILES: usize = 25_000;
pub const MAX_RATE_LIMIT_ENTRIES: usize = 1_024;
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

async fn write_server_response_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &ServerCommandResponse,
) -> std::io::Result<()> {
    let payload = match serde_json::to_vec(resp) {
        Ok(bytes) if bytes.len() <= MAX_FRAME_SIZE => bytes,
        Ok(bytes) => {
            let err_resp = ServerCommandResponse::Error {
                message: format!(
                    "Directory response payload ({} bytes) exceeds 16 MB protocol frame limit.",
                    bytes.len()
                ),
            };
            serde_json::to_vec(&err_resp)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        }
        Err(e) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
    };
    write_frame(writer, &payload).await
}

fn rw_read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn rw_write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

async fn record_failed_attempt(
    failed_attempts: &Mutex<HashMap<IpAddr, (u32, Instant)>>,
    peer_ip: IpAddr,
) {
    let mut map = failed_attempts.lock().await;
    if map.len() >= MAX_RATE_LIMIT_ENTRIES && !map.contains_key(&peer_ip) {
        map.retain(|_, (_, last)| last.elapsed() < Duration::from_secs(300));
    }
    if map.len() < MAX_RATE_LIMIT_ENTRIES || map.contains_key(&peer_ip) {
        let entry = map.entry(peer_ip).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }
}

fn open_file_nofollow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

#[derive(Debug, Clone)]
pub struct ServerLogEvent {
    pub timestamp: String,
    pub message: String,
    pub is_error: bool,
}

#[derive(Debug, Clone)]
pub struct ActiveUploadInfo {
    pub id: u64,
    pub peer: String,
    pub folder_root: PathBuf,
    pub file_name: String,
    pub bytes_sent: u64,
    pub total_size: u64,
    pub speed_mbps: f32,
    pub started_at: Instant,
}

static NEXT_UPLOAD_ID: AtomicU64 = AtomicU64::new(1);

pub struct ServerHandle {
    pub is_running: Arc<AtomicBool>,
    pub local_ip: String,
    pub all_ips: Vec<String>,
    pub port: u16,
    pub password: String,
    pub stop_sender: tokio::sync::oneshot::Sender<()>,
    pub shared_folders: Arc<std::sync::RwLock<Vec<PathBuf>>>,
    pub duration_hours: Option<f32>,
    pub registry: Arc<std::sync::RwLock<SharedFolderRegistry>>,
    pub log_tx: UnboundedSender<ServerLogEvent>,
    pub active_downloads: Arc<AtomicUsize>,
    pub active_folder_downloads: Arc<std::sync::RwLock<HashMap<PathBuf, usize>>>,
    pub active_uploads: Arc<std::sync::RwLock<HashMap<u64, ActiveUploadInfo>>>,
    pub registry_notify_tx: tokio::sync::watch::Sender<u64>,
}

pub struct ActiveDownloadGuard {
    id: u64,
    total: Arc<AtomicUsize>,
    by_folder: Arc<std::sync::RwLock<HashMap<PathBuf, usize>>>,
    uploads: Arc<std::sync::RwLock<HashMap<u64, ActiveUploadInfo>>>,
    root: PathBuf,
}

impl ActiveDownloadGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        total: Arc<AtomicUsize>,
        by_folder: Arc<std::sync::RwLock<HashMap<PathBuf, usize>>>,
        uploads: Arc<std::sync::RwLock<HashMap<u64, ActiveUploadInfo>>>,
        root: PathBuf,
        peer: String,
        file_name: String,
        bytes_sent: u64,
        total_size: u64,
    ) -> Self {
        let id = NEXT_UPLOAD_ID.fetch_add(1, Ordering::Relaxed);
        total.fetch_add(1, Ordering::SeqCst);
        {
            let mut map = rw_write(&by_folder);
            *map.entry(root.clone()).or_insert(0) += 1;
        }
        {
            let mut map = rw_write(&uploads);
            map.insert(
                id,
                ActiveUploadInfo {
                    id,
                    peer,
                    folder_root: root.clone(),
                    file_name,
                    bytes_sent,
                    total_size,
                    speed_mbps: 0.0,
                    started_at: Instant::now(),
                },
            );
        }
        Self {
            id,
            total,
            by_folder,
            uploads,
            root,
        }
    }

    pub fn update_progress(&self, bytes_sent: u64, speed_mbps: f32) {
        let mut map = rw_write(&self.uploads);
        if let Some(info) = map.get_mut(&self.id) {
            info.bytes_sent = bytes_sent;
            info.speed_mbps = speed_mbps;
        }
    }
}

impl Drop for ActiveDownloadGuard {
    fn drop(&mut self) {
        self.total.fetch_sub(1, Ordering::SeqCst);
        {
            let mut map = rw_write(&self.by_folder);
            if let Some(count) = map.get_mut(&self.root) {
                if *count <= 1 {
                    map.remove(&self.root);
                } else {
                    *count -= 1;
                }
            }
        }
        let mut uploads = rw_write(&self.uploads);
        uploads.remove(&self.id);
    }
}

impl ServerHandle {
    /// Dynamically updates the shared folders and files while the server is running without restarting or disconnecting peers.
    pub fn update_shared_folders(&self, new_paths: Vec<PathBuf>) -> Result<(), String> {
        let mut validated = Vec::new();
        for p in &new_paths {
            let safe = validate_shared_path(p)?;
            if !validated.contains(&safe) {
                validated.push(safe);
            }
        }
        sort_shared_paths(&mut validated);
        if validated.is_empty() {
            return Err(
                "Cannot remove all shares while sharing is active. Stop sharing instead."
                    .to_string(),
            );
        }

        let new_registry = SharedFolderRegistry::new(validated.clone());
        *rw_write(&self.registry) = new_registry;
        *rw_write(&self.shared_folders) = validated.clone();
        let next_ver = self.registry_notify_tx.borrow().wrapping_add(1);
        let _ = self.registry_notify_tx.send(next_ver);

        let ts = crate::core::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = self.log_tx.send(ServerLogEvent {
            timestamp: ts,
            message: format!("Shares updated: {} item(s) active on LAN.", validated.len()),
            is_error: false,
        });

        Ok(())
    }

    pub fn current_shared_folders(&self) -> Vec<PathBuf> {
        rw_read(&self.shared_folders).clone()
    }

    /// Returns the number of active peer file transfers currently reading from `folder`.
    pub fn active_downloads_for_folder(&self, folder: &std::path::Path) -> usize {
        let key = crate::security::clean_path(
            &folder
                .canonicalize()
                .unwrap_or_else(|_| folder.to_path_buf()),
        );
        let map = rw_read(&self.active_folder_downloads);
        if let Some(&count) = map.get(&key) {
            return count;
        }
        map.get(folder).copied().unwrap_or(0)
    }

    /// Returns a snapshot of currently active peer uploads sorted by start order.
    pub fn active_uploads_snapshot(&self) -> Vec<ActiveUploadInfo> {
        let map = rw_read(&self.active_uploads);
        let mut list: Vec<ActiveUploadInfo> = map.values().cloned().collect();
        list.sort_by_key(|u| u.id);
        list
    }
}

#[derive(Debug, Clone)]
pub struct SharedFolderRegistry {
    pub folders: Vec<(String, PathBuf)>,
}

impl SharedFolderRegistry {
    pub fn new(mut paths: Vec<PathBuf>) -> Self {
        sort_shared_paths(&mut paths);
        let mut folders = Vec::new();
        let mut name_counts: HashMap<String, usize> = HashMap::new();

        for path in paths {
            let base_name = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "Share".to_string());

            let count = name_counts.entry(base_name.clone()).or_insert(0);
            *count += 1;
            let alias = if *count == 1 {
                base_name
            } else {
                format!("{} ({})", base_name, count)
            };
            folders.push((alias, path));
        }

        Self { folders }
    }

    pub fn resolve_path(&self, subpath: &str) -> Result<PathBuf, String> {
        self.resolve_path_with_root(subpath).map(|(p, _)| p)
    }

    /// Resolves `subpath` and returns `(resolved_target_path, shared_folder_root)`.
    pub fn resolve_path_with_root(&self, subpath: &str) -> Result<(PathBuf, PathBuf), String> {
        let clean_subpath = subpath.trim_matches('/').replace('\\', "/");

        if clean_subpath.is_empty() {
            return Err("Cannot access share root as a single file".to_string());
        }

        let mut parts = clean_subpath.splitn(2, '/');
        let alias = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("");

        for (folder_alias, folder_path) in &self.folders {
            if folder_alias == alias {
                let resolved = resolve_safe_path(folder_path, rest)?;
                return Ok((resolved, folder_path.clone()));
            }
        }

        // Backward compatibility fallback: if subpath doesn't start with alias and there's 1 shared folder
        if self.folders.len() == 1 {
            let (_, folder_path) = &self.folders[0];
            if folder_path.is_dir() {
                if let Ok(safe) = resolve_safe_path(folder_path, &clean_subpath) {
                    return Ok((safe, folder_path.clone()));
                }
            }
        }

        Err(format!("Shared folder '{}' not found", alias))
    }

    pub fn contains_root(&self, root: &std::path::Path) -> bool {
        self.folders
            .iter()
            .any(|(_, folder_path)| folder_path == root)
    }
}

pub async fn start_server(
    shared_folders: Vec<PathBuf>,
    password: String,
    duration_hours: Option<f32>,
    log_tx: UnboundedSender<ServerLogEvent>,
) -> Result<ServerHandle, Box<dyn std::error::Error + Send + Sync>> {
    if shared_folders.is_empty() {
        return Err("No folders or files specified to share.".into());
    }
    if password.trim().len() < MIN_SECRET_LEN {
        return Err(format!("LAN secret must be at least {} characters.", MIN_SECRET_LEN).into());
    }

    // Re-validate all shared folders and files before starting server
    let mut validated_folders = Vec::with_capacity(shared_folders.len());
    for folder in &shared_folders {
        let safe = validate_shared_path(folder)?;
        if !validated_folders.contains(&safe) {
            validated_folders.push(safe);
        }
    }
    sort_shared_paths(&mut validated_folders);

    let validated_folders_arc = Arc::new(std::sync::RwLock::new(validated_folders.clone()));
    let registry = Arc::new(std::sync::RwLock::new(SharedFolderRegistry::new(
        validated_folders,
    )));

    // Ephemeral TLS setup
    let (certs, key) = generate_ephemeral_tls()?;
    let tls_config = make_server_tls_config(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Bind TCP port 22222 by default, or automatically fall back to a free OS-assigned port if 22222 is in use
    let tcp_listener = match TcpListener::bind(format!("0.0.0.0:{}", DEFAULT_TCP_PORT)).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind("0.0.0.0:0").await?,
    };
    let all_ips = crate::network::get_all_local_lan_ips();
    let local_ip = all_ips
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = tcp_listener.local_addr()?.port();

    let is_running = Arc::new(AtomicBool::new(true));
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

    let password_arc = Arc::new(password.clone());
    let is_running_clone = is_running.clone();

    // Concurrency limiter (max 64 simultaneous client connections)
    let conn_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));

    // Shutdown broadcast to instantly terminate all active client tasks
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (registry_notify_tx, registry_notify_rx) = tokio::sync::watch::channel(0u64);

    // Brute-force failure tracking: IP -> (failure_count, last_failure_instant)
    let failed_attempts = Arc::new(Mutex::new(HashMap::<IpAddr, (u32, Instant)>::new()));

    let active_downloads = Arc::new(AtomicUsize::new(0));
    let active_folder_downloads =
        Arc::new(std::sync::RwLock::new(HashMap::<PathBuf, usize>::new()));
    let active_uploads = Arc::new(std::sync::RwLock::new(
        HashMap::<u64, ActiveUploadInfo>::new(),
    ));

    // Spawn multi-adapter UDP Discovery Beacon + Active Probe / Reverse-TCP Control task
    let (control_tx, mut control_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::discovery::ControlPacket>();
    let host_name = get_computer_name();
    let reg_id = crate::discovery::service()
        .map(|svc| svc.register_server(control_tx, host_name.clone(), port));

    let beacon_running = is_running.clone();
    let beacon_secret = password.clone();
    let udp_acceptor = acceptor.clone();
    let udp_registry = registry.clone();
    let udp_pwd = password_arc.clone();
    let udp_log_tx = log_tx.clone();
    let udp_limiter = conn_limiter.clone();
    let udp_failed = failed_attempts.clone();
    let udp_shutdown_rx = shutdown_rx.clone();
    let udp_registry_rx = registry_notify_rx.clone();
    let udp_active_downloads = active_downloads.clone();
    let udp_active_folder_downloads = active_folder_downloads.clone();
    let udp_active_uploads = active_uploads.clone();

    tokio::spawn(async move {
        let mut seen_rev_nonces: VecDeque<[u8; 12]> = VecDeque::with_capacity(32);
        let mut next_broadcast = Instant::now();

        while beacon_running.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now >= next_broadcast {
                let beacon = DiscoveryBeacon::new(host_name.clone(), port, &beacon_secret);
                if let Ok(beacon_bytes) = serde_json::to_vec(&beacon) {
                    if let Some(svc) = crate::discovery::service() {
                        let mut targets = std::collections::HashSet::new();
                        for binding in crate::network::get_broadcast_bindings(DEFAULT_UDP_PORT) {
                            for target in binding.targets {
                                targets.insert(target);
                            }
                        }
                        for peer_ip in svc.recent_peer_ips(Duration::from_secs(60)) {
                            targets.insert(SocketAddr::new(peer_ip, DEFAULT_UDP_PORT));
                        }
                        for peer_addr in svc.recent_peer_addrs(Duration::from_secs(60)) {
                            targets.insert(peer_addr);
                        }
                        for target in targets {
                            svc.send_from_control(&beacon_bytes, target);
                        }
                    }
                }
                let jitter_bytes: [u8; 2] = crate::network::random_bytes();
                let jitter_ms = (u16::from_le_bytes(jitter_bytes) % 3001) as u64;
                next_broadcast = Instant::now() + Duration::from_millis(12_000 + jitter_ms);
            }

            let wait_dur = next_broadcast
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(20));

            tokio::select! {
                _ = tokio::time::sleep(wait_dur) => {}
                pkt_opt = control_rx.recv() => {
                    let Some(pkt) = pkt_opt else { break; };
                    match pkt {
                        crate::discovery::ControlPacket::Probe(probe, src) => {
                            if probe.verify(&beacon_secret) {
                                let reply = DiscoveryBeacon::new(
                                    host_name.clone(),
                                    port,
                                    &beacon_secret,
                                );
                                if let Some(svc) = crate::discovery::service() {
                                    svc.record_authenticated_peer_addr(src);
                                    if let Ok(reply_bytes) = serde_json::to_vec(&reply) {
                                        let jitter_byte = crate::network::random_bytes::<1>()[0];
                                        let delay_ms = 20 + (u64::from(jitter_byte) % 131);
                                        tokio::spawn(async move {
                                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                            svc.send_from_control(&reply_bytes, src);
                                        });
                                    }
                                }
                            }
                        }
                        crate::discovery::ControlPacket::Reverse(rev_req, src) => {
                            let peer_ip = src.ip();
                            // Rate limit check
                            {
                                let mut map = udp_failed.lock().await;
                                if let Some((count, last)) = map.get(&peer_ip) {
                                    if *count >= 5 && last.elapsed() < Duration::from_secs(300) {
                                        continue;
                                    } else if last.elapsed() >= Duration::from_secs(300) {
                                        map.remove(&peer_ip);
                                    }
                                }
                            }

                            let Some(rev_payload) = rev_req.decrypt(&beacon_secret) else {
                                record_failed_attempt(&udp_failed, peer_ip).await;
                                continue;
                            };

                            if let Some(svc) = crate::discovery::service() {
                                svc.record_authenticated_peer_addr(src);
                            }

                            // Deduplicate retries of the same ReverseConnectRequest nonce
                            if seen_rev_nonces.contains(&rev_req.nonce) {
                                continue;
                            }
                            if seen_rev_nonces.len() >= 32 {
                                seen_rev_nonces.pop_front();
                            }
                            seen_rev_nonces.push_back(rev_req.nonce);

                            let Ok(permit) = udp_limiter.clone().try_acquire_owned() else {
                                continue;
                            };

                            let target_addr = SocketAddr::new(peer_ip, rev_payload.tcp_port);
                            let acc = udp_acceptor.clone();
                            let reg = udp_registry.clone();
                            let pwd = udp_pwd.clone();
                            let l_tx = udp_log_tx.clone();
                            let fails = udp_failed.clone();
                            let s_rx = udp_shutdown_rx.clone();
                            let r_rx = udp_registry_rx.clone();
                            let act_dl = udp_active_downloads.clone();
                            let act_folder_dl = udp_active_folder_downloads.clone();
                            let act_uploads = udp_active_uploads.clone();

                            let ts = crate::core::Local::now().format("%Y-%m-%d %H:%M:%S");
                            let _ = l_tx.send(ServerLogEvent {
                                timestamp: ts,
                                message: format!("Reverse TCP requested by {}. Connecting to callback port {}...", peer_ip, rev_payload.tcp_port),
                                is_error: false,
                            });

                            tokio::spawn(async move {
                                match tokio::time::timeout(
                                    Duration::from_secs(4),
                                    TcpStream::connect(target_addr),
                                )
                                .await
                                {
                                    Ok(Ok(stream)) => {
                                        run_client_session(
                                            stream,
                                            target_addr,
                                            acc,
                                            reg,
                                            pwd,
                                            l_tx,
                                            fails,
                                            s_rx,
                                            r_rx,
                                            act_dl,
                                            act_folder_dl,
                                            act_uploads,
                                            permit,
                                        )
                                        .await;
                                    }
                                    Ok(Err(e)) => {
                                        let ts = crate::core::Local::now().format("%Y-%m-%d %H:%M:%S");
                                        let _ = l_tx.send(ServerLogEvent {
                                            timestamp: ts,
                                            message: format!("Reverse TCP callback to {} failed: {}", target_addr, e),
                                            is_error: true,
                                        });
                                    }
                                    Err(_) => {
                                        let ts = crate::core::Local::now().format("%Y-%m-%d %H:%M:%S");
                                        let _ = l_tx.send(ServerLogEvent {
                                            timestamp: ts,
                                            message: format!("Reverse TCP callback to {} timed out", target_addr),
                                            is_error: true,
                                        });
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }

        if let (Some(svc), Some(id)) = (crate::discovery::service(), reg_id) {
            svc.unregister_server(id);
        }
    });

    // TCP Accept Loop with immediate auto-stop timer
    let server_running = is_running.clone();
    let server_log_tx_for_loop = log_tx.clone();
    let display_ip = local_ip.clone();
    let loop_registry = registry.clone();
    let loop_active_downloads = active_downloads.clone();
    let loop_active_folder_downloads = active_folder_downloads.clone();
    let loop_active_uploads = active_uploads.clone();
    let loop_registry_notify_rx = registry_notify_rx.clone();

    tokio::spawn(async move {
        let server_log_sender = server_log_tx_for_loop.clone();
        let server_log = move |msg: String, is_err: bool| {
            let ts = crate::core::Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = server_log_sender.send(ServerLogEvent {
                timestamp: ts,
                message: msg,
                is_error: is_err,
            });
        };

        if let Some(dur) = duration_hours {
            server_log(
                format!(
                    "LAN server started on {} (Auto-stop in {:.1}h)",
                    display_ip, dur
                ),
                false,
            );
        } else {
            server_log(format!("LAN server started on {}", display_ip), false);
        }

        let mut sleep_opt = duration_hours.map(|dh| {
            let timer_seconds = (dh * 3600.0) as u64;
            Box::pin(tokio::time::sleep(Duration::from_secs(timer_seconds)))
        });

        loop {
            tokio::select! {
                _ = &mut stop_rx => {
                    break;
                }
                _ = async {
                    if let Some(ref mut sleep) = sleep_opt {
                        sleep.as_mut().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    server_log("Sharing session time expired. Stopping server...".to_string(), false);
                    break;
                }
                accept_res = tcp_listener.accept() => {
                    if !server_running.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok((stream, peer_addr)) = accept_res {
                        let peer_ip = peer_addr.ip();
                        if !is_private_lan_ip(&peer_ip) {
                            server_log(
                                format!("Rejected connection from non-LAN IP: {}", peer_ip),
                                true,
                            );
                            continue;
                        }

                        // Rate limit check: reject if >= 5 failures within 5 minutes
                        {
                            let mut map = failed_attempts.lock().await;
                            if let Some((count, last)) = map.get(&peer_ip) {
                                if *count >= 5 && last.elapsed() < Duration::from_secs(300) {
                                    server_log(
                                        format!(
                                            "Rejected {}: Too many failed attempts. Temporary cooldown.",
                                            peer_ip
                                        ),
                                        true,
                                    );
                                    continue;
                                } else if last.elapsed() >= Duration::from_secs(300) {
                                    map.remove(&peer_ip);
                                }
                            }
                        }

                        // Connection limiter
                        let permit = match conn_limiter.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                server_log(
                                    format!(
                                        "Rejected {}: Maximum {} concurrent clients reached.",
                                        peer_addr, MAX_CONCURRENT_CLIENTS
                                    ),
                                    true,
                                );
                                continue;
                            }
                        };

                        let acceptor_clone = acceptor.clone();
                        let registry_clone = loop_registry.clone();
                        let pwd_clone = password_arc.clone();
                        let client_log = server_log_tx_for_loop.clone();
                        let failed_attempts_clone = failed_attempts.clone();
                        let client_shutdown_rx = shutdown_rx.clone();
                        let client_registry_rx = loop_registry_notify_rx.clone();
                        let client_active_downloads = loop_active_downloads.clone();
                        let client_active_folder_downloads = loop_active_folder_downloads.clone();
                        let client_active_uploads = loop_active_uploads.clone();

                        tokio::spawn(async move {
                            run_client_session(
                                stream,
                                peer_addr,
                                acceptor_clone,
                                registry_clone,
                                pwd_clone,
                                client_log,
                                failed_attempts_clone,
                                client_shutdown_rx,
                                client_registry_rx,
                                client_active_downloads,
                                client_active_folder_downloads,
                                client_active_uploads,
                                permit,
                            )
                            .await;
                        });
                    }
                }
            }
        }

        // Instantly signal all active client connections to terminate
        let _ = shutdown_tx.send(true);
        server_running.store(false, Ordering::Relaxed);
        server_log("Server stopped.".to_string(), false);
    });

    Ok(ServerHandle {
        is_running: is_running_clone,
        local_ip,
        all_ips,
        port,
        password,
        stop_sender: stop_tx,
        shared_folders: validated_folders_arc,
        duration_hours,
        registry,
        log_tx,
        active_downloads,
        active_folder_downloads,
        active_uploads,
        registry_notify_tx,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_client_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    registry: Arc<std::sync::RwLock<SharedFolderRegistry>>,
    pwd: Arc<String>,
    client_log: UnboundedSender<ServerLogEvent>,
    failed_attempts: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    client_shutdown_rx: tokio::sync::watch::Receiver<bool>,
    client_registry_rx: tokio::sync::watch::Receiver<u64>,
    active_downloads: Arc<AtomicUsize>,
    active_folder_downloads: Arc<std::sync::RwLock<HashMap<PathBuf, usize>>>,
    active_uploads: Arc<std::sync::RwLock<HashMap<u64, ActiveUploadInfo>>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let peer_ip = peer_addr.ip();
    let c_log = move |msg: String, is_err: bool| {
        let ts = crate::core::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = client_log.send(ServerLogEvent {
            timestamp: ts,
            message: msg,
            is_error: is_err,
        });
    };

    // TLS Accept with 10s timeout
    let mut tls_stream =
        match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                c_log(
                    format!("TLS handshake error with {}: {}", peer_addr, e),
                    true,
                );
                return;
            }
            Err(_) => {
                c_log(format!("TLS handshake timed out for {}", peer_addr), true);
                return;
            }
        };

    // 1. Handshake with 10s timeout
    let handshake_data =
        match tokio::time::timeout(Duration::from_secs(10), read_frame(&mut tls_stream)).await {
            Ok(Ok(d)) => d,
            _ => return,
        };

    let req: HandshakeRequest = match serde_json::from_slice(&handshake_data) {
        Ok(r) => r,
        Err(_) => {
            record_failed_attempt(&failed_attempts, peer_ip).await;
            return;
        }
    };

    // Sanitize client_name
    let clean_client_name: String = req
        .client_name
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(64)
        .collect();
    let client_name = if clean_client_name.is_empty() {
        "Peer".to_string()
    } else {
        clean_client_name
    };

    // Constant-time verification of channel-bound auth token
    let auth_valid = verify_tls_auth_token(tls_stream.get_ref().1, &pwd, &req.auth_token);

    if !auth_valid {
        record_failed_attempt(&failed_attempts, peer_ip).await;
        c_log(
            format!("Failed login attempt from {} ({})", peer_addr, client_name),
            true,
        );
        let resp = HandshakeResponse {
            authenticated: false,
            server_name: get_computer_name(),
            message: "Incorrect LAN secret or authentication error.".to_string(),
            server_auth_token: Vec::new(),
        };
        let _ = write_frame(&mut tls_stream, &serde_json::to_vec(&resp).unwrap()).await;
        return;
    }

    // Clear failed attempts on successful login
    {
        let mut map = failed_attempts.lock().await;
        map.remove(&peer_ip);
    }

    let server_auth_token = match compute_tls_server_auth_token(tls_stream.get_ref().1, &pwd) {
        Ok(tok) => tok,
        Err(e) => {
            c_log(
                format!(
                    "Failed to compute server auth token for {}: {}",
                    peer_addr, e
                ),
                true,
            );
            return;
        }
    };

    c_log(
        format!("Peer connected: {} ({})", peer_addr, client_name),
        false,
    );
    let resp = HandshakeResponse {
        authenticated: true,
        server_name: get_computer_name(),
        message: "Connected to LanShare".to_string(),
        server_auth_token,
    };
    if write_frame(&mut tls_stream, &serde_json::to_vec(&resp).unwrap())
        .await
        .is_err()
    {
        return;
    }

    // 2. Command Loop (Strictly Read-Only)
    let peer_label = format!("{} ({})", peer_addr, client_name);
    let _ = handle_client_commands(
        &mut tls_stream,
        &registry,
        peer_addr,
        &peer_label,
        &c_log,
        client_shutdown_rx,
        client_registry_rx,
        &active_downloads,
        &active_folder_downloads,
        &active_uploads,
    )
    .await;

    c_log(format!("Peer disconnected: {}", peer_label), false);
}

#[allow(clippy::too_many_arguments)]
async fn handle_client_commands<S>(
    stream: &mut S,
    registry: &Arc<std::sync::RwLock<SharedFolderRegistry>>,
    peer_addr: SocketAddr,
    peer_label: &str,
    log: &impl Fn(String, bool),
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    mut registry_rx: tokio::sync::watch::Receiver<u64>,
    active_downloads: &Arc<AtomicUsize>,
    active_folder_downloads: &Arc<std::sync::RwLock<HashMap<PathBuf, usize>>>,
    active_uploads: &Arc<std::sync::RwLock<HashMap<u64, ActiveUploadInfo>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut folder_manifest_active = false;
    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        // Enforce 300s idle timeout between commands, or immediate break if server stopped
        let frame = tokio::select! {
            _ = shutdown_rx.changed() => {
                break;
            }
            res = tokio::time::timeout(Duration::from_secs(300), read_frame(stream)) => {
                match res {
                    Ok(Ok(f)) => f,
                    _ => break, // Timeout or client disconnected cleanly
                }
            }
        };

        let cmd: ClientCommand = match serde_json::from_slice(&frame) {
            Ok(c) => c,
            Err(_) => {
                let err_resp = ServerCommandResponse::Error {
                    message: "Invalid command format".to_string(),
                };
                write_frame(stream, &serde_json::to_vec(&err_resp)?).await?;
                continue;
            }
        };

        match cmd {
            ClientCommand::ListDirectory { subpath } => {
                let clean_sub = subpath.trim_matches('/').replace('\\', "/");
                // Always list the shared folders and files at root (folders first, then files)
                let resp = if clean_sub.is_empty() {
                    let mut entries = Vec::new();
                    {
                        let reg = rw_read(registry);
                        for (alias, path) in &reg.folders {
                            let meta = match fs::symlink_metadata(path) {
                                Ok(m) if !is_symlink_or_reparse(&m) => m,
                                _ => continue,
                            };
                            let modified_timestamp = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let is_dir = meta.is_dir();

                            entries.push(FileEntry {
                                name: alias.clone(),
                                is_dir,
                                size: if is_dir { 0 } else { meta.len() },
                                modified_timestamp,
                            });
                        }
                    }
                    entries.sort_by(|a, b| {
                        b.is_dir
                            .cmp(&a.is_dir)
                            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                    });
                    ServerCommandResponse::DirectoryListing {
                        current_path: String::new(),
                        entries,
                        notice: None,
                    }
                } else {
                    let safe_dir_res = {
                        let reg = rw_read(registry);
                        reg.resolve_path(&subpath)
                    };
                    match safe_dir_res {
                        Ok(safe_dir) if !safe_dir.is_dir() => ServerCommandResponse::Error {
                            message: "Selected share is a file, not a directory.".to_string(),
                        },
                        Ok(safe_dir) => {
                            let mut dirs = Vec::new();
                            let mut files = Vec::new();
                            let mut too_many_dirs = false;
                            let mut too_many_files = false;
                            if let Ok(read_dir) = fs::read_dir(&safe_dir) {
                                for entry in read_dir.flatten() {
                                    if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                                        if is_symlink_or_reparse(&meta) {
                                            continue;
                                        }
                                        let is_dir = meta.is_dir();
                                        let modified_timestamp = meta
                                            .modified()
                                            .ok()
                                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                            .map(|d| d.as_secs())
                                            .unwrap_or(0);

                                        if is_dir {
                                            if dirs.len() < MAX_DIRECTORY_LISTING_ENTRIES {
                                                dirs.push(FileEntry {
                                                    name: entry
                                                        .file_name()
                                                        .to_string_lossy()
                                                        .to_string(),
                                                    is_dir: true,
                                                    size: 0,
                                                    modified_timestamp,
                                                });
                                            } else {
                                                too_many_dirs = true;
                                                break;
                                            }
                                        } else if !too_many_files {
                                            if files.len() < MAX_DIRECTORY_LISTING_ENTRIES {
                                                files.push(FileEntry {
                                                    name: entry
                                                        .file_name()
                                                        .to_string_lossy()
                                                        .to_string(),
                                                    is_dir: false,
                                                    size: meta.len(),
                                                    modified_timestamp,
                                                });
                                            } else {
                                                too_many_files = true;
                                                files.clear();
                                            }
                                        }
                                    }
                                }
                            }
                            if too_many_dirs {
                                ServerCommandResponse::Error {
                                    message: format!(
                                        "Too many directories (> {} subdirectories) to display in browser. Go up one level and download the folder directly.",
                                        MAX_DIRECTORY_LISTING_ENTRIES
                                    ),
                                }
                            } else {
                                let mut entries = dirs;
                                if !too_many_files {
                                    entries.extend(files);
                                }
                                entries.sort_by(|a, b| {
                                    b.is_dir.cmp(&a.is_dir).then_with(|| {
                                        a.name.to_lowercase().cmp(&b.name.to_lowercase())
                                    })
                                });

                                let notice = if too_many_files {
                                    Some(format!(
                                        "Too many files in directory (> {} files) — showing subdirectories only. Go up one level to download this folder.",
                                        MAX_DIRECTORY_LISTING_ENTRIES
                                    ))
                                } else {
                                    None
                                };

                                ServerCommandResponse::DirectoryListing {
                                    current_path: subpath,
                                    entries,
                                    notice,
                                }
                            }
                        }
                        Err(e) => ServerCommandResponse::Error { message: e },
                    }
                };
                write_server_response_frame(stream, &resp).await?;
            }
            ClientCommand::GetDirectoryManifest { subpath } => {
                let clean_sub = subpath.trim_matches('/').replace('\\', "/");
                if clean_sub.is_empty() {
                    let folders_snapshot = rw_read(registry).folders.clone();
                    let mut batch = Vec::with_capacity(MANIFEST_BATCH_FILES.min(1024));
                    let mut total_manifest_files = 0usize;

                    for (alias, folder_path) in &folders_snapshot {
                        for entry in WalkDir::new(folder_path)
                            .follow_links(false)
                            .into_iter()
                            .filter_entry(|e| {
                                fs::symlink_metadata(e.path())
                                    .map(|m| !is_symlink_or_reparse(&m))
                                    .unwrap_or(false)
                            })
                            .filter_map(|e| e.ok())
                        {
                            if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                                if is_symlink_or_reparse(&meta) {
                                    continue;
                                }
                                if meta.is_file() {
                                    if let Ok(rel) = entry.path().strip_prefix(folder_path) {
                                        let rel_str = rel.to_string_lossy().replace('\\', "/");
                                        let full_rel = if rel_str.is_empty() {
                                            alias.clone()
                                        } else {
                                            format!("{}/{}", alias, rel_str)
                                        };
                                        batch.push(ManifestFileEntry {
                                            relative_path: full_rel,
                                            file_size: meta.len(),
                                        });
                                        total_manifest_files += 1;
                                        if batch.len() >= MANIFEST_BATCH_FILES {
                                            let chunk_resp =
                                                ServerCommandResponse::DirectoryManifest {
                                                    root_folder_name: "Shared_Folders".to_string(),
                                                    files: std::mem::take(&mut batch),
                                                    has_more: true,
                                                };
                                            write_server_response_frame(stream, &chunk_resp)
                                                .await?;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    folder_manifest_active = true;
                    log(
                        format!(
                            "{} started downloading all shared folders ({} files)",
                            peer_label, total_manifest_files
                        ),
                        false,
                    );

                    let final_resp = ServerCommandResponse::DirectoryManifest {
                        root_folder_name: "Shared_Folders".to_string(),
                        files: batch,
                        has_more: false,
                    };
                    write_server_response_frame(stream, &final_resp).await?;
                } else {
                    let folder_res = {
                        let reg = rw_read(registry);
                        reg.resolve_path(&subpath)
                    };
                    match folder_res {
                        Ok(folder_path) if !folder_path.is_dir() => {
                            let resp = ServerCommandResponse::Error {
                                message: "Selected share is a file; download it directly."
                                    .to_string(),
                            };
                            write_server_response_frame(stream, &resp).await?;
                        }
                        Ok(folder_path) => {
                            let folder_name = folder_path
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_else(|| "folder".to_string());

                            let mut batch = Vec::with_capacity(MANIFEST_BATCH_FILES.min(1024));
                            let mut total_manifest_files = 0usize;
                            let mut total_manifest_bytes = 0u64;
                            for entry in WalkDir::new(&folder_path)
                                .follow_links(false)
                                .into_iter()
                                .filter_entry(|e| {
                                    fs::symlink_metadata(e.path())
                                        .map(|m| !is_symlink_or_reparse(&m))
                                        .unwrap_or(false)
                                })
                                .filter_map(|e| e.ok())
                            {
                                if let Ok(meta) = fs::symlink_metadata(entry.path()) {
                                    if is_symlink_or_reparse(&meta) {
                                        continue;
                                    }
                                    if meta.is_file() {
                                        if let Ok(rel) = entry.path().strip_prefix(&folder_path) {
                                            let sz = meta.len();
                                            total_manifest_bytes =
                                                total_manifest_bytes.saturating_add(sz);
                                            batch.push(ManifestFileEntry {
                                                relative_path: rel
                                                    .to_string_lossy()
                                                    .replace('\\', "/"),
                                                file_size: sz,
                                            });
                                            total_manifest_files += 1;
                                            if batch.len() >= MANIFEST_BATCH_FILES {
                                                let chunk_resp =
                                                    ServerCommandResponse::DirectoryManifest {
                                                        root_folder_name: folder_name.clone(),
                                                        files: std::mem::take(&mut batch),
                                                        has_more: true,
                                                    };
                                                write_server_response_frame(stream, &chunk_resp)
                                                    .await?;
                                            }
                                        }
                                    }
                                }
                            }
                            folder_manifest_active = true;
                            log(
                                format!(
                                    "{} started downloading folder '{}' ({} files, {})",
                                    peer_label,
                                    folder_name,
                                    total_manifest_files,
                                    format_file_size(total_manifest_bytes)
                                ),
                                false,
                            );

                            let final_resp = ServerCommandResponse::DirectoryManifest {
                                root_folder_name: folder_name,
                                files: batch,
                                has_more: false,
                            };
                            write_server_response_frame(stream, &final_resp).await?;
                        }
                        Err(e) => {
                            let resp = ServerCommandResponse::Error { message: e };
                            write_server_response_frame(stream, &resp).await?;
                        }
                    }
                }
            }
            ClientCommand::DownloadFile {
                subpath,
                resume_offset,
            } => {
                let resolved = {
                    let reg = rw_read(registry);
                    reg.resolve_path_with_root(&subpath)
                };
                match resolved {
                    Ok((file_path, shared_root)) => {
                        let meta = match fs::symlink_metadata(&file_path) {
                            Ok(m) => m,
                            Err(e) => {
                                let resp = ServerCommandResponse::Error {
                                    message: e.to_string(),
                                };
                                write_server_response_frame(stream, &resp).await?;
                                continue;
                            }
                        };
                        if is_symlink_or_reparse(&meta) || !meta.is_file() {
                            let resp = ServerCommandResponse::Error {
                                message: "Path is not a safe regular file.".to_string(),
                            };
                            write_server_response_frame(stream, &resp).await?;
                            continue;
                        }

                        let file_name = file_path
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_else(|| "file".to_string());

                        let std_file = match open_file_nofollow(&file_path) {
                            Ok(f) => f,
                            Err(e) => {
                                let resp = ServerCommandResponse::Error {
                                    message: e.to_string(),
                                };
                                write_server_response_frame(stream, &resp).await?;
                                continue;
                            }
                        };
                        let total_size = std_file.metadata().map(|m| m.len()).unwrap_or(meta.len());

                        // Determine start offset (validate against file bounds)
                        let start_offset = if resume_offset <= total_size {
                            resume_offset
                        } else {
                            0 // Invalid offset, restart from 0
                        };
                        let remaining_size = total_size - start_offset;
                        let has_digest_trailer = remaining_size > 0;

                        let resp = ServerCommandResponse::DownloadReady {
                            file_name: file_name.clone(),
                            remaining_size,
                            total_size,
                            start_offset,
                            has_digest_trailer,
                        };
                        write_server_response_frame(stream, &resp).await?;

                        if remaining_size == 0 {
                            continue;
                        }

                        let _download_guard = ActiveDownloadGuard::new(
                            active_downloads.clone(),
                            active_folder_downloads.clone(),
                            active_uploads.clone(),
                            shared_root.clone(),
                            peer_addr.ip().to_string(),
                            file_name.clone(),
                            start_offset,
                            total_size,
                        );

                        if start_offset > 0 {
                            log(
                                format!(
                                    "{} resuming '{}' from {} / {}",
                                    peer_label,
                                    file_name,
                                    format_file_size(start_offset),
                                    format_file_size(total_size)
                                ),
                                false,
                            );
                        } else if !folder_manifest_active {
                            log(
                                format!(
                                    "{} started downloading '{}' ({})",
                                    peer_label,
                                    file_name,
                                    format_file_size(total_size)
                                ),
                                false,
                            );
                        }

                        let mut file = File::from_std(std_file);
                        if start_offset > 0 {
                            file.seek(std::io::SeekFrom::Start(start_offset)).await?;
                        }

                        let mut buffer = vec![0u8; 64 * 1024];
                        let mut remaining = remaining_size;
                        let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
                        let mut last_progress_update = Instant::now();
                        let mut last_sample_time = Instant::now();
                        let mut last_sample_bytes = 0u64;
                        let mut smoothed_speed_mbps = 0.0f32;

                        while remaining > 0 {
                            if *shutdown_rx.borrow() {
                                log(
                                    format!(
                                        "Server stopped: interrupted download stream of '{}' to {}",
                                        file_name, peer_addr
                                    ),
                                    false,
                                );
                                break;
                            }
                            if !rw_read(registry).contains_root(&shared_root) {
                                log(
                                    format!(
                                        "Share removed: aborted download stream of '{}' to {}",
                                        file_name, peer_addr
                                    ),
                                    false,
                                );
                                let _ = stream.shutdown().await;
                                return Ok(());
                            }
                            let to_read = remaining.min(buffer.len() as u64) as usize;
                            let n = file.read(&mut buffer[..to_read]).await?;
                            if n == 0 {
                                log(
                                    format!(
                                        "Warning: '{}' truncated on disk while streaming ({} remaining). Aborting transfer.",
                                        file_name,
                                        format_file_size(remaining)
                                    ),
                                    true,
                                );
                                let _ = stream.shutdown().await;
                                return Ok(());
                            }
                            hasher.update(&buffer[..n]);
                            let mut written = 0;
                            while written < n {
                                tokio::select! {
                                    _ = shutdown_rx.changed() => {
                                        log(format!("Server stopped: aborted download stream of '{}' to {}", file_name, peer_addr), false);
                                        let _ = stream.shutdown().await;
                                        return Ok(());
                                    }
                                    res = registry_rx.changed() => {
                                        if res.is_err() || !rw_read(registry).contains_root(&shared_root) {
                                            log(format!("Share removed: aborted download stream of '{}' to {}", file_name, peer_addr), false);
                                            let _ = stream.shutdown().await;
                                            return Ok(());
                                        }
                                    }
                                    write_res = tokio::time::timeout(STREAM_WRITE_TIMEOUT, stream.write(&buffer[written..n])) => {
                                        match write_res {
                                            Err(_) => {
                                                log(
                                                    format!(
                                                        "{} stalled while downloading '{}' (write timeout)",
                                                        peer_addr, file_name
                                                    ),
                                                    true,
                                                );
                                                let _ = stream.shutdown().await;
                                                return Ok(());
                                            }
                                            Ok(Ok(0)) | Ok(Err(_)) => {
                                                log(
                                                    format!(
                                                        "{} disconnected or cancelled download of '{}' ({} / {} sent)",
                                                        peer_addr,
                                                        file_name,
                                                        format_file_size(total_size - remaining),
                                                        format_file_size(total_size)
                                                    ),
                                                    false,
                                                );
                                                let _ = stream.shutdown().await;
                                                return Ok(());
                                            }
                                            Ok(Ok(w)) => {
                                                written += w;
                                                remaining -= w as u64;
                                                if remaining == 0
                                                    || last_progress_update.elapsed()
                                                        >= Duration::from_millis(100)
                                                {
                                                    let sent_now = total_size - remaining;
                                                    let session_sent =
                                                        sent_now.saturating_sub(start_offset);
                                                    let dt =
                                                        last_sample_time.elapsed().as_secs_f64();
                                                    if dt >= 0.2 {
                                                        let delta_bytes = session_sent
                                                            .saturating_sub(last_sample_bytes);
                                                        let inst_mbps = (delta_bytes as f64
                                                            / (1024.0 * 1024.0 * dt))
                                                            as f32;
                                                        smoothed_speed_mbps =
                                                            if smoothed_speed_mbps <= 0.0 {
                                                                inst_mbps
                                                            } else {
                                                                smoothed_speed_mbps * 0.5
                                                                    + inst_mbps * 0.5
                                                            };
                                                        last_sample_bytes = session_sent;
                                                        last_sample_time = Instant::now();
                                                    } else if smoothed_speed_mbps <= 0.0
                                                        && dt >= 0.05
                                                    {
                                                        smoothed_speed_mbps = (session_sent as f64
                                                            / (1024.0 * 1024.0 * dt))
                                                            as f32;
                                                    }
                                                    _download_guard.update_progress(
                                                        sent_now,
                                                        smoothed_speed_mbps,
                                                    );
                                                    last_progress_update = Instant::now();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if *shutdown_rx.borrow() {
                            let _ = stream.shutdown().await;
                            return Ok(());
                        }
                        if remaining > 0 {
                            log(
                                format!(
                                    "{} download ended prematurely for '{}' ({} / {} sent)",
                                    peer_addr,
                                    file_name,
                                    format_file_size(total_size - remaining),
                                    format_file_size(total_size)
                                ),
                                false,
                            );
                            let _ = stream.shutdown().await;
                            return Ok(());
                        }
                        let digest = hasher.finish();
                        match tokio::time::timeout(
                            STREAM_WRITE_TIMEOUT,
                            stream.write_all(digest.as_ref()),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            _ => {
                                let _ = stream.shutdown().await;
                                return Ok(());
                            }
                        }
                        stream.flush().await?;
                        if !folder_manifest_active {
                            log(
                                format!(
                                    "{} finished downloading '{}' ({})",
                                    peer_label,
                                    file_name,
                                    format_file_size(total_size)
                                ),
                                false,
                            );
                        }
                    }
                    Err(e) => {
                        let resp = ServerCommandResponse::Error { message: e };
                        write_server_response_frame(stream, &resp).await?;
                    }
                }
            }
        }
    }

    let _ = stream.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::clean_path;

    #[test]
    fn test_shared_folder_registry_single_and_multiple() {
        let pid = std::process::id();
        let temp_dir1 = std::env::temp_dir().join(format!("lanshare_test_dir1_{}", pid));
        let temp_dir2 = std::env::temp_dir().join(format!("lanshare_test_dir2_{}", pid));
        let _ = std::fs::create_dir_all(&temp_dir1);
        let _ = std::fs::create_dir_all(&temp_dir2);

        let file1 = temp_dir1.join("hello.txt");
        let _ = std::fs::write(&file1, "world");

        // 1. Single share registry
        let reg_single = SharedFolderRegistry::new(vec![temp_dir1.clone()]);
        assert_eq!(reg_single.folders.len(), 1);
        let alias = &reg_single.folders[0].0;

        // Path resolution with alias/file
        let resolved = reg_single
            .resolve_path(&format!("{}/hello.txt", alias))
            .unwrap();
        assert_eq!(resolved, clean_path(&file1.canonicalize().unwrap()));

        // Path resolution directly on root alias
        let resolved_root = reg_single.resolve_path(alias).unwrap();
        assert_eq!(
            resolved_root,
            clean_path(&temp_dir1.canonicalize().unwrap())
        );

        // 2. Multi-share registry (folders ordered before shared files)
        let reg_multi =
            SharedFolderRegistry::new(vec![file1.clone(), temp_dir1.clone(), temp_dir2.clone()]);
        assert_eq!(reg_multi.folders.len(), 3);
        assert_eq!(reg_multi.folders[2].0, "hello.txt");
        assert_eq!(
            reg_multi.resolve_path("hello.txt").unwrap(),
            clean_path(&file1.canonicalize().unwrap())
        );

        let _ = std::fs::remove_file(file1);
        let _ = std::fs::remove_dir_all(temp_dir1);
        let _ = std::fs::remove_dir_all(temp_dir2);
    }

    #[test]
    fn test_server_active_downloads_guard() {
        let counter = Arc::new(AtomicUsize::new(0));
        let by_folder = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let uploads = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let folder_a = PathBuf::from("/tmp/share_a");
        let folder_b = PathBuf::from("/tmp/share_b");
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        {
            let guard_a = ActiveDownloadGuard::new(
                counter.clone(),
                by_folder.clone(),
                uploads.clone(),
                folder_a.clone(),
                "192.168.1.50".to_string(),
                "movie.mkv".to_string(),
                0,
                1000,
            );
            let _guard_b = ActiveDownloadGuard::new(
                counter.clone(),
                by_folder.clone(),
                uploads.clone(),
                folder_b.clone(),
                "192.168.1.51".to_string(),
                "archive.zip".to_string(),
                0,
                2000,
            );
            guard_a.update_progress(500, 12.5);
            assert_eq!(counter.load(Ordering::SeqCst), 2);
            assert_eq!(uploads.read().unwrap().len(), 2);
            assert_eq!(
                by_folder
                    .read()
                    .unwrap()
                    .get(&folder_a)
                    .copied()
                    .unwrap_or(0),
                1
            );
            assert_eq!(
                by_folder
                    .read()
                    .unwrap()
                    .get(&folder_b)
                    .copied()
                    .unwrap_or(0),
                1
            );
        }

        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(by_folder.read().unwrap().is_empty());
        assert!(uploads.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_removing_share_aborts_matching_download_stream() {
        use tokio::io::AsyncReadExt;

        let base = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target");
        let pid = std::process::id();
        let dir_a = base.join(format!("lanshare_abort_a_{}", pid));
        let dir_b = base.join(format!("lanshare_abort_b_{}", pid));
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::create_dir_all(&dir_a);
        let _ = std::fs::create_dir_all(&dir_b);

        let safe_a = validate_shared_folder(&dir_a).unwrap();
        let safe_b = validate_shared_folder(&dir_b).unwrap();
        let file_a = safe_a.join("big_a.bin");
        let file_b = safe_b.join("small_b.bin");
        std::fs::write(&file_a, vec![b'A'; 4 * 1024 * 1024]).unwrap();
        std::fs::write(&file_b, vec![b'B'; 1024]).unwrap();

        let (stop_tx, _stop_rx) = tokio::sync::oneshot::channel();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let registry = Arc::new(std::sync::RwLock::new(SharedFolderRegistry::new(vec![
            safe_a.clone(),
            safe_b.clone(),
        ])));
        let active_downloads = Arc::new(AtomicUsize::new(0));
        let active_folder_downloads = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let active_uploads = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (registry_notify_tx, registry_notify_rx) = tokio::sync::watch::channel(0u64);

        let handle = ServerHandle {
            is_running: Arc::new(AtomicBool::new(true)),
            local_ip: "127.0.0.1".to_string(),
            all_ips: vec!["127.0.0.1".to_string()],
            port: 22222,
            password: "ring-secret-test".to_string(),
            stop_sender: stop_tx,
            shared_folders: Arc::new(std::sync::RwLock::new(vec![safe_a.clone(), safe_b.clone()])),
            duration_hours: None,
            registry: registry.clone(),
            log_tx,
            active_downloads: active_downloads.clone(),
            active_folder_downloads: active_folder_downloads.clone(),
            active_uploads: active_uploads.clone(),
            registry_notify_tx,
        };

        let peer_addr: SocketAddr = "127.0.0.1:45000".parse().unwrap();

        // Client A downloads big_a.bin from dir_a over a bounded duplex stream
        let (mut server_stream_a, mut client_stream_a) = tokio::io::duplex(16 * 1024);
        let reg_a = registry.clone();
        let s_rx_a = shutdown_rx.clone();
        let r_rx_a = registry_notify_rx.clone();
        let act_a = active_downloads.clone();
        let folder_act_a = active_folder_downloads.clone();
        let uploads_a = active_uploads.clone();
        let srv_a_task = tokio::spawn(async move {
            let noop = |_: String, _: bool| {};
            let _ = handle_client_commands(
                &mut server_stream_a,
                &reg_a,
                peer_addr,
                "127.0.0.1:45000 (TestPeer)",
                &noop,
                s_rx_a,
                r_rx_a,
                &act_a,
                &folder_act_a,
                &uploads_a,
            )
            .await;
        });

        let alias_a = safe_a.file_name().unwrap().to_string_lossy().to_string();
        let alias_b = safe_b.file_name().unwrap().to_string_lossy().to_string();

        let req_a = serde_json::to_vec(&ClientCommand::DownloadFile {
            subpath: format!("{}/big_a.bin", alias_a),
            resume_offset: 0,
        })
        .unwrap();
        write_frame(&mut client_stream_a, &req_a).await.unwrap();
        let resp_a_bytes = read_frame(&mut client_stream_a).await.unwrap();
        let resp_a: ServerCommandResponse = serde_json::from_slice(&resp_a_bytes).unwrap();
        assert!(matches!(
            resp_a,
            ServerCommandResponse::DownloadReady { .. }
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(handle.active_downloads_for_folder(&dir_a), 1);
        assert_eq!(handle.active_downloads_for_folder(&dir_b), 0);
        let uploads_snap = handle.active_uploads_snapshot();
        assert_eq!(uploads_snap.len(), 1);
        assert_eq!(uploads_snap[0].file_name, "big_a.bin");
        assert_eq!(uploads_snap[0].peer, "127.0.0.1");

        // Remove folder A while B stays shared
        handle.update_shared_folders(vec![dir_b.clone()]).unwrap();

        // Client A's stream aborts well before 4MB and closes cleanly
        let mut received_a = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = client_stream_a.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            received_a.extend_from_slice(&buf[..n]);
        }
        srv_a_task.await.unwrap();
        assert!(received_a.len() < 4 * 1024 * 1024);
        assert_eq!(handle.active_downloads_for_folder(&dir_a), 0);

        // Client B downloading from remaining folder B completes normally
        let (mut server_stream_b, mut client_stream_b) = tokio::io::duplex(16 * 1024);
        let reg_b = registry.clone();
        let s_rx_b = shutdown_rx.clone();
        let r_rx_b = registry_notify_rx.clone();
        let act_b = active_downloads.clone();
        let folder_act_b = active_folder_downloads.clone();
        let uploads_b = active_uploads.clone();
        let srv_b_task = tokio::spawn(async move {
            let noop = |_: String, _: bool| {};
            let _ = handle_client_commands(
                &mut server_stream_b,
                &reg_b,
                peer_addr,
                "127.0.0.1:45000 (TestPeer)",
                &noop,
                s_rx_b,
                r_rx_b,
                &act_b,
                &folder_act_b,
                &uploads_b,
            )
            .await;
        });

        let req_b = serde_json::to_vec(&ClientCommand::DownloadFile {
            subpath: format!("{}/small_b.bin", alias_b),
            resume_offset: 0,
        })
        .unwrap();
        write_frame(&mut client_stream_b, &req_b).await.unwrap();
        let resp_b_bytes = read_frame(&mut client_stream_b).await.unwrap();
        let resp_b: ServerCommandResponse = serde_json::from_slice(&resp_b_bytes).unwrap();
        assert!(matches!(
            resp_b,
            ServerCommandResponse::DownloadReady {
                total_size: 1024,
                has_digest_trailer: true,
                ..
            }
        ));
        let mut exact_b = vec![0u8; 1024];
        client_stream_b.read_exact(&mut exact_b).await.unwrap();
        assert!(exact_b.iter().all(|&b| b == b'B'));
        let mut digest_trailer = [0u8; 32];
        client_stream_b
            .read_exact(&mut digest_trailer)
            .await
            .unwrap();
        let expected_digest = ring::digest::digest(&ring::digest::SHA256, &exact_b);
        assert_eq!(&digest_trailer, expected_digest.as_ref());
        drop(client_stream_b);
        srv_b_task.await.unwrap();

        let _ = handle.stop_sender.send(());
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[tokio::test]
    async fn test_start_server_rejects_short_secret() {
        let base = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target");
        let test_dir = base.join(format!("lanshare_short_sec_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&test_dir);
        std::fs::create_dir_all(&test_dir).unwrap();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let err = start_server(
            vec![test_dir.clone()],
            "123456789".to_string(),
            None,
            log_tx,
        )
        .await
        .err()
        .expect("9-char secret must fail")
        .to_string();
        assert!(err.contains("10"));
        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[tokio::test]
    async fn test_write_server_response_frame_converts_oversized_payload_to_error() {
        let (mut server_side, mut client_side) = tokio::io::duplex(256 * 1024);
        let huge_entries: Vec<FileEntry> = (0..MAX_DIRECTORY_LISTING_ENTRIES)
            .map(|i| FileEntry {
                name: format!("{:0>400}_{}", i, "x"),
                is_dir: false,
                size: 10,
                modified_timestamp: 0,
            })
            .collect();
        let oversized_resp = ServerCommandResponse::DirectoryListing {
            current_path: "big".to_string(),
            entries: huge_entries,
            notice: None,
        };

        let send_task = tokio::spawn(async move {
            write_server_response_frame(&mut server_side, &oversized_resp)
                .await
                .unwrap();
        });

        let raw = read_frame(&mut client_side).await.unwrap();
        send_task.await.unwrap();
        let decoded: ServerCommandResponse = serde_json::from_slice(&raw).unwrap();
        match decoded {
            ServerCommandResponse::Error { message } => {
                assert!(message.contains("exceeds 16 MB protocol frame limit"));
            }
            other => panic!("Expected ServerCommandResponse::Error, got {:?}", other),
        }
    }
}
