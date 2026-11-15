use crate::client::{self, ClientTlsStream, ConnectionContext, TransferProgress};
use crate::protocol::{DiscoveredPeer, FileEntry, HandshakeResponse, DEFAULT_TCP_PORT};
use crate::security::{ensure_safe_client_dest_path, sanitize_client_relative_path};
use chrono::{DateTime, Local};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

/// Results posted by background client network and download worker tasks to the UI loop.
pub enum ClientActionResult {
    Connected(ClientTlsStream, HandshakeResponse, String),
    ConnectFailed(String),
    ListingLoaded(ClientTlsStream, String, Vec<FileEntry>),
    ListingFailed(Option<ClientTlsStream>, String),
    QueueItemFinished { id: u64, result: Result<(), String> },
}

/// Outcome summary produced when a queued download finishes or is cancelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueCompletionInfo {
    pub item_name: String,
    pub cancelled: bool,
    pub error: Option<String>,
}

/// Sorts discovered LAN peers in-place case-insensitively by host name.
pub fn sort_peers_alphabetically(peers: &mut [DiscoveredPeer]) {
    peers.sort_by_key(|p| p.host_name.to_lowercase());
}

/// Returns display ordering priority for queue entries (`Downloading` -> `Pending` -> `Failed` -> `Completed` -> `Cancelled`).
pub fn queue_status_sort_rank(status: &QueueItemStatus) -> u8 {
    match status {
        QueueItemStatus::Downloading => 0,
        QueueItemStatus::Pending => 1,
        QueueItemStatus::Failed(_) => 2,
        QueueItemStatus::Completed => 3,
        QueueItemStatus::Cancelled => 4,
    }
}

/// Reports whether a client session currently has an active or pending download.
pub fn has_active_client_downloads(
    active_progress: Option<&TransferProgress>,
    active_queue_id: Option<u64>,
    download_queue: &VecDeque<QueuedDownloadItem>,
) -> bool {
    active_progress.map(|p| !p.is_finished).unwrap_or(false)
        || active_queue_id.is_some()
        || download_queue.iter().any(|i| {
            matches!(
                i.status,
                QueueItemStatus::Downloading | QueueItemStatus::Pending
            )
        })
}

/// Starts the next `Pending` item in `download_queue` when no item is currently active.
pub fn spawn_next_queued_download(
    tokio_rt: &tokio::runtime::Runtime,
    download_queue: &mut VecDeque<QueuedDownloadItem>,
    active_queue_id: &mut Option<u64>,
    transfer_cancel_tx: &mut Option<tokio::sync::watch::Sender<bool>>,
    action_tx: &Sender<ClientActionResult>,
    prog_tx: &tokio::sync::mpsc::UnboundedSender<TransferProgress>,
) {
    if active_queue_id.is_some() {
        return;
    }

    let next_item = download_queue
        .iter_mut()
        .find(|i| i.status == QueueItemStatus::Pending)
        .map(|i| {
            i.status = QueueItemStatus::Downloading;
            i.started_at = Some(Instant::now());
            i.clone()
        });

    let Some(item) = next_item else {
        return;
    };

    *active_queue_id = Some(item.id);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    *transfer_cancel_tx = Some(cancel_tx);

    let tx = action_tx.clone();
    let prog_tx = prog_tx.clone();

    tokio_rt.spawn(async move {
        let item_id = item.id;
        let res = execute_queued_download(item, prog_tx, cancel_rx).await;
        let _ = tx.send(ClientActionResult::QueueItemFinished {
            id: item_id,
            result: res,
        });
    });
}

/// Updates queue bookkeeping when a download worker completes, fails, or is cancelled by the user.
pub fn complete_queued_download(
    download_queue: &mut VecDeque<QueuedDownloadItem>,
    active_queue_id: &mut Option<u64>,
    transfer_cancel_tx: &mut Option<tokio::sync::watch::Sender<bool>>,
    active_progress: Option<&TransferProgress>,
    id: u64,
    result: &Result<(), String>,
) -> QueueCompletionInfo {
    *transfer_cancel_tx = None;
    if *active_queue_id == Some(id) {
        *active_queue_id = None;
    }

    let (cancelled, error) = match result {
        Ok(()) => (false, None),
        Err(e) if e.contains("cancelled") => (true, None),
        Err(e) => (false, Some(e.clone())),
    };

    let mut info = QueueCompletionInfo {
        item_name: String::new(),
        cancelled,
        error,
    };

    if let Some(item) = download_queue.iter_mut().find(|i| i.id == id) {
        if let Some(start) = item.started_at {
            item.elapsed_duration = Some(start.elapsed());
        }
        if item.total_bytes.is_none() {
            if let Some(prog) = active_progress {
                if prog.bytes_total > 0 {
                    item.total_bytes = Some(prog.bytes_total);
                } else if prog.bytes_done > 0 {
                    item.total_bytes = Some(prog.bytes_done);
                }
            }
        }
        info.item_name = item.entry.name.clone();
        match result {
            Ok(()) => {
                item.status = QueueItemStatus::Completed;
                item.completed_at = Some(Local::now());
            }
            Err(e) if e.contains("cancelled") => {
                item.status = QueueItemStatus::Cancelled;
            }
            Err(e) => {
                item.status = QueueItemStatus::Failed(e.clone());
            }
        }
    }

    if info.cancelled {
        download_queue.retain(|i| i.id != id);
    }

    info
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueItemStatus {
    Pending,
    Downloading,
    Completed,
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct QueuedDownloadItem {
    pub id: u64,
    pub peer_name: String,
    pub conn_ctx: ConnectionContext,
    pub is_mock: bool,
    pub entry: FileEntry,
    pub remote_subpath: String,
    pub local_dest_dir: PathBuf,
    pub status: QueueItemStatus,
    pub started_at: Option<Instant>,
    pub elapsed_duration: Option<Duration>,
    pub completed_at: Option<DateTime<Local>>,
    pub total_bytes: Option<u64>,
}

/// Executes a single queued download item (either mock or real TLS session) and reports progress.
pub async fn execute_queued_download(
    item: QueuedDownloadItem,
    prog_tx: tokio::sync::mpsc::UnboundedSender<TransferProgress>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    if item.is_mock {
        simulate_mock_download(
            &item.conn_ctx.ip,
            item.entry,
            item.remote_subpath,
            item.local_dest_dir,
            prog_tx,
            cancel_rx,
        )
        .await
    } else {
        let mut ctx = item.conn_ctx;
        if ctx.peer_name.is_none()
            && !item.peer_name.trim().is_empty()
            && item.peer_name.trim().parse::<std::net::IpAddr>().is_err()
        {
            ctx.peer_name = Some(item.peer_name.clone());
        }
        let target_label = item.entry.name.clone();
        let total_bytes = item.total_bytes.unwrap_or(item.entry.size);
        let policy = client::ReconnectPolicy::default();
        let mut cancel_rx_conn = cancel_rx.clone();

        match client::connect_with_wait(
            &mut ctx,
            policy,
            Some(&prog_tx),
            client::ReconnectProgressContext {
                selected_target: &target_label,
                bytes_done: 0,
                bytes_total: total_bytes,
                file_index: 1,
                total_files: 1,
                after_drop: false,
            },
            &mut cancel_rx_conn,
        )
        .await
        {
            Ok((mut dl_stream, _)) => {
                let dl_res = if item.entry.is_dir {
                    client::download_folder_recursively_with_policy(
                        &mut dl_stream,
                        Some(&mut ctx),
                        policy,
                        &item.remote_subpath,
                        &item.local_dest_dir,
                        Some(prog_tx),
                        cancel_rx,
                    )
                    .await
                } else {
                    match sanitize_client_relative_path(&item.local_dest_dir, &item.entry.name) {
                        Ok(dest_file) => {
                            client::download_single_file_with_policy(
                                &mut dl_stream,
                                Some(&mut ctx),
                                policy,
                                &target_label,
                                &item.remote_subpath,
                                &dest_file,
                                Some(prog_tx),
                                1,
                                1,
                                cancel_rx,
                                None,
                            )
                            .await
                        }
                        Err(e) => Err(format!("Unsafe filename from server: {}", e)),
                    }
                };
                let _ = dl_stream.shutdown().await;
                dl_res
            }
            Err(e) => Err(e),
        }
    }
}

pub fn default_mock_peers() -> Vec<DiscoveredPeer> {
    let mut list = vec![
        DiscoveredPeer {
            host_name: "Mock-Gaming-PC (Test Mode)".to_string(),
            ip: "mock://gaming-pc".to_string(),
            port: DEFAULT_TCP_PORT,
            last_seen: Instant::now(),
        },
        DiscoveredPeer {
            host_name: "Alice-Laptop (Test Mode)".to_string(),
            ip: "mock://alice-laptop".to_string(),
            port: DEFAULT_TCP_PORT,
            last_seen: Instant::now(),
        },
    ];
    sort_peers_alphabetically(&mut list);
    list
}

pub fn mock_directory_entries(mock_ip: &str, subpath: &str) -> Vec<FileEntry> {
    let clean = subpath.trim_matches('/');
    let now_ts = 1_730_000_000u64;

    if mock_ip.contains("alice") {
        return match clean {
            "" => vec![
                FileEntry {
                    name: "Design_Assets".to_string(),
                    is_dir: true,
                    size: 0,
                    modified_timestamp: now_ts - 1200,
                },
                FileEntry {
                    name: "Shared_Notes.md".to_string(),
                    is_dir: false,
                    size: 24_576,
                    modified_timestamp: now_ts - 400,
                },
                FileEntry {
                    name: "Demo_Reel_1080p.mp4".to_string(),
                    is_dir: false,
                    size: 92 * 1024 * 1024,
                    modified_timestamp: now_ts - 800,
                },
            ],
            "Design_Assets" => vec![
                FileEntry {
                    name: "ui_mockups.fig".to_string(),
                    is_dir: false,
                    size: 18 * 1024 * 1024,
                    modified_timestamp: now_ts - 1500,
                },
                FileEntry {
                    name: "icons_pack.zip".to_string(),
                    is_dir: false,
                    size: 6 * 1024 * 1024,
                    modified_timestamp: now_ts - 1400,
                },
            ],
            _ => Vec::new(),
        };
    }

    match clean {
        "" => vec![
            FileEntry {
                name: "Games_Patches".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: now_ts - 3600,
            },
            FileEntry {
                name: "LAN_Party_Photos".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: now_ts - 7200,
            },
            FileEntry {
                name: "Maps_And_Mods".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: now_ts - 10800,
            },
            FileEntry {
                name: "Massive_Assets_25k_Files".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: now_ts - 500,
            },
            FileEntry {
                name: "Huge_Files_Archive".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: now_ts - 300,
            },
            FileEntry {
                name: "HighRes_Wallpaper_Pack.zip".to_string(),
                is_dir: false,
                size: 128 * 1024 * 1024,
                modified_timestamp: now_ts - 1800,
            },
            FileEntry {
                name: "Soundtrack_Mix.flac".to_string(),
                is_dir: false,
                size: 64 * 1024 * 1024,
                modified_timestamp: now_ts - 2400,
            },
            FileEntry {
                name: "Tournament_Brackets.pdf".to_string(),
                is_dir: false,
                size: 4_404_019,
                modified_timestamp: now_ts - 900,
            },
            FileEntry {
                name: "Server_Rules.txt".to_string(),
                is_dir: false,
                size: 12_480,
                modified_timestamp: now_ts - 600,
            },
        ],
        "Games_Patches" => vec![
            FileEntry {
                name: "balance_update.pak".to_string(),
                is_dir: false,
                size: 89_653_248,
                modified_timestamp: now_ts - 4000,
            },
            FileEntry {
                name: "patch_v1.4_hotfix.bin".to_string(),
                is_dir: false,
                size: 47_185_920,
                modified_timestamp: now_ts - 3800,
            },
            FileEntry {
                name: "changelog.txt".to_string(),
                is_dir: false,
                size: 8_192,
                modified_timestamp: now_ts - 3600,
            },
        ],
        "LAN_Party_Photos" => vec![
            FileEntry {
                name: "Day_1".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: now_ts - 8000,
            },
            FileEntry {
                name: "group_banner.png".to_string(),
                is_dir: false,
                size: 10_276_044,
                modified_timestamp: now_ts - 7200,
            },
        ],
        "LAN_Party_Photos/Day_1" => vec![
            FileEntry {
                name: "setup_01.jpg".to_string(),
                is_dir: false,
                size: 6_815_744,
                modified_timestamp: now_ts - 8400,
            },
            FileEntry {
                name: "setup_02.jpg".to_string(),
                is_dir: false,
                size: 7_444_889,
                modified_timestamp: now_ts - 8200,
            },
            FileEntry {
                name: "team_photo.png".to_string(),
                is_dir: false,
                size: 14_889_779,
                modified_timestamp: now_ts - 8000,
            },
        ],
        "Maps_And_Mods" => vec![
            FileEntry {
                name: "custom_arena_v2.map".to_string(),
                is_dir: false,
                size: 33_554_432,
                modified_timestamp: now_ts - 12000,
            },
            FileEntry {
                name: "hd_textures.pak".to_string(),
                is_dir: false,
                size: 157_286_400,
                modified_timestamp: now_ts - 11000,
            },
        ],
        "Massive_Assets_25k_Files" => (1..=25_000)
            .map(|i| FileEntry {
                name: format!("asset_{:05}.bin", i),
                is_dir: false,
                size: 512 + ((i as u64 * 47) % 8192),
                modified_timestamp: now_ts - (i as u64 % 86400),
            })
            .collect(),
        "Huge_Files_Archive" => vec![
            FileEntry {
                name: "Linux_Enterprise_Server.iso".to_string(),
                is_dir: false,
                size: 4_700_000_000,
                modified_timestamp: now_ts - 5000,
            },
            FileEntry {
                name: "Raw_4K_Video_Footage.tar".to_string(),
                is_dir: false,
                size: 14_500_000_000,
                modified_timestamp: now_ts - 4200,
            },
            FileEntry {
                name: "Database_Backup_Full.dump".to_string(),
                is_dir: false,
                size: 42_000_000_000,
                modified_timestamp: now_ts - 2100,
            },
            FileEntry {
                name: "Virtual_Lab_Cluster.vmdk".to_string(),
                is_dir: false,
                size: 85_000_000_000,
                modified_timestamp: now_ts - 1000,
            },
        ],
        _ => Vec::new(),
    }
}

pub fn collect_mock_folder_files(
    mock_ip: &str,
    subpath: &str,
    rel_prefix: &str,
    out: &mut Vec<(String, u64)>,
) {
    for entry in mock_directory_entries(mock_ip, subpath) {
        let child_sub = if subpath.is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", subpath.trim_matches('/'), entry.name)
        };
        let child_rel = if rel_prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", rel_prefix, entry.name)
        };
        if entry.is_dir {
            collect_mock_folder_files(mock_ip, &child_sub, &child_rel, out);
        } else {
            out.push((child_rel, entry.size));
        }
    }
}

/// Returns true when `TransferProgress.file_name` indicates waiting for network or host recovery.
pub fn is_transfer_waiting_status(status: &str) -> bool {
    status.starts_with("Network interrupted") || status.starts_with("Waiting for network/host")
}

/// Simulation timing and dummy outage controls for `--test` client downloads.
#[derive(Clone, Copy, Debug)]
pub struct MockClientDownloadConfig {
    pub step_sleep_ms: u64,
    pub batch_sleep_ms: u64,
    pub simulate_interruptions: bool,
    pub outage_retry_delays: [Duration; 2],
}

impl Default for MockClientDownloadConfig {
    fn default() -> Self {
        Self {
            step_sleep_ms: if cfg!(test) { 1 } else { 65 },
            batch_sleep_ms: 15,
            simulate_interruptions: !cfg!(test),
            outage_retry_delays: [Duration::from_millis(1200), Duration::from_millis(2000)],
        }
    }
}

struct MockOutageParams<'a> {
    mock_ip: &'a str,
    selected_target: &'a str,
    file_name: &'a str,
    bytes_done: u64,
    bytes_total: u64,
    resume_offset_bytes: u64,
    current_file: usize,
    total_files: usize,
}

fn format_mock_delay(d: Duration) -> String {
    if d.as_secs() >= 1 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis().max(1))
    }
}

async fn wait_mock_step_or_cancel(
    delay: Duration,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    if *cancel_rx.borrow() {
        return Err("Transfer cancelled by user.".to_string());
    }
    tokio::select! {
        _ = cancel_rx.changed() => Err("Transfer cancelled by user.".to_string()),
        _ = tokio::time::sleep(delay) => Ok(()),
    }
}

async fn simulate_mock_network_outage(
    params: &MockOutageParams<'_>,
    retry_delays: [Duration; 2],
    prog_tx: &tokio::sync::mpsc::UnboundedSender<TransferProgress>,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<Duration, String> {
    let outage_start = Instant::now();
    let stages = [
        (
            "Network interrupted",
            format!("Connection reset by peer during '{}'", params.file_name),
            retry_delays[0],
        ),
        (
            "Waiting for network/host",
            "Host unreachable".to_string(),
            retry_delays[1],
        ),
    ];

    for (idx, (prefix, reason, delay)) in stages.iter().enumerate() {
        let attempt = idx + 1;
        let delay_label = format_mock_delay(*delay);
        let _ = prog_tx.send(TransferProgress {
            selected_target: params.selected_target.to_string(),
            file_name: format!(
                "{} ({}). Reconnecting in {} (attempt #{})...",
                prefix, params.mock_ip, delay_label, attempt
            ),
            bytes_done: params.bytes_done,
            bytes_total: params.bytes_total,
            speed_mbps: 0.0,
            is_finished: false,
            current_file: params.current_file,
            total_files: params.total_files,
            log_message: Some(format!(
                "[Mock] {} ({}). Retrying in {} (attempt #{}) — {}",
                prefix, params.mock_ip, delay_label, attempt, reason
            )),
        });
        wait_mock_step_or_cancel(*delay, cancel_rx).await?;
    }

    let _ = prog_tx.send(TransferProgress {
        selected_target: params.selected_target.to_string(),
        file_name: params.file_name.to_string(),
        bytes_done: params.bytes_done,
        bytes_total: params.bytes_total,
        speed_mbps: 0.0,
        is_finished: false,
        current_file: params.current_file,
        total_files: params.total_files,
        log_message: Some(format!(
            "[Mock] Reconnected to '{}' — resuming '{}' from {}",
            params.mock_ip,
            params.file_name,
            format_file_size(params.resume_offset_bytes)
        )),
    });

    Ok(outage_start.elapsed())
}

pub async fn simulate_mock_download(
    mock_ip: &str,
    entry: FileEntry,
    subpath: String,
    dest_dir: PathBuf,
    prog_tx: tokio::sync::mpsc::UnboundedSender<TransferProgress>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    simulate_mock_download_with_config(
        mock_ip,
        entry,
        subpath,
        dest_dir,
        prog_tx,
        cancel_rx,
        MockClientDownloadConfig::default(),
    )
    .await
}

/// Runs a simulated `--test` client download using the supplied timing and outage config.
pub async fn simulate_mock_download_with_config(
    mock_ip: &str,
    entry: FileEntry,
    subpath: String,
    dest_dir: PathBuf,
    prog_tx: tokio::sync::mpsc::UnboundedSender<TransferProgress>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    config: MockClientDownloadConfig,
) -> Result<(), String> {
    let selected_target = entry.name.clone();

    let files: Vec<(String, PathBuf, u64)> = if entry.is_dir {
        let base_folder = sanitize_client_relative_path(&dest_dir, &entry.name)?;
        let mut rel_files = Vec::new();
        collect_mock_folder_files(mock_ip, &subpath, "", &mut rel_files);
        let mut list = Vec::new();
        for (rel, sz) in rel_files {
            let local_path = sanitize_client_relative_path(&base_folder, &rel)?;
            list.push((rel, local_path, sz));
        }
        list
    } else {
        let local_path = sanitize_client_relative_path(&dest_dir, &entry.name)?;
        vec![(entry.name.clone(), local_path, entry.size)]
    };

    let total_folder_bytes: u64 = if entry.is_dir {
        files.iter().map(|(_, _, sz)| *sz).sum()
    } else {
        entry.size
    };
    let mut folder_bytes_done = 0u64;

    let total_files = files.len().max(1);
    let mut paused_duration = Duration::ZERO;
    let mut outage_triggered = false;

    if total_files > 500 {
        // High-throughput simulation for massive batch folder transfers (e.g. 25,000 small files)
        let batch_size = 25;
        let start_instant = Instant::now();
        for (idx, (file_name, local_path, total_size)) in files.iter().enumerate() {
            let file_index = idx + 1;
            if *cancel_rx.borrow() {
                return Err("Transfer cancelled by user.".to_string());
            }

            folder_bytes_done += *total_size;

            let is_batch_end = file_index % batch_size == 0 || file_index == total_files;
            if is_batch_end {
                wait_mock_step_or_cancel(
                    Duration::from_millis(config.batch_sleep_ms),
                    &mut cancel_rx,
                )
                .await?;

                let elapsed_secs = start_instant
                    .elapsed()
                    .saturating_sub(paused_duration)
                    .as_secs_f32()
                    .max(0.001);
                let speed_mbps =
                    ((folder_bytes_done as f32 / (1024.0 * 1024.0)) / elapsed_secs).max(0.1);
                let _ = prog_tx.send(TransferProgress {
                    selected_target: selected_target.clone(),
                    file_name: file_name.clone(),
                    bytes_done: folder_bytes_done,
                    bytes_total: total_folder_bytes,
                    speed_mbps,
                    is_finished: false,
                    current_file: file_index,
                    total_files,
                    log_message: None,
                });

                if config.simulate_interruptions
                    && !outage_triggered
                    && file_index >= total_files / 2
                    && file_index < total_files
                {
                    outage_triggered = true;
                    paused_duration += simulate_mock_network_outage(
                        &MockOutageParams {
                            mock_ip,
                            selected_target: &selected_target,
                            file_name,
                            bytes_done: folder_bytes_done,
                            bytes_total: total_folder_bytes,
                            resume_offset_bytes: folder_bytes_done,
                            current_file: file_index,
                            total_files,
                        },
                        config.outage_retry_delays,
                        &prog_tx,
                        &mut cancel_rx,
                    )
                    .await?;
                }
            }

            // Write sample files to disk without cluttering the filesystem with tens of thousands of inodes
            if file_index <= 5 || file_index == total_files {
                ensure_safe_client_dest_path(local_path)?;
                let placeholder = format!(
                    "LanShare simulated test file: {}\nSimulated size: {} bytes\n",
                    file_name, total_size
                );
                let _ = tokio::fs::write(local_path, placeholder.as_bytes()).await;
            }
        }
    } else {
        let sleep_ms = config.step_sleep_ms;
        // Realistic simulated LAN transfer speed cap: ~75 MB/s (restricts huge files from finishing instantly)
        let max_speed_bytes_per_sec = 75 * 1024 * 1024u64;
        let max_step_bytes = (max_speed_bytes_per_sec * sleep_ms) / 1000;
        let start_instant = Instant::now();
        let mid_file_idx = total_files.div_ceil(2).max(1);

        for (idx, (file_name, local_path, total_size)) in files.iter().enumerate() {
            let file_index = idx + 1;
            let size = (*total_size).max(1024);

            ensure_safe_client_dest_path(local_path)?;

            // Restrict speed for large/huge files so simulation runs at realistic LAN speeds (~75 MB/s)
            let min_steps = 18u64;
            let step_bytes = (size / min_steps).min(max_step_bytes).max(1024);
            let mut steps = size.div_ceil(step_bytes);
            steps = steps.max(min_steps);
            if cfg!(test) {
                steps = steps.min(20);
            }
            let mid_step = (steps / 2).max(1);

            for step in 1..=steps {
                wait_mock_step_or_cancel(Duration::from_millis(sleep_ms), &mut cancel_rx).await?;

                let file_step_done = if step == steps {
                    *total_size
                } else {
                    (*total_size).min(step_bytes * step)
                };
                let elapsed_secs = start_instant
                    .elapsed()
                    .saturating_sub(paused_duration)
                    .as_secs_f32()
                    .max(0.001);
                let cur_bytes_done = if entry.is_dir {
                    folder_bytes_done + file_step_done
                } else {
                    file_step_done
                };
                let speed_mbps =
                    ((cur_bytes_done as f32 / (1024.0 * 1024.0)) / elapsed_secs).max(0.1);
                let is_last_step = step == steps;
                let is_all_finished = is_last_step && file_index == total_files && !entry.is_dir;

                let (bytes_done, bytes_total) = if entry.is_dir {
                    let rep_tot = if total_folder_bytes > 0 {
                        total_folder_bytes
                    } else {
                        total_files as u64
                    };
                    let rep_done = if total_folder_bytes > 0 {
                        folder_bytes_done + file_step_done
                    } else {
                        file_index as u64
                    };
                    (rep_done, rep_tot)
                } else {
                    (file_step_done, *total_size)
                };

                let _ = prog_tx.send(TransferProgress {
                    selected_target: selected_target.clone(),
                    file_name: file_name.clone(),
                    bytes_done,
                    bytes_total,
                    speed_mbps,
                    is_finished: is_all_finished,
                    current_file: file_index,
                    total_files,
                    log_message: if is_last_step {
                        Some(format!(
                            "[Mock] Downloaded '{}' ({})",
                            file_name,
                            format_file_size(*total_size)
                        ))
                    } else {
                        None
                    },
                });

                if config.simulate_interruptions
                    && !outage_triggered
                    && file_index == mid_file_idx
                    && step == mid_step
                {
                    outage_triggered = true;
                    paused_duration += simulate_mock_network_outage(
                        &MockOutageParams {
                            mock_ip,
                            selected_target: &selected_target,
                            file_name,
                            bytes_done,
                            bytes_total,
                            resume_offset_bytes: file_step_done,
                            current_file: file_index,
                            total_files,
                        },
                        config.outage_retry_delays,
                        &prog_tx,
                        &mut cancel_rx,
                    )
                    .await?;
                }
            }

            if entry.is_dir {
                folder_bytes_done += *total_size;
            }

            // Write lightweight placeholder file in test download folder
            let placeholder = format!(
                "LanShare simulated test file: {}\nSimulated size: {} bytes\n",
                file_name, total_size
            );
            let _ = tokio::fs::write(local_path, placeholder.as_bytes()).await;
        }
    }

    if entry.is_dir {
        let final_bytes = if total_folder_bytes > 0 {
            total_folder_bytes
        } else {
            total_files as u64
        };
        let _ = prog_tx.send(TransferProgress {
            selected_target,
            file_name: format!("Folder '{}' (all files complete)", entry.name),
            bytes_done: final_bytes,
            bytes_total: final_bytes,
            speed_mbps: 0.0,
            is_finished: true,
            current_file: total_files,
            total_files,
            log_message: Some(format!(
                "[Mock] Finished downloading folder '{}' ({} files total)",
                entry.name, total_files
            )),
        });
    }

    Ok(())
}

pub fn validate_cli_secret(raw: String) -> Result<String, String> {
    let trimmed = raw.trim().to_string();
    if trimmed.len() < crate::protocol::MIN_SECRET_LEN {
        return Err(format!(
            "Share-Ring secret must be at least {} characters.",
            crate::protocol::MIN_SECRET_LEN
        ));
    }
    Ok(trimmed)
}

pub fn read_secret_from_env(var_name: &str) -> Result<String, String> {
    let val = std::env::var(var_name)
        .map_err(|_| format!("Environment variable '{}' is not set.", var_name))?;
    validate_cli_secret(val)
}

pub fn read_secret_from_stdin() -> Result<String, String> {
    use std::io::BufRead;
    let mut line = String::new();
    let stdin = std::io::stdin();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read secret from stdin: {}", e))?;
    validate_cli_secret(line)
}

pub fn generate_random_password() -> String {
    const CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    // Largest multiple of 31 fitting in a byte (248 = 8 * 31) for unbiased rejection sampling.
    const LIMIT: u8 = 248;

    let mut groups = Vec::with_capacity(4);
    for _ in 0..4 {
        let mut group = String::with_capacity(4);
        while group.len() < 4 {
            let buf: [u8; 8] = crate::network::random_bytes();
            for &b in &buf {
                if b < LIMIT && group.len() < 4 {
                    group.push(CHARS[(b as usize) % CHARS.len()] as char);
                }
            }
        }
        groups.push(group);
    }
    groups.join("-")
}

pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let (val, unit) = if bytes >= TB {
        (bytes as f64 / TB as f64, "TB")
    } else if bytes >= GB {
        (bytes as f64 / GB as f64, "GB")
    } else if bytes >= MB {
        (bytes as f64 / MB as f64, "MB")
    } else if bytes >= KB {
        (bytes as f64 / KB as f64, "KB")
    } else {
        return format!("{} B", bytes);
    };

    let rounded = val.round();
    if rounded == 0.0 {
        // Show decimals if otherwise zero
        if val >= 0.095 {
            format!("{:.1} {}", val, unit)
        } else {
            format!("{:.2} {}", val, unit)
        }
    } else {
        format!("{:.0} {}", rounded, unit)
    }
}

/// Formats a Share-Ring secret for display in constrained-width UI panels.
/// If `is_plain` is false, returns masked bullet characters ("••••••••••••").
/// If `is_plain` is true and secret exceeds `max_line_len`, wraps it across multiple lines
/// preferring delimiter breaks (`-`, `_`, ` `) or hard wrapping without altering the underlying secret.
pub fn format_secret_display(secret: &str, is_plain: bool, max_line_len: usize) -> String {
    if !is_plain {
        return "••••••••••••".to_string();
    }
    if secret.len() <= max_line_len {
        return secret.to_string();
    }
    let mut lines = Vec::new();
    let mut remaining = secret;
    while !remaining.is_empty() {
        if remaining.len() <= max_line_len {
            lines.push(remaining.to_string());
            break;
        }
        let chunk = &remaining[..max_line_len];
        let split_at = if let Some(last_break) = chunk.rfind(['-', '_', ' ']) {
            if last_break >= max_line_len / 2 {
                last_break + 1
            } else {
                max_line_len
            }
        } else {
            max_line_len
        };
        lines.push(remaining[..split_at].trim_end().to_string());
        remaining = remaining[split_at..].trim_start();
    }
    lines.join("\n")
}

/// Formats an estimated remaining duration in either seconds, minutes, or hours.
/// Examples:
/// - Under 60 seconds: "45s"
/// - Under 60 minutes: "12m"
/// - 60 minutes or more: "1.5h" or "2h"
pub fn format_remaining_time(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        let mins = (seconds as f64 / 60.0).round() as u64;
        format!("{}m", mins.max(1))
    } else {
        let hours = seconds as f64 / 3600.0;
        if hours >= 10.0 {
            format!("{:.0}h", hours.round())
        } else {
            let rounded = (hours * 10.0).round() / 10.0;
            if rounded.fract() == 0.0 {
                format!("{:.0}h", rounded)
            } else {
                format!("{:.1}h", rounded)
            }
        }
    }
}

/// Formats a completed download timestamp.
/// If completed on the current date, returns "HH:MM:SS".
/// If completed on a different date, includes the date: "YYYY-MM-DD HH:MM:SS".
pub fn format_completed_timestamp(dt: DateTime<Local>) -> String {
    let now = Local::now();
    if dt.date_naive() == now.date_naive() {
        dt.format("%H:%M:%S").to_string()
    } else {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

/// Calculates estimated remaining seconds given bytes remaining and speed in MB/s (MiB/s).
pub fn estimate_remaining_seconds(remaining_bytes: u64, speed_mbps: f32) -> Option<u64> {
    if speed_mbps > 0.001 && remaining_bytes > 0 {
        let bytes_per_sec = speed_mbps as f64 * 1024.0 * 1024.0;
        let secs = (remaining_bytes as f64 / bytes_per_sec).round() as u64;
        Some(secs.max(1))
    } else if remaining_bytes == 0 {
        Some(0)
    } else {
        None
    }
}

/// Calculates estimated remaining seconds for single and multi-file transfers, taking into
/// account byte transfer throughput as well as per-file processing rate when multiple files are transferred.
pub fn estimate_folder_remaining_seconds(
    remaining_bytes: u64,
    speed_mbps: f32,
    current_file: usize,
    total_files: usize,
    elapsed_duration: Option<Duration>,
) -> Option<u64> {
    let byte_eta = estimate_remaining_seconds(remaining_bytes, speed_mbps);
    if total_files > 1 && current_file > 0 {
        if let Some(elapsed) = elapsed_duration {
            let elapsed_secs = elapsed.as_secs_f64();
            if elapsed_secs >= 0.2 {
                let remaining_files = total_files.saturating_sub(current_file);
                let time_per_file = elapsed_secs / current_file as f64;
                let file_eta = (remaining_files as f64 * time_per_file).round() as u64;
                return match byte_eta {
                    Some(b_eta) => {
                        Some(
                            b_eta
                                .max(file_eta)
                                .max(if remaining_files > 0 { 1 } else { 0 }),
                        )
                    }
                    None => {
                        if remaining_files > 0 {
                            Some(file_eta.max(1))
                        } else {
                            Some(0)
                        }
                    }
                };
            }
        }
    }
    byte_eta
}

/// Smooths and throttles estimated time of arrival (ETA) calculation.
/// Above 2 minutes (> 120s): uses slower polling (4s interval) with heavy EMA smoothing (75/25)
/// so that the displayed ETA does not oscillate or flicker between adjacent minutes.
/// Between 1 and 2 minutes (61s..=120s): uses moderate polling (2s interval) with 50/50 smoothing.
/// Under 1 minute (<= 60s): updates frequently (1s interval) for smooth second-by-second countdown.
#[derive(Debug, Clone, Default)]
pub struct EtaStabilizer {
    current_key: Option<String>,
    cached_eta: Option<u64>,
    last_update: Option<Instant>,
}

impl EtaStabilizer {
    pub fn new() -> Self {
        Self {
            current_key: None,
            cached_eta: None,
            last_update: None,
        }
    }

    pub fn reset(&mut self) {
        self.current_key = None;
        self.cached_eta = None;
        self.last_update = None;
    }

    pub fn update(&mut self, key: Option<&str>, raw_eta: Option<u64>) -> Option<u64> {
        self.update_at(key, raw_eta, Instant::now())
    }

    pub fn update_at(
        &mut self,
        key: Option<&str>,
        raw_eta: Option<u64>,
        now: Instant,
    ) -> Option<u64> {
        let (Some(key), Some(raw)) = (key, raw_eta) else {
            self.reset();
            return None;
        };

        if self.current_key.as_deref() != Some(key) {
            self.reset();
            self.current_key = Some(key.to_string());
        }

        if raw == 0 {
            self.cached_eta = Some(0);
            self.last_update = Some(now);
            return Some(0);
        }

        let Some(cached) = self.cached_eta else {
            self.cached_eta = Some(raw);
            self.last_update = Some(now);
            return Some(raw);
        };

        let last_time = self.last_update.unwrap_or(now);
        let elapsed = now.saturating_duration_since(last_time);

        // Determine calculation/polling frequency:
        // - Above 2 minutes (> 120s): slower polling (4s interval)
        // - Between 1 and 2 minutes (61s..=120s): moderate polling (2s interval)
        // - Under 1 minute (<= 60s): fast polling (1s interval)
        let interval = if cached > 120 {
            Duration::from_secs(4)
        } else if cached > 60 {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(1)
        };

        // If raw ETA dropped significantly under 1 minute while cached was higher,
        // break out of slow polling immediately to display under-one-minute countdown.
        let force_fast_update = raw <= 60 && cached > 60;

        if !force_fast_update && elapsed < interval {
            return Some(cached);
        }

        let smoothed = if force_fast_update {
            raw
        } else if cached > 120 {
            (cached as f64 * 0.75 + raw as f64 * 0.25).round() as u64
        } else if cached > 60 {
            (cached as f64 * 0.50 + raw as f64 * 0.50).round() as u64
        } else if raw > cached {
            // Light dampening when under 1 minute to avoid jittering upwards on momentary throughput dips
            (cached as f64 * 0.50 + raw as f64 * 0.50).round() as u64
        } else {
            raw
        };

        let next_eta = smoothed.max(1);
        self.cached_eta = Some(next_eta);
        self.last_update = Some(now);
        Some(next_eta)
    }

    pub fn current(&self) -> Option<u64> {
        self.cached_eta
    }
}

pub fn dirs_fallback() -> PathBuf {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.trim().is_empty() {
            return PathBuf::from(profile);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return PathBuf::from(home);
        }
    }
    if cfg!(unix) {
        PathBuf::from("/tmp")
    } else {
        PathBuf::from(r"C:\")
    }
}

/// Returns an isolated per-process downloads directory used only in Test Mode / unit tests.
pub fn test_downloads_dir() -> PathBuf {
    std::env::temp_dir().join(format!("lanshare-test-downloads-{}", std::process::id()))
}

/// Opens a directory in the native file explorer / manager (Explorer on Windows, xdg-open on Linux, Finder on macOS).
pub fn open_folder_in_explorer(path: &std::path::Path) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }

    if !path.exists() {
        let _ = std::fs::create_dir_all(path);
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(path)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("Failed to open Explorer: {}", e))
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("Failed to open Finder: {}", e))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let res = std::process::Command::new("xdg-open").arg(path).spawn();
        match res {
            Ok(_) => Ok(()),
            Err(_) => std::process::Command::new("gio")
                .arg("open")
                .arg(path)
                .spawn()
                .map(|_| ())
                .map_err(|e| format!("Failed to open file manager: {}", e)),
        }
    }
}

pub const GITHUB_REPO_URL: &str = "https://github.com/jokkeheikkila/LanShare";
pub const GITHUB_RELEASES_URL: &str = "https://github.com/jokkeheikkila/LanShare/releases";

#[cfg(target_os = "windows")]
fn windows_shell_open(target: &std::ffi::OsStr, kind: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut std::ffi::c_void,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }

    const SW_SHOWNORMAL: i32 = 1;
    let op: Vec<u16> = "open\0".encode_utf16().collect();
    let file: Vec<u16> = target.encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: `op` and `file` are valid NUL-terminated UTF-16 buffers kept alive across the call;
    // unused pointer arguments and `hwnd` are intentionally null.
    let rc = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if rc > 32 {
        Ok(())
    } else {
        Err(format!(
            "Failed to open {} (ShellExecuteW code {})",
            kind, rc
        ))
    }
}

fn open_in_os(target: &std::ffi::OsStr, kind: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        windows_shell_open(target, kind)
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(target)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("Failed to open {}: {}", kind, e))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let res = std::process::Command::new("xdg-open").arg(target).spawn();
        match res {
            Ok(_) => Ok(()),
            Err(_) => std::process::Command::new("gio")
                .arg("open")
                .arg(target)
                .spawn()
                .map(|_| ())
                .map_err(|e| format!("Failed to open {}: {}", kind, e)),
        }
    }
}

pub fn open_file_in_default_app(path: &std::path::Path) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }

    if !path.exists() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);
    }

    open_in_os(path.as_os_str(), "file")
}

/// Opens an `http://` or `https://` URL in the user's default browser.
pub fn open_url(url: &str) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Only http:// and https:// URLs are supported.".to_string());
    }
    if cfg!(test) {
        return Ok(());
    }
    open_in_os(std::ffi::OsStr::new(url), "URL")
}

static LOG_FILE_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
const MAX_RETAINED_LOGS: usize = 10;

fn get_writable_log_dir() -> PathBuf {
    let dir = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(dirs_fallback)
            .join("LanShare")
            .join("logs")
    } else if let Some(xdg_state) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(xdg_state).join("lanshare").join("logs")
    } else {
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(dirs_fallback);
        home.join(".local")
            .join("state")
            .join("lanshare")
            .join("logs")
    };

    if std::fs::create_dir_all(&dir).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        return dir;
    }

    std::env::temp_dir().join("lanshare-logs")
}

fn prune_old_logs(base_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return;
    };
    let mut logs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("lanshare-") && n.ends_with(".log"))
        })
        .collect();
    if logs.len() <= MAX_RETAINED_LOGS {
        return;
    }
    logs.sort();
    let excess = logs.len() - MAX_RETAINED_LOGS;
    for old in logs.into_iter().take(excess) {
        let _ = std::fs::remove_file(old);
    }
}

/// Generates a session-specific timestamped log filename.
///
/// Format: `lanshare-YYYYMMDD-HHMMSS.log` (or `lanshare-YYYYMMDD-HHMMSS-<pid>.log` if duplicate).
pub fn generate_session_log_path(base_dir: &std::path::Path, ts: &str, pid: u32) -> PathBuf {
    let candidate = base_dir.join(format!("lanshare-{}.log", ts));
    if !candidate.exists() {
        candidate
    } else {
        base_dir.join(format!("lanshare-{}-{}.log", ts, pid))
    }
}

/// Returns the path to this session's persistent log file inside the OS user state/log directory.
pub fn get_log_file_path() -> PathBuf {
    LOG_FILE_PATH
        .get_or_init(|| {
            let base_dir = get_writable_log_dir();
            let _ = std::fs::create_dir_all(&base_dir);
            prune_old_logs(&base_dir);
            let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
            let pid = std::process::id();
            generate_session_log_path(&base_dir, &ts, pid)
        })
        .clone()
}

/// Appends a single line to the persistent log file on disk.
pub fn spool_log_entry(line: &str) {
    let path = get_log_file_path();
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(file, "{}", line);
    }
}

/// Writes a prominent session start banner whenever LanShare starts up.
pub fn spool_log_session_start(mode: &str) {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let version = env!("CARGO_PKG_VERSION");
    let pid = std::process::id();
    let banner = format!(
        "\n============================================================\n[Session Started] {} | LanShare v{} ({}) [PID: {}]\n============================================================",
        ts, version, mode, pid
    );
    spool_log_entry(&banner);
}

const MOCK_FRIEND_DOWNLOADS: &[(&str, &str, u64)] = &[
    (
        "Alice-Laptop (192.168.1.42)",
        "vacation_highlights.mp4",
        42_500_000,
    ),
    ("Bob-Deck (192.168.1.77)", "party_playlist.zip", 18_400_000),
    (
        "Charlie-Workstation (192.168.1.105)",
        "lan_notes_2026.pdf",
        3_250_000,
    ),
    (
        "Diana-Mini (192.168.1.63)",
        "retro_pixel_pack.tar.gz",
        64_100_000,
    ),
    (
        "Eve-MacBook (192.168.1.91)",
        "boardgame_rules.pdf",
        5_800_000,
    ),
    (
        "Frank-LinuxBox (192.168.1.118)",
        "weekend_photos_raw.zip",
        128_000_000,
    ),
];

/// Timing configuration for simulated friend downloads in `--test` mode.
#[derive(Clone, Copy, Debug)]
pub struct MockDownloadConfig {
    pub initial_delay: std::time::Duration,
    pub transfer_duration: std::time::Duration,
    pub between_delay: std::time::Duration,
    pub max_events: Option<usize>,
    pub simulate_interruptions: bool,
    pub interruption_delay: std::time::Duration,
}

impl Default for MockDownloadConfig {
    fn default() -> Self {
        Self {
            initial_delay: std::time::Duration::from_millis(1200),
            transfer_duration: std::time::Duration::from_millis(2000),
            between_delay: std::time::Duration::from_millis(4000),
            max_events: None,
            simulate_interruptions: true,
            interruption_delay: std::time::Duration::from_millis(2500),
        }
    }
}

struct MockActiveDownloadGuard {
    total: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    by_folder:
        std::sync::Arc<std::sync::RwLock<std::collections::HashMap<std::path::PathBuf, usize>>>,
    root: std::path::PathBuf,
}

impl MockActiveDownloadGuard {
    fn new(
        total: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        by_folder: std::sync::Arc<
            std::sync::RwLock<std::collections::HashMap<std::path::PathBuf, usize>>,
        >,
        root: std::path::PathBuf,
    ) -> Self {
        total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut map) = by_folder.write() {
            *map.entry(root.clone()).or_insert(0) += 1;
        }
        Self {
            total,
            by_folder,
            root,
        }
    }
}

impl Drop for MockActiveDownloadGuard {
    fn drop(&mut self) {
        self.total
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut map) = self.by_folder.write() {
            if let Some(count) = map.get_mut(&self.root) {
                if *count <= 1 {
                    map.remove(&self.root);
                } else {
                    *count -= 1;
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MockTransferOutcome {
    Completed,
    ServerStopped,
    ShareRemoved,
}

fn push_mock_server_log(
    log_tx: &tokio::sync::mpsc::UnboundedSender<crate::server::ServerLogEvent>,
    message: String,
    is_error: bool,
) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = log_tx.send(crate::server::ServerLogEvent {
        timestamp,
        message,
        is_error,
    });
}

async fn wait_mock_delay(
    duration: std::time::Duration,
    is_running: &std::sync::atomic::AtomicBool,
    registry_notify_rx: &mut tokio::sync::watch::Receiver<u64>,
    wake_on_registry_change: bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + duration;
    let slice = std::time::Duration::from_millis(100);
    loop {
        if !is_running.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return true;
        }
        let step = (deadline - now).min(slice);
        if wake_on_registry_change {
            tokio::select! {
                _ = tokio::time::sleep(step) => {}
                res = registry_notify_rx.changed() => {
                    if res.is_ok() {
                        return is_running.load(std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        } else {
            tokio::time::sleep(step).await;
        }
    }
}

async fn wait_mock_transfer(
    duration: std::time::Duration,
    is_running: &std::sync::atomic::AtomicBool,
    shared_folders: &std::sync::RwLock<Vec<std::path::PathBuf>>,
    root: &std::path::Path,
    registry_notify_rx: &mut tokio::sync::watch::Receiver<u64>,
) -> MockTransferOutcome {
    let deadline = tokio::time::Instant::now() + duration;
    let slice = std::time::Duration::from_millis(100);
    loop {
        if !is_running.load(std::sync::atomic::Ordering::Relaxed) {
            return MockTransferOutcome::ServerStopped;
        }
        let still_shared = shared_folders
            .read()
            .map(|list| list.iter().any(|p| p == root))
            .unwrap_or(false);
        if !still_shared {
            return MockTransferOutcome::ShareRemoved;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return MockTransferOutcome::Completed;
        }
        let step = (deadline - now).min(slice);
        tokio::select! {
            _ = tokio::time::sleep(step) => {}
            _ = registry_notify_rx.changed() => {}
        }
    }
}

fn push_mock_abort_log(
    log_tx: &tokio::sync::mpsc::UnboundedSender<crate::server::ServerLogEvent>,
    outcome: MockTransferOutcome,
    file_label: &str,
    peer: &str,
) -> bool {
    match outcome {
        MockTransferOutcome::Completed => false,
        MockTransferOutcome::ServerStopped => {
            push_mock_server_log(
                log_tx,
                format!("Server stopped: aborted download stream of '{file_label}' to {peer}"),
                true,
            );
            true
        }
        MockTransferOutcome::ShareRemoved => {
            push_mock_server_log(
                log_tx,
                format!("Share removed: aborted download stream of '{file_label}' to {peer}"),
                true,
            );
            false
        }
    }
}

struct MockServerTransferCtx<'a> {
    config: MockDownloadConfig,
    simulate_drop: bool,
    peer: &'a str,
    file_label: &'a str,
    size_label: &'a str,
    is_running: &'a std::sync::atomic::AtomicBool,
    shared_folders: &'a std::sync::RwLock<Vec<std::path::PathBuf>>,
    root: &'a std::path::Path,
    registry_notify_rx: &'a mut tokio::sync::watch::Receiver<u64>,
    log_tx: &'a tokio::sync::mpsc::UnboundedSender<crate::server::ServerLogEvent>,
}

async fn run_single_mock_server_transfer(ctx: MockServerTransferCtx<'_>) -> bool {
    let first_phase = if ctx.simulate_drop {
        ctx.config.transfer_duration / 2
    } else {
        ctx.config.transfer_duration
    };

    let outcome = wait_mock_transfer(
        first_phase,
        ctx.is_running,
        ctx.shared_folders,
        ctx.root,
        ctx.registry_notify_rx,
    )
    .await;
    if outcome != MockTransferOutcome::Completed {
        return push_mock_abort_log(ctx.log_tx, outcome, ctx.file_label, ctx.peer);
    }

    if ctx.simulate_drop {
        push_mock_server_log(
            ctx.log_tx,
            format!(
                "{} network interrupted while downloading '{}' (connection reset at 50%); waiting to resume...",
                ctx.peer, ctx.file_label
            ),
            true,
        );
        let outage_outcome = wait_mock_transfer(
            ctx.config.interruption_delay,
            ctx.is_running,
            ctx.shared_folders,
            ctx.root,
            ctx.registry_notify_rx,
        )
        .await;
        if outage_outcome != MockTransferOutcome::Completed {
            return push_mock_abort_log(ctx.log_tx, outage_outcome, ctx.file_label, ctx.peer);
        }

        push_mock_server_log(
            ctx.log_tx,
            format!("{} reconnected and resumed '{}'", ctx.peer, ctx.file_label),
            false,
        );

        let second_phase = ctx.config.transfer_duration.saturating_sub(first_phase);
        let resume_outcome = wait_mock_transfer(
            second_phase,
            ctx.is_running,
            ctx.shared_folders,
            ctx.root,
            ctx.registry_notify_rx,
        )
        .await;
        if resume_outcome != MockTransferOutcome::Completed {
            return push_mock_abort_log(ctx.log_tx, resume_outcome, ctx.file_label, ctx.peer);
        }
    }

    push_mock_server_log(
        ctx.log_tx,
        format!(
            "{} finished downloading '{}' ({})",
            ctx.peer, ctx.file_label, ctx.size_label
        ),
        false,
    );
    false
}

/// Runs a loop simulating made-up friends downloading dummy files from currently shared folders.
pub fn run_mock_server_downloads(
    handle: &crate::server::ServerHandle,
    config: MockDownloadConfig,
) -> impl std::future::Future<Output = ()> + Send + 'static {
    let is_running = handle.is_running.clone();
    let shared_folders = handle.shared_folders.clone();
    let log_tx = handle.log_tx.clone();
    let active_downloads = handle.active_downloads.clone();
    let active_folder_downloads = handle.active_folder_downloads.clone();
    let mut registry_notify_rx = handle.registry_notify_tx.subscribe();

    async move {
        if !wait_mock_delay(
            config.initial_delay,
            &is_running,
            &mut registry_notify_rx,
            false,
        )
        .await
        {
            return;
        }

        let mut idx: usize = 0;
        let mut emitted: usize = 0;

        loop {
            if !is_running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if let Some(limit) = config.max_events {
                if emitted >= limit {
                    break;
                }
            }

            let folders = shared_folders.read().map(|g| g.clone()).unwrap_or_default();
            if folders.is_empty() {
                if !wait_mock_delay(
                    config.between_delay,
                    &is_running,
                    &mut registry_notify_rx,
                    true,
                )
                .await
                {
                    break;
                }
                continue;
            }

            let root = folders[idx % folders.len()].clone();
            let (peer, dummy_file, size_bytes) =
                MOCK_FRIEND_DOWNLOADS[idx % MOCK_FRIEND_DOWNLOADS.len()];
            idx = idx.wrapping_add(1);
            let simulate_drop = config.simulate_interruptions && idx.is_multiple_of(2);

            let folder_label = root
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("shared");
            let file_label = format!("{folder_label}/{dummy_file}");
            let size_label = format_file_size(size_bytes);

            let _guard = MockActiveDownloadGuard::new(
                active_downloads.clone(),
                active_folder_downloads.clone(),
                root.clone(),
            );
            push_mock_server_log(
                &log_tx,
                format!("{peer} started downloading '{file_label}' ({size_label})"),
                false,
            );

            let should_stop = run_single_mock_server_transfer(MockServerTransferCtx {
                config,
                simulate_drop,
                peer,
                file_label: &file_label,
                size_label: &size_label,
                is_running: &is_running,
                shared_folders: &shared_folders,
                root: &root,
                registry_notify_rx: &mut registry_notify_rx,
                log_tx: &log_tx,
            })
            .await;

            drop(_guard);
            if should_stop {
                break;
            }
            emitted += 1;

            if let Some(limit) = config.max_events {
                if emitted >= limit {
                    break;
                }
            }

            if !wait_mock_delay(
                config.between_delay,
                &is_running,
                &mut registry_notify_rx,
                false,
            )
            .await
            {
                break;
            }
        }
    }
}

/// Spawns simulated friend downloads onto the provided Tokio runtime for `--test` hosting.
pub fn spawn_mock_server_downloads(
    rt: &tokio::runtime::Runtime,
    handle: &crate::server::ServerHandle,
) {
    rt.spawn(run_mock_server_downloads(
        handle,
        MockDownloadConfig::default(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_spooling() {
        let log_path = get_log_file_path();
        let fname = log_path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        assert!(fname.starts_with("lanshare-") && fname.ends_with(".log"));

        let unique_marker = format!(
            "TEST_LOG_ENTRY_{:x}",
            u64::from_le_bytes(crate::network::random_bytes())
        );
        spool_log_entry(&unique_marker);

        let contents = std::fs::read_to_string(&log_path).expect("failed to read log file");
        assert!(contents.contains(&unique_marker));
    }

    #[test]
    fn test_timestamped_session_log_path() {
        let temp_dir = std::env::temp_dir();
        let path1 = generate_session_log_path(&temp_dir, "20261112-140800", 1111);
        assert_eq!(path1, temp_dir.join("lanshare-20261112-140800.log"));

        // If file already exists, appends PID to guarantee uniqueness
        std::fs::write(&path1, b"session 1").unwrap();
        let path2 = generate_session_log_path(&temp_dir, "20261112-140800", 2222);
        assert_eq!(path2, temp_dir.join("lanshare-20261112-140800-2222.log"));

        let _ = std::fs::remove_file(&path1);
    }

    #[test]
    fn test_format_remaining_time_and_estimates() {
        // Seconds (< 60s)
        assert_eq!(format_remaining_time(0), "0s");
        assert_eq!(format_remaining_time(1), "1s");
        assert_eq!(format_remaining_time(15), "15s");
        assert_eq!(format_remaining_time(59), "59s");

        // Minutes (60s <= t < 3600s)
        assert_eq!(format_remaining_time(60), "1m");
        assert_eq!(format_remaining_time(120), "2m");
        assert_eq!(format_remaining_time(720), "12m");
        assert_eq!(format_remaining_time(3540), "59m");

        // Hours (>= 3600s)
        assert_eq!(format_remaining_time(3600), "1h");
        assert_eq!(format_remaining_time(5400), "1.5h");
        assert_eq!(format_remaining_time(7200), "2h");
        assert_eq!(format_remaining_time(36000), "10h");
        assert_eq!(format_remaining_time(86400), "24h");

        // Calculations from remaining bytes & speed (MB/s)
        assert_eq!(estimate_remaining_seconds(0, 10.0), Some(0));
        assert_eq!(estimate_remaining_seconds(100, 0.0), None);
        // 10 MB at 1 MB/s -> ~10s
        let ten_mb = 10 * 1024 * 1024;
        assert_eq!(estimate_remaining_seconds(ten_mb, 1.0), Some(10));
        // 120 MB at 2 MB/s -> ~60s
        let one_twenty_mb = 120 * 1024 * 1024;
        assert_eq!(estimate_remaining_seconds(one_twenty_mb, 2.0), Some(60));

        // Folder multi-file estimates (small files processing rate vs throughput)
        // 100 files total, 10 done in 5.0 seconds -> 90 files remaining at 0.5s/file = 45s
        let folder_est = estimate_folder_remaining_seconds(
            100 * 1024,
            50.0,
            10,
            100,
            Some(Duration::from_secs(5)),
        );
        assert_eq!(folder_est, Some(45));

        // When all files done -> Some(0)
        let done_est =
            estimate_folder_remaining_seconds(0, 50.0, 100, 100, Some(Duration::from_secs(50)));
        assert_eq!(done_est, Some(0));

        // Test completed timestamp formatting: today vs different day
        let now = Local::now();
        let today_formatted = format_completed_timestamp(now);
        assert_eq!(today_formatted, now.format("%H:%M:%S").to_string());

        let yesterday = now - chrono::Duration::days(1);
        let yesterday_formatted = format_completed_timestamp(yesterday);
        assert_eq!(
            yesterday_formatted,
            yesterday.format("%Y-%m-%d %H:%M:%S").to_string()
        );

        // File and folder size formatting (rounded, no decimals, decimals only if otherwise zero)
        assert_eq!(format_file_size(0), "0 B");
        assert_eq!(format_file_size(1), "1 B");
        assert_eq!(format_file_size(500), "500 B");
        assert_eq!(format_file_size(1024), "1 KB");
        assert_eq!(format_file_size(1500), "1 KB");
        assert_eq!(format_file_size(1600), "2 KB");
        assert_eq!(format_file_size(1024 * 1024), "1 MB");
        assert_eq!(format_file_size(15 * 1024 * 1024 + 300_000), "15 MB");
        assert_eq!(format_file_size(15 * 1024 * 1024 + 800_000), "16 MB");
        assert_eq!(format_file_size(1024 * 1024 * 1024), "1 GB");
        assert_eq!(format_file_size(1024 * 1024 * 1024 + 200_000_000), "1 GB");
        assert_eq!(
            format_file_size(1024 * 1024 * 1024 * 2 + 700_000_000),
            "3 GB"
        );

        // ETA Stabilizer: slow polling and smoothing > 2m, fast countdown <= 1m
        let mut stabilizer = EtaStabilizer::new();
        let t0 = Instant::now();

        // 1. Initial measurement above 2m: initializes immediately
        assert_eq!(
            stabilizer.update_at(Some("item1"), Some(180), t0),
            Some(180)
        );
        assert_eq!(format_remaining_time(stabilizer.current().unwrap()), "3m");

        // 2. Rapid polling within 4s interval above 2m: holds cached value, ignores momentary speed jitter
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!(
            stabilizer.update_at(Some("item1"), Some(145), t1),
            Some(180)
        ); // 145 would have displayed 2m
        let t2 = t0 + Duration::from_secs(2);
        assert_eq!(
            stabilizer.update_at(Some("item1"), Some(220), t2),
            Some(180)
        ); // 220 would have displayed 4m
        let t3 = t0 + Duration::from_millis(3900);
        assert_eq!(
            stabilizer.update_at(Some("item1"), Some(160), t3),
            Some(180)
        );

        // 3. At 4s, slow polling triggers update with 75/25 smoothing
        let t4 = t0 + Duration::from_secs(4);
        // (180 * 0.75 + 160 * 0.25) = 135 + 40 = 175
        assert_eq!(
            stabilizer.update_at(Some("item1"), Some(160), t4),
            Some(175)
        );
        assert_eq!(format_remaining_time(stabilizer.current().unwrap()), "3m"); // Stays stably at 3m

        // 4. If raw ETA drops to under 1m (e.g. 50s), it immediately breaks out of slow polling
        let t5 = t4 + Duration::from_millis(200);
        assert_eq!(stabilizer.update_at(Some("item1"), Some(50), t5), Some(50));
        assert_eq!(format_remaining_time(stabilizer.current().unwrap()), "50s");

        // 5. Under 1 minute: fast polling (1s interval) displays second-by-second countdown
        let t6 = t5 + Duration::from_secs(1);
        assert_eq!(stabilizer.update_at(Some("item1"), Some(49), t6), Some(49));
        let t7 = t6 + Duration::from_secs(1);
        assert_eq!(stabilizer.update_at(Some("item1"), Some(48), t7), Some(48));

        // 6. When download finishes (raw = 0), updates immediately to 0
        let t8 = t7 + Duration::from_millis(100);
        assert_eq!(stabilizer.update_at(Some("item1"), Some(0), t8), Some(0));

        // 7. Switching download key or passing None resets stabilizer
        assert_eq!(stabilizer.update_at(None, None, t8), None);
        assert!(stabilizer.current().is_none());
        assert_eq!(stabilizer.update_at(Some("item2"), Some(75), t8), Some(75));

        // 8. Secret multi-line display formatting
        // Hidden secret returns masked string
        assert_eq!(
            format_secret_display("party-ring-42", false, 16),
            "••••••••••••"
        );
        // Short secret fits on single line
        assert_eq!(
            format_secret_display("party-ring-42", true, 16),
            "party-ring-42"
        );
        // Long secret with hyphen splits into multi-line
        assert_eq!(
            format_secret_display("super-long-custom-shared-secret-key-1234", true, 16),
            "super-long-\ncustom-shared-\nsecret-key-1234"
        );
        // Long secret without delimiters hard wraps
        assert_eq!(
            format_secret_display("0123456789abcdef0123456789abcdef", true, 16),
            "0123456789abcdef\n0123456789abcdef"
        );
    }

    #[test]
    fn test_open_folder_in_explorer_ensures_dir() {
        let temp_dir = std::env::temp_dir();
        assert!(temp_dir.exists());
        // Verifies open_folder_in_explorer handles existing and created directories
        let res = open_folder_in_explorer(&temp_dir);
        // In headless test environments xdg-open/gio may succeed or exit without display, but must not panic
        let _ = res;
    }

    #[test]
    fn test_open_file_in_default_app() {
        let temp_file =
            std::env::temp_dir().join(format!("lanshare_test_open_{}.log", std::process::id()));
        let res = open_file_in_default_app(&temp_file);
        assert!(res.is_ok());
        let _ = std::fs::remove_file(temp_file);
    }

    #[test]
    fn test_open_url_validates_scheme() {
        assert!(open_url(GITHUB_REPO_URL).is_ok());
        assert!(open_url(GITHUB_RELEASES_URL).is_ok());
        assert!(open_url("http://example.com").is_ok());
        assert!(open_url("file:///etc/passwd").is_err());
        assert!(open_url("javascript:alert(1)").is_err());
    }

    #[tokio::test]
    async fn test_folder_small_files_progress_and_estimates() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

        let temp_dir =
            std::env::temp_dir().join(format!("lanshare_mock_folder_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let entry = FileEntry {
            name: "Games_Patches".to_string(),
            is_dir: true,
            size: 0,
            modified_timestamp: 0,
        };

        let target_dir = temp_dir.clone();
        let handle = tokio::spawn(async move {
            simulate_mock_download(
                "mock://gaming-pc",
                entry,
                "Games_Patches".to_string(),
                target_dir,
                tx,
                cancel_rx,
            )
            .await
        });

        let mut received_progress = Vec::new();
        while let Some(prog) = rx.recv().await {
            received_progress.push(prog);
        }

        let res = handle.await.unwrap();
        assert!(res.is_ok());

        // Verify that cumulative folder bytes were reported
        assert!(!received_progress.is_empty());
        let last = received_progress.last().unwrap();
        assert!(last.is_finished);
        assert!(last.bytes_total > 100 * 1024);
        assert_eq!(last.bytes_done, last.bytes_total);

        // Verify remaining seconds estimate works accurately on cumulative folder progress
        let mid = &received_progress[received_progress.len() / 2];
        let remaining_bytes = mid.bytes_total.saturating_sub(mid.bytes_done);
        let est = estimate_remaining_seconds(remaining_bytes, mid.speed_mbps);
        assert!(est.is_some());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mock_massive_small_files_folder() {
        let root = mock_directory_entries("mock://gaming-pc", "");
        assert!(root
            .iter()
            .any(|e| e.name == "Massive_Assets_25k_Files" && e.is_dir));

        let files = mock_directory_entries("mock://gaming-pc", "Massive_Assets_25k_Files");
        assert_eq!(files.len(), 25_000);
        assert_eq!(files[0].name, "asset_00001.bin");
        assert_eq!(files[24_999].name, "asset_25000.bin");
        assert!(!files[0].is_dir);

        // Huge files folder simulation in test mode
        assert!(root
            .iter()
            .any(|e| e.name == "Huge_Files_Archive" && e.is_dir));
        let huge_files = mock_directory_entries("mock://gaming-pc", "Huge_Files_Archive");
        assert_eq!(huge_files.len(), 4);
        assert!(huge_files
            .iter()
            .any(|f| f.name.contains(".iso") && f.size >= 4_000_000_000));
        assert!(huge_files
            .iter()
            .any(|f| f.name.contains(".vmdk") && f.size >= 80_000_000_000));
    }

    #[tokio::test]
    async fn test_mock_download_speed_restricted_for_huge_files() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

        let temp_dir =
            std::env::temp_dir().join(format!("lanshare_mock_huge_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let entry = FileEntry {
            name: "Linux_Enterprise_Server.iso".to_string(),
            is_dir: false,
            size: 4_700_000_000,
            modified_timestamp: 0,
        };

        let target_dir = temp_dir.clone();
        let handle = tokio::spawn(async move {
            simulate_mock_download(
                "mock://gaming-pc",
                entry,
                "".to_string(),
                target_dir,
                tx,
                cancel_rx,
            )
            .await
        });

        let mut reports = Vec::new();
        while let Some(prog) = rx.recv().await {
            reports.push(prog);
        }

        let res = handle.await.unwrap();
        assert!(res.is_ok());
        assert!(!reports.is_empty());
        let last = reports.last().unwrap();
        assert!(last.is_finished);
        assert_eq!(last.bytes_done, 4_700_000_000);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    fn make_mock_test_server_handle(
        folders: Vec<std::path::PathBuf>,
    ) -> (
        crate::server::ServerHandle,
        tokio::sync::mpsc::UnboundedReceiver<crate::server::ServerLogEvent>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let (stop_sender, stop_rx) = tokio::sync::oneshot::channel();
        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
        let (registry_notify_tx, _) = tokio::sync::watch::channel(0u64);
        let registry = std::sync::Arc::new(std::sync::RwLock::new(
            crate::server::SharedFolderRegistry::new(folders.clone()),
        ));
        let handle = crate::server::ServerHandle {
            is_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            local_ip: "127.0.0.1".to_string(),
            all_ips: vec!["127.0.0.1".to_string()],
            port: 18080,
            password: "secret".to_string(),
            stop_sender,
            shared_folders: std::sync::Arc::new(std::sync::RwLock::new(folders)),
            duration_hours: None,
            registry,
            log_tx,
            active_downloads: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            active_folder_downloads: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            registry_notify_tx,
        };
        (handle, log_rx, stop_rx)
    }

    #[tokio::test]
    async fn test_mock_server_downloads_emit_logs_and_balance_active_counts() {
        let music = std::path::PathBuf::from("/virtual_shares/Music");
        let photos = std::path::PathBuf::from("/virtual_shares/Photos");
        let (handle, mut log_rx, _stop_rx) =
            make_mock_test_server_handle(vec![music.clone(), photos.clone()]);

        let active_total = handle.active_downloads.clone();
        let active_by_folder = handle.active_folder_downloads.clone();

        let cfg = MockDownloadConfig {
            initial_delay: std::time::Duration::from_millis(5),
            transfer_duration: std::time::Duration::from_millis(40),
            between_delay: std::time::Duration::from_millis(5),
            max_events: Some(2),
            simulate_interruptions: false,
            interruption_delay: std::time::Duration::from_millis(10),
        };
        let task = tokio::spawn(run_mock_server_downloads(&handle, cfg));

        let mut events = Vec::new();
        while let Some(ev) = log_rx.recv().await {
            if ev.message.contains("started downloading") {
                assert_eq!(active_total.load(std::sync::atomic::Ordering::Relaxed), 1);
                let map = active_by_folder.read().unwrap();
                assert_eq!(map.values().sum::<usize>(), 1);
            }
            events.push(ev);
            if events.len() == 4 {
                break;
            }
        }
        task.await.unwrap();

        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|e| !e.is_error));
        assert!(events[0].message.contains(
            "Alice-Laptop (192.168.1.42) started downloading 'Music/vacation_highlights.mp4'"
        ));
        assert!(events[1].message.contains(
            "Alice-Laptop (192.168.1.42) finished downloading 'Music/vacation_highlights.mp4'"
        ));
        assert!(events[2]
            .message
            .contains("Bob-Deck (192.168.1.77) started downloading 'Photos/party_playlist.zip'"));
        assert!(events[3]
            .message
            .contains("Bob-Deck (192.168.1.77) finished downloading 'Photos/party_playlist.zip'"));
        for ev in &events {
            assert_eq!(ev.timestamp.len(), 19, "expected YYYY-MM-DD HH:MM:SS");
            assert!(ev.timestamp.contains('-'));
            assert!(ev.timestamp.contains(' '));
            assert!(ev.timestamp.contains(':'));
        }

        assert_eq!(
            handle
                .active_downloads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert!(handle.active_folder_downloads.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_mock_server_downloads_abort_when_server_stops() {
        let share = std::path::PathBuf::from("/virtual_shares/Docs");
        let (handle, mut log_rx, _stop_rx) = make_mock_test_server_handle(vec![share]);

        let cfg = MockDownloadConfig {
            initial_delay: std::time::Duration::from_millis(5),
            transfer_duration: std::time::Duration::from_millis(2000),
            between_delay: std::time::Duration::from_millis(5),
            max_events: None,
            simulate_interruptions: false,
            interruption_delay: std::time::Duration::from_millis(10),
        };
        let task = tokio::spawn(run_mock_server_downloads(&handle, cfg));

        let start_ev = log_rx.recv().await.unwrap();
        assert!(start_ev.message.contains("started downloading 'Docs/"));
        assert!(!start_ev.is_error);

        handle
            .is_running
            .store(false, std::sync::atomic::Ordering::Relaxed);

        let abort_ev = log_rx.recv().await.unwrap();
        assert!(abort_ev
            .message
            .contains("Server stopped: aborted download stream of 'Docs/"));
        assert!(abort_ev.is_error);

        task.await.unwrap();
        assert_eq!(
            handle
                .active_downloads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn test_mock_server_downloads_abort_when_share_removed() {
        let share = std::path::PathBuf::from("/virtual_shares/Videos");
        let (handle, mut log_rx, _stop_rx) = make_mock_test_server_handle(vec![share]);

        let cfg = MockDownloadConfig {
            initial_delay: std::time::Duration::from_millis(5),
            transfer_duration: std::time::Duration::from_millis(2000),
            between_delay: std::time::Duration::from_millis(5),
            max_events: Some(1),
            simulate_interruptions: false,
            interruption_delay: std::time::Duration::from_millis(10),
        };
        let task = tokio::spawn(run_mock_server_downloads(&handle, cfg));

        let start_ev = log_rx.recv().await.unwrap();
        assert!(start_ev.message.contains("started downloading 'Videos/"));

        handle.shared_folders.write().unwrap().clear();
        let _ = handle.registry_notify_tx.send(1);

        let abort_ev = log_rx.recv().await.unwrap();
        assert!(abort_ev
            .message
            .contains("Share removed: aborted download stream of 'Videos/"));
        assert!(abort_ev.is_error);

        task.await.unwrap();
        assert_eq!(
            handle
                .active_downloads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn test_mock_client_download_simulates_outage_resume_and_cancel() {
        let temp_dir =
            std::env::temp_dir().join(format!("lanshare_mock_outage_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let entry = FileEntry {
            name: "Games_Patches".to_string(),
            is_dir: true,
            size: 0,
            modified_timestamp: 0,
        };
        let cfg = MockClientDownloadConfig {
            step_sleep_ms: 1,
            batch_sleep_ms: 1,
            simulate_interruptions: true,
            outage_retry_delays: [Duration::from_millis(5), Duration::from_millis(5)],
        };

        let dest1 = temp_dir.clone();
        let res = simulate_mock_download_with_config(
            "mock://gaming-pc",
            entry.clone(),
            "Games_Patches".to_string(),
            dest1,
            tx,
            cancel_rx,
            cfg,
        )
        .await;
        assert!(res.is_ok());

        let mut saw_interrupted = false;
        let mut saw_waiting = false;
        let mut saw_reconnected = false;
        let mut last_finished = false;
        while let Ok(p) = rx.try_recv() {
            if p.file_name.starts_with("Network interrupted") {
                saw_interrupted = true;
                assert!(is_transfer_waiting_status(&p.file_name));
                assert_eq!(p.speed_mbps, 0.0);
            }
            if p.file_name.starts_with("Waiting for network/host") {
                saw_waiting = true;
                assert!(is_transfer_waiting_status(&p.file_name));
            }
            if let Some(ref msg) = p.log_message {
                if msg.contains("Reconnected to 'mock://gaming-pc'") {
                    saw_reconnected = true;
                }
            }
            last_finished = p.is_finished;
        }
        assert!(saw_interrupted);
        assert!(saw_waiting);
        assert!(saw_reconnected);
        assert!(last_finished);

        // Cancel during simulated outage aborts promptly
        let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
        let (cancel_tx2, cancel_rx2) = tokio::sync::watch::channel(false);
        let cfg_slow_outage = MockClientDownloadConfig {
            step_sleep_ms: 1,
            batch_sleep_ms: 1,
            simulate_interruptions: true,
            outage_retry_delays: [Duration::from_secs(10), Duration::from_secs(10)],
        };
        let dest2 = temp_dir.join("cancel_run");
        std::fs::create_dir_all(&dest2).unwrap();
        let handle = tokio::spawn(simulate_mock_download_with_config(
            "mock://gaming-pc",
            entry,
            "Games_Patches".to_string(),
            dest2,
            tx2,
            cancel_rx2,
            cfg_slow_outage,
        ));

        while let Some(p) = rx2.recv().await {
            if is_transfer_waiting_status(&p.file_name) {
                let _ = cancel_tx2.send(true);
                break;
            }
        }
        let err = handle.await.unwrap().unwrap_err();
        assert!(err.contains("cancelled by user"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_mock_server_downloads_simulate_network_interruption_and_resume() {
        let music = std::path::PathBuf::from("/virtual_shares/Music");
        let (handle, mut log_rx, _stop_rx) = make_mock_test_server_handle(vec![music]);

        let cfg = MockDownloadConfig {
            initial_delay: std::time::Duration::from_millis(5),
            transfer_duration: std::time::Duration::from_millis(20),
            between_delay: std::time::Duration::from_millis(5),
            max_events: Some(2),
            simulate_interruptions: true,
            interruption_delay: std::time::Duration::from_millis(10),
        };
        let task = tokio::spawn(run_mock_server_downloads(&handle, cfg));

        let mut events = Vec::new();
        while let Some(ev) = log_rx.recv().await {
            events.push(ev);
            if events.len() == 6 {
                break;
            }
        }
        task.await.unwrap();

        assert_eq!(events.len(), 6);
        assert!(events[0].message.contains("started downloading"));
        assert!(events[1].message.contains("finished downloading"));
        assert!(events[2].message.contains("started downloading"));
        assert!(events[3]
            .message
            .contains("network interrupted while downloading"));
        assert!(events[3].is_error);
        assert!(events[4].message.contains("reconnected and resumed"));
        assert!(!events[4].is_error);
        assert!(events[5].message.contains("finished downloading"));
        assert_eq!(
            handle
                .active_downloads
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn test_shared_peer_sort_and_queue_helpers() {
        let mut peers = vec![
            DiscoveredPeer {
                host_name: "zebra".to_string(),
                ip: "10.0.0.2".to_string(),
                port: DEFAULT_TCP_PORT,
                last_seen: Instant::now(),
            },
            DiscoveredPeer {
                host_name: "Alpha".to_string(),
                ip: "10.0.0.1".to_string(),
                port: DEFAULT_TCP_PORT,
                last_seen: Instant::now(),
            },
        ];
        sort_peers_alphabetically(&mut peers);
        assert_eq!(peers[0].host_name, "Alpha");
        assert_eq!(peers[1].host_name, "zebra");

        assert!(
            queue_status_sort_rank(&QueueItemStatus::Downloading)
                < queue_status_sort_rank(&QueueItemStatus::Pending)
        );
        assert!(
            queue_status_sort_rank(&QueueItemStatus::Pending)
                < queue_status_sort_rank(&QueueItemStatus::Failed("err".to_string()))
        );
        assert!(
            queue_status_sort_rank(&QueueItemStatus::Failed("err".to_string()))
                < queue_status_sort_rank(&QueueItemStatus::Completed)
        );

        let mut queue = VecDeque::new();
        queue.push_back(QueuedDownloadItem {
            id: 7,
            peer_name: "Alpha".to_string(),
            conn_ctx: ConnectionContext {
                ip: "10.0.0.1".to_string(),
                port: DEFAULT_TCP_PORT,
                password: "test-secret-value".to_string(),
                peer_name: Some("Alpha".to_string()),
            },
            is_mock: true,
            entry: FileEntry {
                name: "Bundle".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: 0,
            },
            remote_subpath: "Bundle".to_string(),
            local_dest_dir: PathBuf::from("."),
            status: QueueItemStatus::Downloading,
            started_at: Some(Instant::now()),
            elapsed_duration: None,
            completed_at: None,
            total_bytes: None,
        });
        let mut active_id = Some(7);
        let (tx, _rx) = tokio::sync::watch::channel(false);
        let mut cancel_tx = Some(tx);
        assert!(has_active_client_downloads(None, active_id, &queue));

        let prog = TransferProgress {
            selected_target: "Bundle".to_string(),
            file_name: "Bundle".to_string(),
            bytes_done: 1024,
            bytes_total: 2048,
            speed_mbps: 1.0,
            is_finished: false,
            current_file: 1,
            total_files: 1,
            log_message: None,
        };
        let info = complete_queued_download(
            &mut queue,
            &mut active_id,
            &mut cancel_tx,
            Some(&prog),
            7,
            &Ok(()),
        );
        assert_eq!(info.item_name, "Bundle");
        assert!(!info.cancelled);
        assert!(info.error.is_none());
        assert_eq!(active_id, None);
        assert!(cancel_tx.is_none());
        assert_eq!(queue[0].status, QueueItemStatus::Completed);
        assert_eq!(queue[0].total_bytes, Some(2048));
        assert!(queue[0].completed_at.is_some());
        assert!(!has_active_client_downloads(None, active_id, &queue));

        queue[0].status = QueueItemStatus::Downloading;
        let cancel_info = complete_queued_download(
            &mut queue,
            &mut active_id,
            &mut cancel_tx,
            None,
            7,
            &Err("Transfer cancelled by user.".to_string()),
        );
        assert!(cancel_info.cancelled);
        assert!(queue.is_empty());

        // Even if the item was already removed by the UI before QueueItemFinished arrives,
        // `cancelled` and `error` must still reflect `result`.
        let already_removed_cancel = complete_queued_download(
            &mut queue,
            &mut active_id,
            &mut cancel_tx,
            None,
            99,
            &Err("Transfer cancelled by user.".to_string()),
        );
        assert!(already_removed_cancel.cancelled);
        assert!(already_removed_cancel.error.is_none());

        let already_removed_err = complete_queued_download(
            &mut queue,
            &mut active_id,
            &mut cancel_tx,
            None,
            99,
            &Err("Disk full".to_string()),
        );
        assert!(!already_removed_err.cancelled);
        assert_eq!(already_removed_err.error.as_deref(), Some("Disk full"));
    }
}
