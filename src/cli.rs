use crate::client::{self, ConnectionContext, TransferProgress};
use crate::core::{
    default_mock_peers, dirs_fallback, estimate_remaining_seconds, execute_queued_download,
    format_file_size, format_remaining_time, mock_directory_entries, read_secret_from_env,
    read_secret_from_stdin, run_mock_server_downloads, test_downloads_dir, validate_cli_secret,
    MockDownloadConfig, QueueItemStatus, QueuedDownloadItem,
};
use crate::protocol::{FileEntry, DEFAULT_TCP_PORT, MIN_SECRET_LEN};
use crate::security::{clean_display_path, ensure_safe_client_dir, validate_shared_folder};
use crate::server::{self, ServerLogEvent};
use chrono::{Local, TimeZone};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

static CLI_INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigint(_sig: libc::c_int) {
    CLI_INTERRUPTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    CLI_INTERRUPTED.store(false, Ordering::SeqCst);
    // SAFETY: `handle_sigint` is an async-signal-safe `extern "C"` function that only
    // stores `true` into a static `AtomicBool`.
    unsafe {
        let _ = libc::signal(
            libc::SIGINT,
            handle_sigint as *const () as libc::sighandler_t,
        );
        #[cfg(unix)]
        {
            let _ = libc::signal(
                libc::SIGTERM,
                handle_sigint as *const () as libc::sighandler_t,
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliInvocation {
    Help,
    Version,
    Tui {
        test_mode: bool,
        autostart: bool,
        secret: Option<String>,
        host_folders: Vec<PathBuf>,
    },
    Host {
        secret: Option<String>,
        folders: Vec<PathBuf>,
        test_mode: bool,
    },
    Peers {
        secret: Option<String>,
        test_mode: bool,
    },
    List {
        secret: Option<String>,
        peer: String,
        remote_path: String,
        test_mode: bool,
    },
    Download {
        secret: Option<String>,
        peer: String,
        dest_dir: Option<PathBuf>,
        remote_paths: Vec<String>,
        test_mode: bool,
    },
}

pub fn expand_tilde_path(input: &str) -> PathBuf {
    let trimmed = input.trim();
    if trimmed == "~" {
        return dirs_fallback();
    }
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix(r"~\"))
    {
        return dirs_fallback().join(rest);
    }
    PathBuf::from(trimmed)
}

pub fn validate_remote_cli_path(raw: &str, allow_empty: bool) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.chars().any(|c| matches!(c, '*' | '?' | '[' | ']')) {
        return Err(format!(
            "Wildcards are not supported ('{}'). Specify exact file or folder paths.",
            trimmed
        ));
    }
    let clean = trimmed.trim_matches(['/', '\\']).replace('\\', "/");
    if clean.is_empty() {
        if allow_empty {
            return Ok(String::new());
        }
        return Err("Remote path cannot be empty.".to_string());
    }
    for seg in clean.split('/') {
        let s = seg.trim();
        if s.is_empty() || s == "." || s == ".." {
            return Err(format!(
                "Invalid remote path '{}': traversal ('..') and empty segments are not allowed.",
                raw
            ));
        }
    }
    Ok(clean)
}

pub fn resolve_cli_secret(explicit_secret: Option<String>) -> Result<String, String> {
    if let Some(s) = explicit_secret {
        return validate_cli_secret(s);
    }
    if let Ok(env_val) = std::env::var("LANSHARE_SECRET") {
        if !env_val.trim().is_empty() {
            return validate_cli_secret(env_val);
        }
    }
    eprint!("Enter Share-Ring secret (min {} chars): ", MIN_SECRET_LEN);
    let _ = std::io::stderr().flush();
    read_secret_from_stdin()
}

pub fn format_cli_help() -> String {
    format!(
        "LanShare CLI & TUI (lanshare-cli) — Encrypted zero-config LAN folder sharing powered by Share-Ring\n\
\n\
USAGE:\n\
  lanshare-cli [TUI_OPTIONS]\n\
  lanshare-cli tui [TUI_OPTIONS]\n\
  lanshare-cli host <FOLDER>...\n\
  lanshare-cli peers\n\
  lanshare-cli ls --peer <HOSTNAME_OR_IP> [REMOTE_PATH]\n\
  lanshare-cli download --peer <HOSTNAME_OR_IP> [-d <DEST_DIR>] <REMOTE_PATH>...\n\
\n\
COMMANDS:\n\
  tui                   Launch the interactive Terminal UI (default when no command is given)\n\
  host, share           Share one or more local folders read-only and print live server logs to terminal\n\
  peers, scan           Discover and list active hosts on the Share-Ring\n\
  ls, list              List shared folders or directory contents on a remote host\n\
  download, get         Download one or more files or folders from a remote host (no wildcards)\n\
\n\
SECRET OPTIONS (prompts for secret on stdin by default if omitted and LANSHARE_SECRET is not set):\n\
  --secret-stdin              Prompt / read Share-Ring secret from standard input (default; min {min_len} chars)\n\
  --secret-env <VAR>          Read Share-Ring secret from environment variable (min {min_len} chars)\n\
  -s, --secret <SECRET>       Pass Share-Ring secret directly (min {min_len} chars)\n\
\n\
CLIENT OPTIONS (for `ls` and `download`):\n\
  -p, --peer <HOST_OR_IP>     Target host name or IP address (required for `ls` and `download`)\n\
  -d, --dest <DIR>            Local destination directory for `download` (default: current directory `.`)\n\
\n\
GENERAL & TUI OPTIONS:\n\
  --test, --mock              Use simulated LAN peers / simulated friend downloads\n\
  --host <FOLDER>             (TUI mode) Pre-add a local folder to the Host tab (can be passed multiple times)\n\
  --autostart                 (TUI mode) Automatically start Read-Only hosting on startup (with --host)\n\
  -V, --version               Print version information\n\
  -h, --help                  Print this help message",
        min_len = MIN_SECRET_LEN
    )
}

pub fn parse_cli_args(args: &[String]) -> Result<CliInvocation, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(CliInvocation::Help);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        return Ok(CliInvocation::Version);
    }

    let first = args.first().map(|s| s.as_str());
    let (subcmd, rest) = match first {
        Some("tui") => (Some("tui"), &args[1..]),
        Some("host" | "share") => (Some("host"), &args[1..]),
        Some("peers" | "scan") => (Some("peers"), &args[1..]),
        Some("ls" | "list") => (Some("ls"), &args[1..]),
        Some("download" | "get") => (Some("download"), &args[1..]),
        _ => (None, args),
    };

    if subcmd.is_none() || subcmd == Some("tui") {
        return parse_tui_args(rest);
    }

    let mut test_mode = false;
    let mut secret: Option<String> = None;
    let mut peer: Option<String> = None;
    let mut dest_dir: Option<PathBuf> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut extra_folders: Vec<PathBuf> = Vec::new();

    let mut idx = 0;
    let mut positional_only = false;
    while idx < rest.len() {
        let arg = &rest[idx];
        if positional_only {
            positionals.push(arg.clone());
            idx += 1;
            continue;
        }
        match arg.as_str() {
            "--" => {
                positional_only = true;
            }
            "--test" | "--mock" => {
                test_mode = true;
            }
            "--secret-env" => {
                idx += 1;
                let Some(var_name) = rest.get(idx) else {
                    return Err("--secret-env requires a variable name.".to_string());
                };
                secret = Some(read_secret_from_env(var_name)?);
            }
            "--secret-stdin" => {
                secret = None;
            }
            "-s" | "--secret" => {
                idx += 1;
                let Some(val) = rest.get(idx) else {
                    return Err(format!("{} requires a secret value.", arg));
                };
                secret = Some(validate_cli_secret(val.clone())?);
            }
            "-p" | "--peer" | "--ip" => {
                idx += 1;
                let Some(val) = rest.get(idx) else {
                    return Err(format!("{} requires a hostname or IP address.", arg));
                };
                let trimmed = val.trim().to_string();
                if trimmed.is_empty() {
                    return Err("Peer hostname or IP address cannot be empty.".to_string());
                }
                peer = Some(trimmed);
            }
            "-d" | "--dest" | "-o" | "--output" => {
                if subcmd != Some("download") {
                    return Err(format!(
                        "Option '{}' is only supported with the 'download' command.",
                        arg
                    ));
                }
                idx += 1;
                let Some(val) = rest.get(idx) else {
                    return Err(format!("{} requires a destination directory path.", arg));
                };
                if val.trim().is_empty() {
                    return Err("Destination directory path cannot be empty.".to_string());
                }
                dest_dir = Some(expand_tilde_path(val));
            }
            "-f" | "--folder" | "--host" => {
                if subcmd != Some("host") {
                    return Err(format!(
                        "Option '{}' is only supported with the 'host' command.",
                        arg
                    ));
                }
                idx += 1;
                let Some(val) = rest.get(idx) else {
                    return Err(format!("{} requires a folder path.", arg));
                };
                extra_folders.push(expand_tilde_path(val));
            }
            unknown if unknown.starts_with('-') => {
                return Err(format!(
                    "Unknown option '{}'. Run with --help for usage.",
                    unknown
                ));
            }
            pos => {
                positionals.push(pos.to_string());
            }
        }
        idx += 1;
    }

    let resolved_secret = match secret {
        Some(s) => Some(validate_cli_secret(s)?),
        None => None,
    };

    match subcmd {
        Some("host") => {
            if peer.is_some() {
                return Err("--peer is not valid with the 'host' command.".to_string());
            }
            let mut folders = extra_folders;
            for p in positionals {
                folders.push(expand_tilde_path(&p));
            }
            if folders.is_empty() {
                return Err(
                    "At least one folder path is required for 'host' (e.g. `lanshare-cli host <FOLDER>...`)."
                        .to_string(),
                );
            }
            Ok(CliInvocation::Host {
                secret: resolved_secret,
                folders,
                test_mode,
            })
        }
        Some("peers") => {
            if !positionals.is_empty() {
                return Err(format!(
                    "Unexpected argument '{}' for 'peers' command.",
                    positionals[0]
                ));
            }
            Ok(CliInvocation::Peers {
                secret: resolved_secret,
                test_mode,
            })
        }
        Some("ls") => {
            let Some(peer_str) = peer else {
                return Err(
                    "--peer <HOSTNAME_OR_IP> is required for 'ls'. Run `lanshare-cli peers` to discover hosts."
                        .to_string(),
                );
            };
            if positionals.len() > 1 {
                return Err("'ls' accepts at most one remote directory path argument.".to_string());
            }
            let remote_path = match positionals.first() {
                Some(raw) => validate_remote_cli_path(raw, true)?,
                None => String::new(),
            };
            Ok(CliInvocation::List {
                secret: resolved_secret,
                peer: peer_str,
                remote_path,
                test_mode,
            })
        }
        Some("download") => {
            let Some(peer_str) = peer else {
                return Err(
                    "--peer <HOSTNAME_OR_IP> is required for 'download'. Run `lanshare-cli peers` to discover hosts."
                        .to_string(),
                );
            };
            if positionals.is_empty() {
                return Err(
                    "At least one remote file or folder path is required for 'download'."
                        .to_string(),
                );
            }
            let mut clean_paths = Vec::with_capacity(positionals.len());
            for raw in &positionals {
                clean_paths.push(validate_remote_cli_path(raw, false)?);
            }
            Ok(CliInvocation::Download {
                secret: resolved_secret,
                peer: peer_str,
                dest_dir,
                remote_paths: clean_paths,
                test_mode,
            })
        }
        _ => unreachable!(),
    }
}

fn parse_tui_args(args: &[String]) -> Result<CliInvocation, String> {
    let mut test_mode = false;
    let mut autostart = false;
    let mut secret: Option<String> = None;
    let mut host_folders: Vec<PathBuf> = Vec::new();

    let mut idx = 0;
    while idx < args.len() {
        let arg = &args[idx];
        match arg.as_str() {
            "--test" | "--mock" => test_mode = true,
            "--autostart" => autostart = true,
            "--secret-env" => {
                idx += 1;
                let Some(var_name) = args.get(idx) else {
                    return Err("--secret-env requires a variable name.".to_string());
                };
                secret = Some(read_secret_from_env(var_name)?);
            }
            "--secret-stdin" => {
                secret = Some(read_secret_from_stdin()?);
            }
            "-s" | "--secret" => {
                idx += 1;
                let Some(val) = args.get(idx) else {
                    return Err(format!("{} requires a secret value.", arg));
                };
                secret = Some(validate_cli_secret(val.clone())?);
            }
            "--host" => {
                idx += 1;
                let Some(folder) = args.get(idx) else {
                    return Err("--host requires a folder path.".to_string());
                };
                host_folders.push(expand_tilde_path(folder));
            }
            unknown => {
                return Err(format!(
                    "Unknown option '{}'. Run with --help for usage.",
                    unknown
                ));
            }
        }
        idx += 1;
    }

    Ok(CliInvocation::Tui {
        test_mode,
        autostart,
        secret,
        host_folders,
    })
}

fn now_ts() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn format_modified_time(modified_timestamp: u64) -> String {
    if modified_timestamp == 0 {
        return "-".to_string();
    }
    match Local.timestamp_opt(modified_timestamp as i64, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => "-".to_string(),
    }
}

#[derive(Debug, Clone)]
enum ResolvedPeerTarget {
    Mock { host_name: String, mock_ip: String },
    Network { ip: String, port: u16 },
}

async fn resolve_peer_target<W: Write>(
    peer_arg: &str,
    default_port: u16,
    secret: &str,
    test_mode: bool,
    out: &mut W,
) -> Result<ResolvedPeerTarget, String> {
    let trimmed = peer_arg.trim();
    if trimmed.is_empty() {
        return Err("Peer hostname or IP address cannot be empty.".to_string());
    }

    // 1. Check simulated peers when in --test / --mock mode
    if test_mode || trimmed.starts_with("mock://") {
        let lower = trimmed.to_lowercase();
        if lower == "mock://alice-laptop"
            || lower == "alice-laptop"
            || lower == "alice-laptop (test mode)"
            || lower == "alice"
        {
            return Ok(ResolvedPeerTarget::Mock {
                host_name: "Alice-Laptop (Test Mode)".to_string(),
                mock_ip: "mock://alice-laptop".to_string(),
            });
        }
        if lower == "mock://gaming-pc"
            || lower == "mock-gaming-pc"
            || lower == "mock-gaming-pc (test mode)"
            || lower == "gaming-pc"
        {
            return Ok(ResolvedPeerTarget::Mock {
                host_name: "Mock-Gaming-PC (Test Mode)".to_string(),
                mock_ip: "mock://gaming-pc".to_string(),
            });
        }
    }

    // 2. Check if peer_arg is an explicit IP or IP:port
    if let Ok(sock_addr) = trimmed.parse::<std::net::SocketAddr>() {
        return Ok(ResolvedPeerTarget::Network {
            ip: sock_addr.ip().to_string(),
            port: sock_addr.port(),
        });
    }
    if let Ok(ip_addr) = trimmed.parse::<IpAddr>() {
        return Ok(ResolvedPeerTarget::Network {
            ip: ip_addr.to_string(),
            port: default_port,
        });
    }

    // 3. Peer is specified by hostname: scan LAN for matching Share-Ring peer first
    let _ = writeln!(
        out,
        "[{}] [Client] Resolving peer '{}' on Share-Ring...",
        now_ts(),
        trimmed
    );
    let peers = client::scan_lan_for_hosts(Duration::from_millis(1500), Some(secret)).await;
    if let Some(found) = peers
        .iter()
        .find(|p| p.host_name.eq_ignore_ascii_case(trimmed))
    {
        let _ = writeln!(
            out,
            "[{}] [Client] Resolved '{}' -> {}",
            now_ts(),
            found.host_name,
            found.ip
        );
        return Ok(ResolvedPeerTarget::Network {
            ip: found.ip.clone(),
            port: found.port,
        });
    }

    // Fall back to direct hostname connection if not seen in UDP scan
    Ok(ResolvedPeerTarget::Network {
        ip: trimmed.to_string(),
        port: default_port,
    })
}

/// Runs the `peers` / `scan` CLI command and prints all output to `out`.
pub async fn run_cli_peers<W: Write>(
    secret: &str,
    test_mode: bool,
    out: &mut W,
) -> Result<(), String> {
    let _ = writeln!(
        out,
        "[{}] [Client] Scanning local network for Share-Ring peers...",
        now_ts()
    );
    let mut peers = client::scan_lan_for_hosts(Duration::from_millis(1500), Some(secret)).await;
    if test_mode {
        for mp in default_mock_peers() {
            if !peers.iter().any(|p| p.ip == mp.ip) {
                peers.push(mp);
            }
        }
    }
    peers.sort_by_key(|a| a.host_name.to_lowercase());

    if peers.is_empty() {
        let _ = writeln!(
            out,
            "[{}] [Client] No active peers found on the Share-Ring.",
            now_ts()
        );
        return Ok(());
    }

    let _ = writeln!(out, "{:<36} IP ADDRESS", "HOSTNAME");
    let _ = writeln!(out, "{}", "-".repeat(56));
    for p in &peers {
        let _ = writeln!(out, "{:<36} {}", p.host_name, p.ip);
    }
    let _ = writeln!(out, "{}", "-".repeat(56));
    let _ = writeln!(out, "Found {} peer(s).", peers.len());
    Ok(())
}

async fn fetch_remote_listing_with_single_share_fallback(
    stream: &mut client::ClientTlsStream,
    remote_path: &str,
) -> Result<(String, Vec<FileEntry>), String> {
    match client::request_directory_listing(stream, remote_path).await {
        Ok(entries) => Ok((remote_path.to_string(), entries)),
        Err(first_err) => {
            if !remote_path.is_empty() {
                if let Ok(root_entries) = client::request_directory_listing(stream, "").await {
                    if root_entries.len() == 1 && root_entries[0].is_dir {
                        let root_share = &root_entries[0].name;
                        if !remote_path.starts_with(&format!("{}/", root_share))
                            && remote_path != root_share
                        {
                            let prefixed = format!("{}/{}", root_share, remote_path);
                            if let Ok(entries) =
                                client::request_directory_listing(stream, &prefixed).await
                            {
                                return Ok((prefixed, entries));
                            }
                        }
                    }
                }
            }
            Err(first_err)
        }
    }
}

fn write_directory_listing_table<W: Write>(
    out: &mut W,
    host_label: &str,
    display_path: &str,
    entries: &[FileEntry],
) {
    let formatted_path = if display_path.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", display_path)
    };
    let _ = writeln!(out, "Listing for '{}' — {}:", host_label, formatted_path);
    let _ = writeln!(
        out,
        "{:<6}  {:>10}  {:<16}  NAME",
        "TYPE", "SIZE", "MODIFIED"
    );
    let _ = writeln!(out, "{}", "-".repeat(68));

    if entries.is_empty() {
        let _ = writeln!(out, "(This directory is empty)");
    } else {
        for entry in entries {
            let kind = if entry.is_dir { "DIR" } else { "FILE" };
            let size_str = if entry.is_dir {
                "<DIR>".to_string()
            } else {
                format_file_size(entry.size)
            };
            let mod_str = format_modified_time(entry.modified_timestamp);
            let name_str = if entry.is_dir {
                format!("{}/", entry.name)
            } else {
                entry.name.clone()
            };
            let _ = writeln!(
                out,
                "{:<6}  {:>10}  {:<16}  {}",
                kind, size_str, mod_str, name_str
            );
        }
    }

    let dir_count = entries.iter().filter(|e| e.is_dir).count();
    let file_count = entries.len().saturating_sub(dir_count);
    let _ = writeln!(out, "{}", "-".repeat(68));
    let _ = writeln!(
        out,
        "{} item(s) ({} folder(s), {} file(s))",
        entries.len(),
        dir_count,
        file_count
    );
}

/// Runs the `ls` / `list` CLI command and prints all logs and the directory listing to `out`.
pub async fn run_cli_list<W: Write>(
    secret: &str,
    peer_arg: &str,
    port: u16,
    remote_path: &str,
    test_mode: bool,
    out: &mut W,
) -> Result<(), String> {
    let target = resolve_peer_target(peer_arg, port, secret, test_mode, out).await?;

    match target {
        ResolvedPeerTarget::Mock { host_name, mock_ip } => {
            let _ = writeln!(
                out,
                "[{}] [Client] Connected to '{}' ({}) [Read-Only]",
                now_ts(),
                host_name,
                mock_ip
            );
            let entries = mock_directory_entries(&mock_ip, remote_path);
            if !remote_path.is_empty() && entries.is_empty() {
                return Err(format!(
                    "Remote directory '/{}' not found or empty on '{}'.",
                    remote_path, host_name
                ));
            }
            write_directory_listing_table(out, &host_name, remote_path, &entries);
            Ok(())
        }
        ResolvedPeerTarget::Network {
            ip,
            port: target_port,
        } => {
            let _ = writeln!(out, "[{}] [Client] Connecting to {}...", now_ts(), ip);
            let (mut stream, resp) = client::connect_to_host(&ip, target_port, secret).await?;
            let _ = writeln!(
                out,
                "[{}] [Client] Connected to '{}' ({}) [Read-Only]",
                now_ts(),
                resp.server_name,
                ip
            );

            let res =
                fetch_remote_listing_with_single_share_fallback(&mut stream, remote_path).await;
            let _ = stream.shutdown().await;

            let (effective_path, entries) = res?;
            write_directory_listing_table(out, &resp.server_name, &effective_path, &entries);
            Ok(())
        }
    }
}

fn split_parent_and_name(clean_subpath: &str) -> (&str, &str) {
    match clean_subpath.rsplit_once('/') {
        Some((parent, name)) => (parent, name),
        None => ("", clean_subpath),
    }
}

async fn resolve_remote_entry_network(
    stream: &mut client::ClientTlsStream,
    requested_subpath: &str,
) -> Result<(String, FileEntry), String> {
    let (parent, target_name) = split_parent_and_name(requested_subpath);

    if let Ok(entries) = client::request_directory_listing(stream, parent).await {
        if let Some(entry) = entries.into_iter().find(|e| e.name == target_name) {
            return Ok((requested_subpath.to_string(), entry));
        }
    }

    // Convenience fallback when host shares a single root folder and caller omitted the share prefix
    if let Ok(root_entries) = client::request_directory_listing(stream, "").await {
        if root_entries.len() == 1 && root_entries[0].is_dir {
            let root_share = &root_entries[0].name;
            if !requested_subpath.starts_with(&format!("{}/", root_share))
                && requested_subpath != root_share
            {
                let prefixed_subpath = format!("{}/{}", root_share, requested_subpath);
                let (pref_parent, pref_name) = split_parent_and_name(&prefixed_subpath);
                if let Ok(entries) = client::request_directory_listing(stream, pref_parent).await {
                    if let Some(entry) = entries.into_iter().find(|e| e.name == pref_name) {
                        return Ok((prefixed_subpath, entry));
                    }
                }
            }
        }
    }

    Err(format!(
        "Remote path '{}' was not found on the host.",
        requested_subpath
    ))
}

fn resolve_remote_entry_mock(
    mock_ip: &str,
    requested_subpath: &str,
) -> Result<(String, FileEntry), String> {
    let (parent, target_name) = split_parent_and_name(requested_subpath);
    let entries = mock_directory_entries(mock_ip, parent);
    if let Some(entry) = entries.into_iter().find(|e| e.name == target_name) {
        return Ok((requested_subpath.to_string(), entry));
    }
    Err(format!(
        "Remote path '{}' was not found on simulated host '{}'.",
        requested_subpath, mock_ip
    ))
}

/// Validates local `--dest` directory and remote path syntax for `download`.
pub fn validate_cli_download_inputs(
    dest_dir: Option<&Path>,
    remote_paths: &[String],
    test_mode: bool,
) -> Result<(PathBuf, Vec<String>), String> {
    if remote_paths.is_empty() {
        return Err("At least one remote file or folder path is required.".to_string());
    }
    let mut validated_paths = Vec::with_capacity(remote_paths.len());
    for raw in remote_paths {
        validated_paths.push(validate_remote_cli_path(raw, false)?);
    }

    let resolved_dest = match dest_dir {
        Some(d) => d.to_path_buf(),
        None if test_mode => test_downloads_dir(),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    ensure_safe_client_dir(&resolved_dest)?;
    Ok((resolved_dest, validated_paths))
}

/// Runs the `download` / `get` CLI command: resolves all requested remote files/folders on the peer,
/// downloads them sequentially to `dest_dir` while printing live logs to `out`, and finishes.
pub async fn run_cli_download<W: Write>(
    secret: &str,
    peer_arg: &str,
    port: u16,
    dest_dir: Option<PathBuf>,
    remote_paths: &[String],
    test_mode: bool,
    out: &mut W,
) -> Result<(), String> {
    install_signal_handlers();

    let (resolved_dest, validated_paths) =
        validate_cli_download_inputs(dest_dir.as_deref(), remote_paths, test_mode)?;

    let target = resolve_peer_target(peer_arg, port, secret, test_mode, out).await?;

    let (peer_name, conn_ctx, is_mock, resolved_items) = match target {
        ResolvedPeerTarget::Mock { host_name, mock_ip } => {
            let _ = writeln!(
                out,
                "[{}] [Client] Connected to '{}' ({}) [Read-Only]",
                now_ts(),
                host_name,
                mock_ip
            );
            let mut items = Vec::with_capacity(validated_paths.len());
            for req_path in &validated_paths {
                let (subpath, entry) = resolve_remote_entry_mock(&mock_ip, req_path)?;
                items.push((subpath, entry));
            }
            let ctx = ConnectionContext::new(
                mock_ip,
                DEFAULT_TCP_PORT,
                secret.to_string(),
                Some(host_name.clone()),
            );
            (host_name, ctx, true, items)
        }
        ResolvedPeerTarget::Network {
            ip,
            port: target_port,
        } => {
            let _ = writeln!(out, "[{}] [Client] Connecting to {}...", now_ts(), ip);
            let (mut stream, resp) = client::connect_to_host(&ip, target_port, secret).await?;
            let host_name = resp.server_name.clone();
            let _ = writeln!(
                out,
                "[{}] [Client] Connected to '{}' ({}) [Read-Only]",
                now_ts(),
                host_name,
                ip
            );

            let mut items = Vec::with_capacity(validated_paths.len());
            for req_path in &validated_paths {
                match resolve_remote_entry_network(&mut stream, req_path).await {
                    Ok(item) => items.push(item),
                    Err(e) => {
                        let _ = stream.shutdown().await;
                        return Err(e);
                    }
                }
            }
            let _ = stream.shutdown().await;

            let ctx = ConnectionContext::new(
                ip,
                target_port,
                secret.to_string(),
                Some(host_name.clone()),
            );
            (host_name, ctx, false, items)
        }
    };

    let total_items = resolved_items.len();
    let _ = writeln!(
        out,
        "[{}] [Client] Saving {} item(s) to '{}'",
        now_ts(),
        total_items,
        clean_display_path(&resolved_dest)
    );

    for (idx, (remote_subpath, entry)) in resolved_items.into_iter().enumerate() {
        let item_num = idx + 1;
        let kind_label = if entry.is_dir { "folder" } else { "file" };
        let size_note = if entry.is_dir {
            String::new()
        } else {
            format!(" ({})", format_file_size(entry.size))
        };
        let _ = writeln!(
            out,
            "[{}] [Client] [{}/{}] Starting download of {} '{}'{}...",
            now_ts(),
            item_num,
            total_items,
            kind_label,
            remote_subpath,
            size_note
        );
        let _ = out.flush();

        let queue_item = QueuedDownloadItem {
            id: item_num as u64,
            peer_name: peer_name.clone(),
            conn_ctx: conn_ctx.clone(),
            is_mock,
            entry: entry.clone(),
            remote_subpath: remote_subpath.clone(),
            local_dest_dir: resolved_dest.clone(),
            status: QueueItemStatus::Downloading,
            started_at: Some(Instant::now()),
            elapsed_duration: None,
            completed_at: None,
            total_bytes: if entry.size > 0 {
                Some(entry.size)
            } else {
                None
            },
        };

        let (prog_tx, mut prog_rx) = tokio::sync::mpsc::unbounded_channel::<TransferProgress>();
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let started_at = Instant::now();

        let mut dl_task =
            tokio::spawn(
                async move { execute_queued_download(queue_item, prog_tx, cancel_rx).await },
            );

        let mut last_progress_print = Instant::now() - Duration::from_secs(2);
        let mut final_res: Option<Result<(), String>> = None;

        while final_res.is_none() {
            if CLI_INTERRUPTED.load(Ordering::SeqCst) {
                let _ = cancel_tx.send(true);
            }

            tokio::select! {
                res = &mut dl_task => {
                    final_res = Some(res.map_err(|e| format!("Download task panicked: {}", e))?);
                }
                maybe_prog = prog_rx.recv() => {
                    if let Some(prog) = maybe_prog {
                        log_transfer_progress(out, &prog, &mut last_progress_print);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }

        // Drain any remaining progress messages queued right before completion
        while let Ok(prog) = prog_rx.try_recv() {
            log_transfer_progress(out, &prog, &mut last_progress_print);
        }

        match final_res.unwrap() {
            Ok(()) => {
                let elapsed = started_at.elapsed();
                let took = if elapsed.as_secs() == 0 {
                    "< 1s".to_string()
                } else {
                    format_remaining_time(elapsed.as_secs())
                };
                let dest_target = resolved_dest.join(&entry.name);
                let _ = writeln!(
                    out,
                    "[{}] [Client] [{}/{}] Completed '{}' -> {} (took {})",
                    now_ts(),
                    item_num,
                    total_items,
                    entry.name,
                    clean_display_path(&dest_target),
                    took
                );
                let _ = out.flush();
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    let _ = writeln!(
        out,
        "[{}] [Client] All {} download(s) finished successfully.",
        now_ts(),
        total_items
    );
    let _ = out.flush();
    Ok(())
}

fn log_transfer_progress<W: Write>(
    out: &mut W,
    prog: &TransferProgress,
    last_progress_print: &mut Instant,
) {
    if let Some(ref msg) = prog.log_message {
        let _ = writeln!(out, "[{}] [Client] {}", now_ts(), msg);
        let _ = out.flush();
    } else if crate::core::is_transfer_waiting_status(&prog.file_name) {
        if last_progress_print.elapsed() >= Duration::from_secs(1) {
            let _ = writeln!(
                out,
                "[{}] [Client] [WAIT] {}: {}",
                now_ts(),
                prog.selected_target,
                prog.file_name
            );
            let _ = out.flush();
            *last_progress_print = Instant::now();
        }
    } else if !prog.is_finished
        && prog.bytes_total > 0
        && last_progress_print.elapsed() >= Duration::from_secs(1)
    {
        let pct = ((prog.bytes_done as f64 / prog.bytes_total as f64) * 100.0).clamp(0.0, 100.0);
        let rem_bytes = prog.bytes_total.saturating_sub(prog.bytes_done);
        let eta_str = estimate_remaining_seconds(rem_bytes, prog.speed_mbps)
            .map(|s| format!(", ETA: {}", format_remaining_time(s)))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "[{}] [Client] Progress '{}': {:.0}% ({} / {}) at {:.1} MB/s{}",
            now_ts(),
            prog.file_name,
            pct,
            format_file_size(prog.bytes_done),
            format_file_size(prog.bytes_total),
            prog.speed_mbps,
            eta_str
        );
        let _ = out.flush();
        *last_progress_print = Instant::now();
    }
}

/// Validates local folder paths to share before starting hosting or prompting for secrets.
pub fn validate_cli_host_folders(folders: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    if folders.is_empty() {
        return Err("At least one folder path is required to start hosting.".to_string());
    }

    let mut validated = Vec::with_capacity(folders.len());
    for f in folders {
        let safe = validate_shared_folder(f)?;
        if !validated.contains(&safe) {
            validated.push(safe);
        }
    }
    Ok(validated)
}

/// Runs the `host` / `share` CLI command in the foreground, printing all server logs directly
/// to `out` until interrupted (or until `max_duration` elapses in tests).
pub async fn run_cli_host<W: Write>(
    secret: &str,
    folders: &[PathBuf],
    test_mode: bool,
    max_duration: Option<Duration>,
    out: &mut W,
) -> Result<(), String> {
    install_signal_handlers();

    let validated = validate_cli_host_folders(folders)?;

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel::<ServerLogEvent>();
    let handle = server::start_server(validated.clone(), secret.to_string(), None, log_tx)
        .await
        .map_err(|e| e.to_string())?;

    let host_name = crate::network::get_computer_name();
    let _ = writeln!(
        out,
        "[{}] [Server] Hosting started on {} (Computer: '{}') [Read-Only]",
        now_ts(),
        handle.local_ip,
        host_name
    );
    for folder in &validated {
        let _ = writeln!(
            out,
            "[{}] [Server] Sharing folder (Read-Only): {}",
            now_ts(),
            clean_display_path(folder)
        );
    }
    let _ = writeln!(
        out,
        "[{}] [Server] Waiting for peers... Press Ctrl+C to stop sharing.",
        now_ts()
    );
    let _ = out.flush();

    if test_mode {
        tokio::spawn(run_mock_server_downloads(
            &handle,
            MockDownloadConfig::default(),
        ));
    }

    let start_instant = Instant::now();
    loop {
        if CLI_INTERRUPTED.load(Ordering::SeqCst) {
            let _ = writeln!(
                out,
                "[{}] [Server] Interrupt received — stopping server...",
                now_ts()
            );
            let _ = out.flush();
            break;
        }
        if let Some(max_dur) = max_duration {
            if start_instant.elapsed() >= max_dur {
                let _ = writeln!(
                    out,
                    "[{}] [Server] Stopping server (duration reached)...",
                    now_ts()
                );
                let _ = out.flush();
                break;
            }
        }
        if !handle.is_running.load(Ordering::Relaxed) {
            break;
        }

        tokio::select! {
            maybe_evt = log_rx.recv() => {
                if let Some(evt) = maybe_evt {
                    if evt.is_error {
                        let _ = writeln!(out, "[{}] [Server] [ERROR] {}", evt.timestamp, evt.message);
                    } else {
                        let _ = writeln!(out, "[{}] [Server] {}", evt.timestamp, evt.message);
                    }
                    let _ = out.flush();
                } else {
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    handle.is_running.store(false, Ordering::SeqCst);
    let _ = handle.stop_sender.send(());
    while let Ok(evt) = log_rx.try_recv() {
        if evt.is_error {
            let _ = writeln!(out, "[{}] [Server] [ERROR] {}", evt.timestamp, evt.message);
        } else {
            let _ = writeln!(out, "[{}] [Server] {}", evt.timestamp, evt.message);
        }
    }
    let _ = out.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_parse_cli_args_modes_and_validation() {
        // 1. Default (no subcommand) launches TUI
        let inv = parse_cli_args(&vec_args(&[])).unwrap();
        assert_eq!(
            inv,
            CliInvocation::Tui {
                test_mode: false,
                autostart: false,
                secret: None,
                host_folders: Vec::new(),
            }
        );

        // 2. Explicit `tui` subcommand launches TUI with flags
        let inv_tui = parse_cli_args(&vec_args(&["tui", "--test", "-s", "party-ring-42"])).unwrap();
        assert_eq!(
            inv_tui,
            CliInvocation::Tui {
                test_mode: true,
                autostart: false,
                secret: Some("party-ring-42".to_string()),
                host_folders: Vec::new(),
            }
        );

        // 3. `host` subcommand (with explicit secret and with default stdin prompt)
        let inv_host = parse_cli_args(&vec_args(&[
            "host",
            "-s",
            "party-ring-42",
            "/tmp/folder_a",
            "/tmp/folder_b",
        ]))
        .unwrap();
        assert_eq!(
            inv_host,
            CliInvocation::Host {
                secret: Some("party-ring-42".to_string()),
                folders: vec![
                    PathBuf::from("/tmp/folder_a"),
                    PathBuf::from("/tmp/folder_b")
                ],
                test_mode: false,
            }
        );

        let inv_host_default_stdin = parse_cli_args(&vec_args(&["host", "/tmp/folder_a"])).unwrap();
        assert_eq!(
            inv_host_default_stdin,
            CliInvocation::Host {
                secret: None,
                folders: vec![PathBuf::from("/tmp/folder_a")],
                test_mode: false,
            }
        );

        // 4. `ls` subcommand (root and nested path)
        let inv_ls_root = parse_cli_args(&vec_args(&["ls", "--peer", "Gaming-PC"])).unwrap();
        assert_eq!(
            inv_ls_root,
            CliInvocation::List {
                secret: None,
                peer: "Gaming-PC".to_string(),
                remote_path: String::new(),
                test_mode: false,
            }
        );

        let inv_ls_deep = parse_cli_args(&vec_args(&[
            "ls",
            "-s",
            "party-ring-42",
            "--peer",
            "192.168.1.50",
            "LAN_Party_Photos/Day_1",
        ]))
        .unwrap();
        assert_eq!(
            inv_ls_deep,
            CliInvocation::List {
                secret: Some("party-ring-42".to_string()),
                peer: "192.168.1.50".to_string(),
                remote_path: "LAN_Party_Photos/Day_1".to_string(),
                test_mode: false,
            }
        );

        // `ls` without --peer fails immediately
        assert!(parse_cli_args(&vec_args(&["ls"])).is_err());

        // 5. `download` subcommand with multiple files/folders and destination
        let inv_dl = parse_cli_args(&vec_args(&[
            "download",
            "-s",
            "party-ring-42",
            "--peer",
            "Gaming-PC",
            "-d",
            "/tmp/out",
            "Games_Patches",
            "Tournament_Brackets.pdf",
            "LAN_Party_Photos/Day_1/setup_01.jpg",
        ]))
        .unwrap();
        assert_eq!(
            inv_dl,
            CliInvocation::Download {
                secret: Some("party-ring-42".to_string()),
                peer: "Gaming-PC".to_string(),
                dest_dir: Some(PathBuf::from("/tmp/out")),
                remote_paths: vec![
                    "Games_Patches".to_string(),
                    "Tournament_Brackets.pdf".to_string(),
                    "LAN_Party_Photos/Day_1/setup_01.jpg".to_string(),
                ],
                test_mode: false,
            }
        );

        // `download` rejects wildcards
        let wildcard_err = parse_cli_args(&vec_args(&[
            "download",
            "-s",
            "party-ring-42",
            "--peer",
            "Gaming-PC",
            "Games_Patches/*.pak",
        ]))
        .unwrap_err();
        assert!(wildcard_err.contains("Wildcards are not supported"));

        // `download` without --peer fails
        assert!(parse_cli_args(&vec_args(&[
            "download",
            "-s",
            "party-ring-42",
            "Games_Patches"
        ]))
        .is_err());
    }

    #[test]
    fn test_cli_end_to_end_host_ls_and_multi_download() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let base = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target");
        let pid = std::process::id();
        let share_dir = base.join(format!("lanshare_cli_e2e_share_{}", pid));
        let dest_dir = base.join(format!("lanshare_cli_e2e_dest_{}", pid));
        let _ = std::fs::remove_dir_all(&share_dir);
        let _ = std::fs::remove_dir_all(&dest_dir);

        let sub_dir = share_dir.join("Docs_Subfolder");
        std::fs::create_dir_all(&sub_dir).unwrap();
        std::fs::write(share_dir.join("readme.txt"), b"Root file content").unwrap();
        std::fs::write(sub_dir.join("nested.txt"), b"Nested file content 12345").unwrap();

        let secret = "cli-integration-secret-2026";

        rt.block_on(async {
            // Start a real server hosting `share_dir`
            let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
            let handle =
                server::start_server(vec![share_dir.clone()], secret.to_string(), None, log_tx)
                    .await
                    .expect("Server should start");

            let port = handle.port;

            // 1. List root share via CLI `run_cli_list`
            let mut ls_root_out = Vec::new();
            run_cli_list(secret, "127.0.0.1", port, "", false, &mut ls_root_out)
                .await
                .expect("Root ls should succeed");
            let ls_root_text = String::from_utf8(ls_root_out).unwrap();
            assert!(ls_root_text.contains("Connected to"));
            assert!(ls_root_text.contains(&format!("lanshare_cli_e2e_share_{}/", pid)));

            // 2. List deeper subfolder via CLI `run_cli_list`
            let mut ls_sub_out = Vec::new();
            run_cli_list(
                secret,
                "127.0.0.1",
                port,
                "Docs_Subfolder",
                false,
                &mut ls_sub_out,
            )
            .await
            .expect("Subfolder ls should succeed");
            let ls_sub_text = String::from_utf8(ls_sub_out).unwrap();
            assert!(ls_sub_text.contains("nested.txt"));

            // 3. Download both a file and a folder in a single CLI command
            let mut dl_out = Vec::new();
            run_cli_download(
                secret,
                "127.0.0.1",
                port,
                Some(dest_dir.clone()),
                &["readme.txt".to_string(), "Docs_Subfolder".to_string()],
                false,
                &mut dl_out,
            )
            .await
            .expect("Multi-item CLI download should succeed");

            let dl_text = String::from_utf8(dl_out).unwrap();
            assert!(dl_text.contains("[1/2] Completed 'readme.txt'"));
            assert!(dl_text.contains("[2/2] Completed 'Docs_Subfolder'"));
            assert!(dl_text.contains("All 2 download(s) finished successfully."));

            assert_eq!(
                std::fs::read_to_string(dest_dir.join("readme.txt")).unwrap(),
                "Root file content"
            );
            assert_eq!(
                std::fs::read_to_string(dest_dir.join("Docs_Subfolder").join("nested.txt"))
                    .unwrap(),
                "Nested file content 12345"
            );

            // Shut down server
            handle.is_running.store(false, Ordering::SeqCst);
            let _ = handle.stop_sender.send(());
        });

        // 4. Test foreground `run_cli_host` with a short duration
        rt.block_on(async {
            let mut host_out = Vec::new();
            run_cli_host(
                secret,
                std::slice::from_ref(&share_dir),
                false,
                Some(Duration::from_millis(150)),
                &mut host_out,
            )
            .await
            .expect("Foreground CLI host should run and exit cleanly");
            let host_text = String::from_utf8(host_out).unwrap();
            assert!(host_text.contains("Hosting started on"));
            assert!(host_text.contains("Sharing folder (Read-Only):"));
        });

        let _ = std::fs::remove_dir_all(&share_dir);
        let _ = std::fs::remove_dir_all(&dest_dir);
    }

    #[test]
    fn test_validate_cli_host_folders_and_download_inputs_fail_fast() {
        assert!(validate_cli_host_folders(&[]).is_err());
        let missing = std::env::temp_dir().join("lanshare_definitely_missing_folder_12345");
        let err = validate_cli_host_folders(std::slice::from_ref(&missing)).unwrap_err();
        assert!(!err.is_empty());

        // Avoid std::env::temp_dir() here because on Windows it lives under AppData,
        // which validate_shared_folder intentionally rejects as a restricted folder.
        let valid_dir = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target")
            .join(format!("lanshare_cli_validate_dir_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&valid_dir);
        std::fs::create_dir_all(&valid_dir).unwrap();
        let deduped = validate_cli_host_folders(&[valid_dir.clone(), valid_dir.clone()]).unwrap();
        assert_eq!(deduped.len(), 1);
        let _ = std::fs::remove_dir_all(&valid_dir);

        assert!(validate_cli_download_inputs(None, &[], false).is_err());
    }
}
