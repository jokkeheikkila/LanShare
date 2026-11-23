# Changelog

All notable changes to **LanShare** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-11-23

### Added
- **V3 ChaCha20-Poly1305 AEAD Encrypted UDP Discovery (`LANSHARE_BEACON_V3`, `LANSHARE_PROBE_V3`, `LANSHARE_REVCONN_V3`)**: Encrypts `DiscoveryBeacon` (`host_name`, `port`) and `ReverseConnectRequest` (`client_name`, `tcp_port`) payloads with `ring::aead::CHACHA20_POLY1305` keyed by a PBKDF2-HMAC-SHA256 stretched discovery subkey so zero plaintext computer names or TCP ports appear on the LAN/Wi-Fi wire.
- **True IPv4 Subnet Broadcast Calculation (`compute_directed_broadcast`, `get_local_ipv4_subnets`)**: Queries real interface netmasks and flags via `libc::getifaddrs` on Unix to compute accurate directed broadcast addresses (`ip | !netmask`) across `/16`–`/30` networks, preventing accidental unicast packets to `.255` host IPs on `/16`–`/23` corporate and LAN-party networks.
- **Virtual Hypervisor & Container Adapter Filtering (`is_virtual_interface_name`, `detect_primary_route_ipv4`)**: Automatically deprioritizes virtual switches (`VMware` / `VMnet1` / `VMnet8`, `VirtualBox`, `vEthernet`, `Hyper-V`, `WSL`, `Docker`) so Windows and Linux always display and broadcast on the primary default-route physical LAN interface first.

### Changed
- **Corporate IDS/EDR & Large LAN-Party Safe Discovery**: Removed parallel TCP `:22222` ARP neighbor port-scanning completely, replaced the fixed `850 ms` server broadcast loop with a jittered `2.5–3.5 s` heartbeat, added `20–150 ms` random jitter to unicast `DiscoveryProbe` replies (preventing reply implosion at large LAN parties), and capped Linux `nf_conntrack` local-subnet ARP UDP pinhole refresh to 16 active local neighbors.
- **Smart Reverse-TCP Guard**: `connect_to_host` now only attempts Reverse-TCP UDP traversal when a verified V3 UDP beacon exists from the target peer (or on the local L2 subnet), skipping UDP hole-punching and callback listeners cleanly on cross-subnet or VPN Direct IP failures.
- **Scaled Discovery Cache**: Raised `DiscoveryService` beacon cache capacity from `256` to `1,024` entries (`300 s` TTL) with expired-first and oldest-entry LRU eviction, and raised the client scan peer cap from `64` to `512`.

## [1.1.2] - 2026-11-19

### Added
- Multi-frame `GetDirectoryManifest` streaming (`MANIFEST_BATCH_FILES = 25,000` with `has_more` continuation) so folders with unlimited numbers of files can be downloaded without hitting the 16 MB frame limit or 50,000-file truncation.
- Live single-line in-place CLI progress bar (`\r\x1b[2K`) for `lanshare-cli download` and `lanshare-cli host` showing percentage gauge, transferred/total bytes, speed, item ETA, cumulative `Total ETA`, and folder file counter, dynamically truncated to terminal width to prevent multi-line wrapping.
- Added documentation in `README.md` on downloading multiple files simultaneously by running multiple `lanshare-gui` or `lanshare-cli` instances.

### Changed
- Raised maximum concurrent server client connections (`MAX_CONCURRENT_CLIENTS`) from `16` to `64`.
- Directory browsing (`ListDirectory`) now separates subdirectories from files when a folder contains over `100,000` files—keeping all subdirectories navigable in GUI and TUI while displaying an inline notice to download the folder from the parent level (and returning a clear error if a folder exceeds `100,000` subdirectories).
- Removed per-file log spam during multi-file folder transfers on both server and client, logging once when a folder download begins (including peer name, file count, and total size) and once when standalone files start/finish.
- Capped background shared folder size walks (`MAX_SHARED_SIZE_WALK_ENTRIES = 100,000`) and active session disk log files (`MAX_SESSION_LOG_BYTES = 10 MB`).

### Fixed
- Added `write_server_response_frame` payload guard so oversized directory responses return a clean `ServerCommandResponse::Error` instead of dropping the TLS connection.
- Used `saturating_add` for folder manifest byte totals and portable 64-bit chunk size clamping.
- Fixed Windows 11 Task Manager process description encoding (`â€”` mojibake) in `assets/lanshare.rc` by replacing the UTF-8 em-dash with an ASCII hyphen and bumping `VERSIONINFO` to `1.1.2.0`.
- Replaced the unmaintained `chrono` dependency (`RUSTSEC-2026-0543`) with a lightweight, thread-safe OS-native local date/time formatter (`libc::localtime_r` on Unix, `FileTimeToSystemTime` + `SystemTimeToTzSpecificLocalTime` on Windows) so `cargo audit` passes with zero warnings.

## [1.1.1] - 2026-11-17

### Changed
- Removed the redundant `(Total: ...)` ETA column from the GUI active download row in **Browse LAN** so speed, active ETA, and transferred/total sizes sit closer together without leaving empty space on single downloads (`Total ETA` remains in the panel header).
- Updated `README.md` screenshots.

### Fixed
- Removed the stray outer whole-window scrollbar from the GUI **Share Files** page so scrolling stays confined to the individual **Shared Folders & Files** and **Uploads** panels.

## [1.1.0] - 2026-11-16

### Added
- Support sharing individual files alongside folders across GUI (`Add File(s)`), TUI (`F` / `Add File`), and `lanshare-cli host`, with upfront size calculation for shared items.
- Support discovering and selecting multiple LanShare instances running on the same computer.
- New **Uploads** section in **Share Files** (always-visible and resizable in GUI, collapsible with `u` in TUI) showing active uploads, per-share upload counts, progress bars, speed, ETA, and total upload ETA.
- Live upload progress summaries in `lanshare-cli host`.
- Live download (`↓`) and upload/hosting (`●` / `↑`) indicators in the navigation bar across GUI and TUI.
- Upfront size and ETA calculation for queued downloads.
- Centered GUI startup window across primary and multi-monitor setups.
- GitHub Releases update links in **About** and a Table of Contents in `README.md`.
- Weekly CI security dependency checks (`cargo audit`) and pull-request build checks.

### Changed
- Renamed the host tab from **Share Folders** to **Share Files** across GUI, TUI, and documentation.
- Kept the GUI **Downloads** section always visible with a taller default height and a drag-resizable divider.
- Clearer folder/file loading feedback with an animated spinner and icon-based toolbar controls.
- Stabilized download/upload table columns, action buttons, and completed timestamps so text no longer jumps while transferring.
- Show two decimal places for `GB` and `TB` transfer sizes.
- Validate `lanshare-cli` host and download paths before prompting for the Ring Secret.
- Prevented horizontal scrolling in GUI **Browse LAN** and increased the minimum window size for consistent layout.
- Updated remove-confirmation wording for individual files (`Keep File` instead of `Keep Folder`).

### Fixed
- Kept `Total ETA` accurate and synchronized with item ETAs for both downloads and uploads (summing active upload ETAs and updating immediately as items change).
- Improved light-theme button visibility in **Browse LAN**.
- Silenced Linux `xdg-open` GTK console warnings when opening files or folders from the TUI.
- Fixed GUI **About** window height and clickable repository/release links.
- Fixed Browse `Name` column resizing affecting queue columns, and matched row highlight height to buttons.

### Security
- Hardened the GitHub Actions release workflow and restricted releases to explicit `v*` version tags.

## [1.0.0] - 2026-11-14

### Added
- Initial public release of **LanShare** (`lanshare-gui` desktop GUI and `lanshare-cli` interactive TUI + CLI subcommands `host`, `peers`, `ls`, `download`) for Windows and Linux.
- Domain-separated PBKDF2-HMAC-SHA256 (`100_000` iterations via `ring`) for LAN discovery beacons (`LANSHARE-V2-DISCOVERY`) and mutual-TLS auth tokens (`LANSHARE-V2-TLS-AUTH`) with ephemeral TLS 1.3/1.2 transport (`rcgen` + `tokio-rustls` backed by `ring`).
- Reverse-TCP firewall traversal with authenticated peer IP pinning.
- Streaming SHA-256 transfer verification and verified resume offset handling for files and recursive folder trees.
- Direct IP Connect support for Tailscale (`100.64.0.0/10`) and private LAN/ULA subnets, plus offline `--test` simulated multi-peer mode.
- Read-only path validation, symlink/`O_NOFOLLOW` protection, `--secret-env` / `--secret-stdin` secret loading, and bounded OS-standard log rotation.

[Unreleased]: https://github.com/jokkeheikkila/LanShare/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/jokkeheikkila/LanShare/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/jokkeheikkila/LanShare/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/jokkeheikkila/LanShare/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jokkeheikkila/LanShare/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/jokkeheikkila/LanShare/releases/tag/v1.0.0
