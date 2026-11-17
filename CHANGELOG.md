# Changelog

All notable changes to **LanShare** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/jokkeheikkila/LanShare/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/jokkeheikkila/LanShare/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jokkeheikkila/LanShare/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/jokkeheikkila/LanShare/releases/tag/v1.0.0
