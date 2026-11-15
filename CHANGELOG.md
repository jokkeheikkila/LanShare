# Changelog

All notable changes to **LanShare** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-11-15

### Added
- Support discovering and selecting multiple LanShare instances running on the same computer.
- New **Uploads** section in **Share Folders** (always-visible and resizable in GUI, collapsible with `u` in TUI) showing active uploads, per-folder upload counts, progress bars, speed, ETA, and total upload ETA.
- Live download (`↓`) and upload/hosting (`●` / `↑`) indicators in the navigation bar across GUI and TUI.
- Upfront size and ETA calculation for queued folders.
- Centered GUI startup window across primary and multi-monitor setups.
- GitHub Releases update links in **About** and a Table of Contents in `README.md`.
- Weekly CI security dependency checks (`cargo audit`) and pull-request build checks.

### Changed
- Kept the GUI **Downloads** section always visible with a taller default height and a drag-resizable divider.
- Clearer folder loading feedback with an animated spinner and icon-based toolbar controls.
- Stabilized download/upload table columns, action buttons, and completed timestamps so text no longer jumps while transferring.
- Show two decimal places for `GB` and `TB` transfer sizes.
- Validate `lanshare-cli` host and download paths before prompting for the Ring Secret.

### Fixed
- Kept `Total ETA` accurate and immediately updated as queue items are added, resolved, or removed.
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

[Unreleased]: https://github.com/jokkeheikkila/LanShare/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/jokkeheikkila/LanShare/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/jokkeheikkila/LanShare/releases/tag/v1.0.0
