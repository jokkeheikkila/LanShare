# Changelog

All notable changes to **LanShare** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Multi-instance peer discovery & selection**: track per-instance UDP/TCP ports so multiple LanShare instances on the same host can be discovered and selected independently (`src/discovery.rs`, `src/core.rs`, `src/client.rs`, `src/app.rs`, `src/tui.rs`).
- **Active upload tracking in Shared Folders view**: display per-folder `↑ N uploading` indicators and a live `Uploads — Active: N` progress list (peer IP, file name, progress bar/gauge, speed, ETA, and transferred bytes) across GUI, TUI, and server streams (`src/server.rs`, `src/core.rs`, `src/app.rs`, `src/tui.rs`).
- **Navigation activity indicators**: show active download counts (`↓ N`) and active hosting/upload status (`●` / `↑ N`) on the Browse LAN and Share Folders tabs in both the GUI left rail and TUI top bar (`src/app.rs`, `src/tui.rs`).
- **Pre-resolved queued folder sizes**: compute mock and remote folder byte totals as items enter the queue so pending folders show size and ETA right away (`src/core.rs`, `src/app.rs`, `src/tui.rs`).
- **Centered GUI startup window**: center the initial desktop window consistently across primary and multi-monitor displays (`src/bin/lanshare-gui.rs`, `src/app.rs`).
- **GitHub Releases update links & README Table of Contents**: added direct Releases links to About/download UI (`src/app.rs`, `src/tui.rs`, `src/core.rs`) and a Table of Contents to `README.md`.
- **CI dependency audit & PR checks**: added `.github/workflows/audit.yml` for weekly and lockfile-triggered `cargo audit` scans, and enabled pull-request verification in `.github/workflows/build.yml`.

### Changed
- **Resizable Downloads & Uploads panels**: keep both **Downloads** (Browse LAN) and **Uploads** (Share Folders) always visible at compact default height with drag-resizable splitters in GUI, and add a collapsible **Uploads** (`u`) accordion section in the TUI Host tab matching **Downloads** (`d`) (`src/app.rs`, `src/tui.rs`).
- **Host switch & folder navigation loading feedback**: clear stale file entries immediately on host switch or directory navigation, show a centered loading spinner animation in GUI and TUI, and simplify GUI Up/Refresh toolbar buttons to icon controls (`src/app.rs`, `src/tui.rs`).
- **CLI fail-fast path validation**: validate `lanshare-cli host` and `lanshare-cli download` paths before prompting for the Ring Secret (`src/cli.rs`, `src/main.rs`).
- **Concurrent multi-GB `--test` mock uploads**: simulate multiple concurrent uploads with multi-gigabyte test files in offline `--test` mode (`src/core.rs`).
- **Large file size formatting**: formatted `GB` and `TB` values with two decimal places (`{:.2}`) while keeping `B`, `KB`, and `MB` as whole integers so gigabyte transfer progress remains distinct (`src/core.rs`).
- **Non-jumping transfer metrics & TUI upload summary**: stabilized active download/upload speed, ETA, and byte-count columns in GUI and TUI, moved TUI transfer metrics before filenames with `Total ETA` and collapsed multi-upload summaries, and tightened GUI progress-bar-to-metrics spacing (`src/app.rs`, `src/tui.rs`, `src/core.rs`).
- **Browse table & Download Queue alignment**: unified Browse action buttons (`Queue`, `Active`, `Queued`, `Download`) to a consistent size, removed alternating Browse row striping, moved queue remove (`✖`) buttons to the left column, aligned `Queued`/`Done` badges and `ETA`/`Size` columns, and formatted completed timestamps as time-only (`src/app.rs`, `src/core.rs`).

### Fixed
- **Download queue ETA accuracy**: aligned `Total ETA` with active transfer `ETA` when no other items are pending, and recalculated `Total ETA` immediately whenever queue items are added, removed, completed, or resolved (`src/core.rs`, `src/app.rs`, `src/tui.rs`).
- **Browse resize isolation, hover highlight height, and spinner debounce**: prevented resizing the Browse `Name` column from shifting Active Downloads columns, matched Browse row highlight height to the rendered button height, and debounced the loading spinner (`250ms`) so fast folder loads avoid flicker (`src/app.rs`, `src/tui.rs`, `src/core.rs`).
- **About dialog layout & link opening**: increased GUI About window height so the Close button fits without clipping, and fixed opening repository/release links (`src/app.rs`, `src/tui.rs`, `src/core.rs`).
- **Windows compiler warning**: removed an unused `kind` variable warning in `src/core.rs`.

### Security
- **CI workflow hardening**: pinned `actions/checkout` to full commit SHA (`v7.0.1`) with `persist-credentials: false` and restricted release creation/uploads to explicit `v*` version tags instead of a rolling `latest` tag (`.github/workflows/build.yml`).

## [1.0.0] - 2026-11-14

### Added
- Initial public release of **LanShare** (`lanshare-gui` desktop GUI and `lanshare-cli` interactive TUI + CLI subcommands `host`, `peers`, `ls`, `download`) for Windows and Linux.
- Domain-separated PBKDF2-HMAC-SHA256 (`100_000` iterations via `ring`) for LAN discovery beacons (`LANSHARE-V2-DISCOVERY`) and mutual-TLS auth tokens (`LANSHARE-V2-TLS-AUTH`) with ephemeral TLS 1.3/1.2 transport (`rcgen` + `tokio-rustls` backed by `ring`).
- Reverse-TCP firewall traversal with authenticated peer IP pinning.
- Streaming SHA-256 transfer verification and verified resume offset handling for files and recursive folder trees.
- Direct IP Connect support for Tailscale (`100.64.0.0/10`) and private LAN/ULA subnets, plus offline `--test` simulated multi-peer mode.
- Read-only path validation, symlink/`O_NOFOLLOW` protection, `--secret-env` / `--secret-stdin` secret loading, and bounded OS-standard log rotation.

[Unreleased]: https://github.com/jokkeheikkila/LanShare/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jokkeheikkila/LanShare/releases/tag/v1.0.0
