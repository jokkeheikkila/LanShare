use crate::client::{self, ClientTlsStream, ConnectionContext, TransferProgress};
use crate::core::{
    complete_queued_download, compute_queue_etas, default_mock_peers, dirs_fallback,
    estimate_remaining_seconds, format_completed_timestamp, format_file_size,
    format_remaining_time, generate_random_password,
    has_active_client_downloads as core_has_active_client_downloads, mock_directory_entries,
    mock_folder_total_bytes, open_url, parse_host_and_port, queue_status_sort_rank,
    resolve_remote_folder_total_bytes, sort_peers_alphabetically, sort_shared_paths,
    spawn_next_queued_download, test_downloads_dir, ClientActionResult, EtaStabilizer,
    QueueEtaSummary, QueueItemStatus, QueuedDownloadItem, SharedPathSizeResolver,
    SharedPathSizeStatus, GITHUB_RELEASES_URL, GITHUB_REPO_URL,
};
use crate::protocol::{
    DiscoveredPeer, FileEntry, HandshakeResponse, DEFAULT_TCP_PORT, MIN_SECRET_LEN,
};
use crate::security::{
    clean_display_path, clean_path, validate_shared_file, validate_shared_folder,
    validate_shared_path,
};
use crate::server::{self, ServerHandle, ServerLogEvent};
use arboard::Clipboard;
use chrono::{Local, TimeZone};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const TUI_SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn current_tui_spinner_frame() -> &'static str {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let idx = ((millis / 90) % TUI_SPINNER_FRAMES.len() as u128) as usize;
    TUI_SPINNER_FRAMES[idx]
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TuiTab {
    Client,
    Host,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum InputPromptKind {
    EditSecret,
    DirectIp,
    DestFolder,
    AddHostFolder,
    AddHostFile,
}

#[derive(Clone, Debug)]
pub struct InputPrompt {
    pub kind: InputPromptKind,
    pub title: String,
    pub hint: String,
    pub value: String,
    pub cursor_idx: usize,
    pub error: Option<String>,
}

impl InputPrompt {
    pub fn new(kind: InputPromptKind, title: String, hint: String, value: String) -> Self {
        let cursor_idx = value.chars().count();
        Self {
            kind,
            title,
            hint,
            value,
            cursor_idx,
            error: None,
        }
    }

    pub fn insert_char(&mut self, c: char) {
        let mut chars: Vec<char> = self.value.chars().collect();
        if self.cursor_idx > chars.len() {
            self.cursor_idx = chars.len();
        }
        chars.insert(self.cursor_idx, c);
        self.cursor_idx += 1;
        self.value = chars.into_iter().collect();
        self.error = None;
    }

    pub fn insert_str(&mut self, s: &str) {
        let clean: String = s
            .chars()
            .filter(|c| !c.is_control() || *c == '\t')
            .collect();
        if clean.is_empty() {
            return;
        }
        let mut chars: Vec<char> = self.value.chars().collect();
        if self.cursor_idx > chars.len() {
            self.cursor_idx = chars.len();
        }
        for (i, c) in clean.chars().enumerate() {
            chars.insert(self.cursor_idx + i, c);
        }
        self.cursor_idx += clean.chars().count();
        self.value = chars.into_iter().collect();
        self.error = None;
    }

    pub fn replace_str(&mut self, s: &str) {
        let clean: String = s
            .chars()
            .filter(|c| !c.is_control() || *c == '\t')
            .collect();
        if clean.is_empty() {
            return;
        }
        self.value = clean;
        self.cursor_idx = self.value.chars().count();
        self.error = None;
    }

    pub fn delete_backspace(&mut self) {
        let mut chars: Vec<char> = self.value.chars().collect();
        if self.cursor_idx > 0 && !chars.is_empty() {
            self.cursor_idx -= 1;
            if self.cursor_idx < chars.len() {
                chars.remove(self.cursor_idx);
            }
            self.value = chars.into_iter().collect();
            self.error = None;
        }
    }

    pub fn delete_current(&mut self) {
        let mut chars: Vec<char> = self.value.chars().collect();
        if self.cursor_idx < chars.len() {
            chars.remove(self.cursor_idx);
            self.value = chars.into_iter().collect();
            self.error = None;
        }
    }

    pub fn move_left(&mut self) {
        if self.cursor_idx > 0 {
            self.cursor_idx -= 1;
        }
    }

    pub fn move_right(&mut self) {
        let len = self.value.chars().count();
        if self.cursor_idx < len {
            self.cursor_idx += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor_idx = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor_idx = self.value.chars().count();
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor_idx = 0;
        self.error = None;
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Color {
    Reset,
    Black,
    White,
    Gray,
    DarkGray,
    Cyan,
    LightCyan,
    Blue,
    DarkBlue,
    Green,
    DarkGreen,
    Yellow,
    Red,
    DarkRed,
    Magenta,
}

impl Color {
    fn fg_ansi(self) -> &'static str {
        match self {
            Color::Reset => "\x1b[39m",
            Color::Black => "\x1b[30m",
            Color::White => "\x1b[97m",
            Color::Gray => "\x1b[37m",
            Color::DarkGray => "\x1b[90m",
            Color::Cyan => "\x1b[36m",
            Color::LightCyan => "\x1b[96m",
            Color::Blue => "\x1b[94m",
            Color::DarkBlue => "\x1b[34m",
            Color::Green => "\x1b[92m",
            Color::DarkGreen => "\x1b[32m",
            Color::Yellow => "\x1b[93m",
            Color::Red => "\x1b[91m",
            Color::DarkRed => "\x1b[31m",
            Color::Magenta => "\x1b[95m",
        }
    }

    fn bg_ansi(self) -> &'static str {
        match self {
            Color::Reset => "\x1b[49m",
            Color::Black => "\x1b[40m",
            Color::White => "\x1b[107m",
            Color::Gray => "\x1b[47m",
            Color::DarkGray => "\x1b[100m",
            Color::Cyan => "\x1b[46m",
            Color::LightCyan => "\x1b[106m",
            Color::Blue => "\x1b[104m",
            Color::DarkBlue => "\x1b[44m",
            Color::Green => "\x1b[102m",
            Color::DarkGreen => "\x1b[42m",
            Color::Yellow => "\x1b[103m",
            Color::Red => "\x1b[101m",
            Color::DarkRed => "\x1b[41m",
            Color::Magenta => "\x1b[105m",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: Color::Gray,
            bg: Color::Reset,
            bold: false,
        }
    }
}

pub struct ScreenBuffer {
    pub width: usize,
    pub height: usize,
    pub cells: Vec<Cell>,
}

impl ScreenBuffer {
    pub fn new(width: usize, height: usize) -> Self {
        let w = width.max(40);
        let h = height.max(18);
        Self {
            width: w,
            height: h,
            cells: vec![Cell::default(); w * h],
        }
    }

    pub fn set(&mut self, x: usize, y: usize, ch: char, fg: Color, bg: Color, bold: bool) {
        if x < self.width && y < self.height {
            let idx = y * self.width + x;
            self.cells[idx] = Cell { ch, fg, bg, bold };
        }
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize, fg: Color, bg: Color) {
        for row in y..y.saturating_add(h).min(self.height) {
            for col in x..x.saturating_add(w).min(self.width) {
                self.set(col, row, ' ', fg, bg, false);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw_text(
        &mut self,
        x: usize,
        y: usize,
        max_w: usize,
        text: &str,
        fg: Color,
        bg: Color,
        bold: bool,
    ) -> usize {
        if y >= self.height || x >= self.width || max_w == 0 {
            return 0;
        }
        let limit = x.saturating_add(max_w).min(self.width);
        let mut col = x;
        for ch in text.chars() {
            if ch == '\n' || ch == '\r' {
                continue;
            }
            let cw = UnicodeWidthChar::width(ch).unwrap_or(1).max(1);
            if col + cw > limit {
                break;
            }
            self.set(col, y, ch, fg, bg, bold);
            if cw == 2 && col + 1 < limit {
                self.set(col + 1, y, '\0', fg, bg, bold);
            }
            col += cw;
        }
        col - x
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw_cursor_input(
        &mut self,
        x: usize,
        y: usize,
        max_w: usize,
        prefix: &str,
        text: &str,
        cursor_idx: usize,
        fg: Color,
        bg: Color,
    ) {
        if y >= self.height || x >= self.width || max_w == 0 {
            return;
        }
        let limit = x.saturating_add(max_w).min(self.width);
        let mut col = x;

        // Draw prefix (e.g. "> ")
        for ch in prefix.chars() {
            if col >= limit {
                break;
            }
            self.set(col, y, ch, fg, bg, true);
            col += 1;
        }

        let chars: Vec<char> = text.chars().collect();
        let total_chars = chars.len();
        let avail_w = limit.saturating_sub(col);
        if avail_w == 0 {
            return;
        }

        // Horizontal scrolling if text exceeds avail_w
        let mut view_start = 0;
        if total_chars >= avail_w && cursor_idx >= avail_w.saturating_sub(2) {
            view_start = cursor_idx.saturating_sub(avail_w.saturating_sub(3));
        }

        let clamped_cursor = cursor_idx.min(total_chars);
        let visible_chars = &chars[view_start..total_chars.min(view_start + avail_w)];

        for (offset, &ch) in visible_chars.iter().enumerate() {
            let abs_idx = view_start + offset;
            if col >= limit {
                break;
            }
            if abs_idx == clamped_cursor {
                // Invert colors on the character under the cursor
                self.set(col, y, ch, bg, fg, true);
            } else {
                self.set(col, y, ch, fg, bg, true);
            }
            col += 1;
        }

        // If cursor is at the end of the text, draw block cursor
        if clamped_cursor == total_chars && col < limit {
            self.set(col, y, '█', fg, bg, true);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw_box(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        title: &str,
        border_fg: Color,
        bg: Color,
    ) {
        if w < 2 || h < 2 || x >= self.width || y >= self.height {
            return;
        }
        self.fill_rect(x, y, w, h, Color::Gray, bg);
        let x2 = (x + w - 1).min(self.width - 1);
        let y2 = (y + h - 1).min(self.height - 1);

        for col in (x + 1)..x2 {
            self.set(col, y, '─', border_fg, bg, false);
            self.set(col, y2, '─', border_fg, bg, false);
        }
        for row in (y + 1)..y2 {
            self.set(x, row, '│', border_fg, bg, false);
            self.set(x2, row, '│', border_fg, bg, false);
        }
        self.set(x, y, '╭', border_fg, bg, false);
        self.set(x2, y, '╮', border_fg, bg, false);
        self.set(x, y2, '╰', border_fg, bg, false);
        self.set(x2, y2, '╯', border_fg, bg, false);

        if !title.is_empty() && w > 6 {
            let formatted = format!(" {} ", title);
            self.draw_text(
                x + 2,
                y,
                w.saturating_sub(4),
                &formatted,
                Color::White,
                bg,
                true,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn draw_gauge(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        ratio: f32,
        label: &str,
        fill_fg: Color,
        bg: Color,
    ) {
        if w == 0 || y >= self.height {
            return;
        }
        let clamped = ratio.clamp(0.0, 1.0);
        let filled = ((w as f32) * clamped).round() as usize;
        for i in 0..w {
            let col = x + i;
            if col >= self.width {
                break;
            }
            if i < filled {
                self.set(col, y, '█', fill_fg, bg, false);
            } else {
                self.set(col, y, '░', Color::DarkGray, bg, false);
            }
        }
        if !label.is_empty() && w > label.len() + 2 {
            let start = x + (w.saturating_sub(label.len())) / 2;
            self.draw_text(
                start,
                y,
                label.len(),
                label,
                Color::White,
                Color::DarkBlue,
                true,
            );
        }
    }

    pub fn to_ansi_frame(&self) -> String {
        let mut out = String::with_capacity(self.width * self.height * 2 + 256);
        out.push_str("\x1b[H");
        let mut cur_fg = Color::Reset;
        let mut cur_bg = Color::Reset;
        let mut cur_bold = false;
        out.push_str("\x1b[0m");

        for y in 0..self.height {
            if y > 0 {
                out.push_str("\r\n");
            }
            for x in 0..self.width {
                let cell = self.cells[y * self.width + x];
                if cell.ch == '\0' {
                    continue;
                }
                if cell.bold != cur_bold {
                    if cell.bold {
                        out.push_str("\x1b[1m");
                    } else {
                        out.push_str("\x1b[22m");
                    }
                    cur_bold = cell.bold;
                }
                if cell.fg != cur_fg {
                    out.push_str(cell.fg.fg_ansi());
                    cur_fg = cell.fg;
                }
                if cell.bg != cur_bg {
                    out.push_str(cell.bg.bg_ansi());
                    cur_bg = cell.bg;
                }
                out.push(cell.ch);
            }
        }
        out.push_str("\x1b[0m");
        out
    }

    pub fn to_plain_text(&self) -> String {
        let mut lines = Vec::with_capacity(self.height);
        for y in 0..self.height {
            let mut line = String::with_capacity(self.width);
            for x in 0..self.width {
                let ch = self.cells[y * self.width + x].ch;
                if ch != '\0' {
                    line.push(ch);
                }
            }
            lines.push(line.trim_end().to_string());
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyEvent {
    Char(char),
    Paste(String),
    Enter,
    Backspace,
    Delete,
    Tab,
    BackTab,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    F(u8),
    CtrlC,
    CtrlU,
    CtrlV,
    CtrlY,
    CtrlInsert,
    ShiftInsert,
    ScrollUp,
    ScrollDown,
    MouseClick { col: usize, row: usize },
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub enum ClientSection {
    #[default]
    Browse,
    Downloads,
    Logs,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub enum HostSection {
    #[default]
    Folders,
    Uploads,
    Logs,
}

pub struct LanShareTui {
    pub tokio_rt: Runtime,
    pub should_quit: bool,
    pub test_mode: bool,
    pub mock_session: bool,
    pub secret_confirmed: bool,
    pub current_tab: TuiTab,
    pub show_how_it_works: bool,
    pub active_prompt: Option<InputPrompt>,

    // Share-Ring Secret
    pub ring_secret: String,
    pub secret_cursor_idx: usize,
    pub show_secret_plain: bool,
    pub last_scanned_secret: String,
    pub last_auto_scan: Instant,
    pub local_ips: Vec<String>,

    // Host state
    pub host_folders: Vec<PathBuf>,
    pub host_share_sizes: SharedPathSizeResolver,
    pub selected_host_folder_idx: usize,
    pub host_error: Option<String>,
    pub server_handle: Option<ServerHandle>,
    pub server_logs: VecDeque<ServerLogEvent>,
    server_log_rx: Receiver<ServerLogEvent>,
    server_log_tx: tokio::sync::mpsc::UnboundedSender<ServerLogEvent>,
    pub show_server_logs: bool,

    // Client state
    pub client_ip: String,
    pub client_port: u16,
    pub selected_peer_name: String,
    pub client_dest_folder: PathBuf,
    pub client_error: Option<String>,
    pub discovered_peers: Vec<DiscoveredPeer>,
    pub is_scanning: bool,
    scan_rx: Option<Receiver<Vec<DiscoveredPeer>>>,

    // Connected Client Browsing Session
    pub client_connected: bool,
    pub client_connection_lost: bool,
    pub connected_via_direct_ip: bool,
    pub client_handshake: Option<HandshakeResponse>,
    client_stream: Option<ClientTlsStream>,
    pub client_current_path: String,
    pub client_file_list: Vec<FileEntry>,
    pub selected_file_idx: usize,
    pub file_scroll_offset: usize,
    pub client_loading: bool,
    pub client_loading_started_at: Option<Instant>,

    client_action_rx: Receiver<ClientActionResult>,
    client_action_tx: Sender<ClientActionResult>,

    // Multi-Item Download Queue & Progress
    next_queue_id: u64,
    pub download_queue: VecDeque<QueuedDownloadItem>,
    pub active_queue_id: Option<u64>,
    pub active_progress: Option<TransferProgress>,
    progress_finished_at: Option<Instant>,
    active_eta_stabilizer: EtaStabilizer,
    total_eta_stabilizer: EtaStabilizer,
    upload_total_eta_stabilizer: EtaStabilizer,
    progress_rx: Receiver<TransferProgress>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<TransferProgress>,
    transfer_cancel_tx: Option<tokio::sync::watch::Sender<bool>>,

    // Client Accordion & Scroll State
    pub client_section: ClientSection,
    pub selected_queue_idx: usize,
    pub queue_scroll_offset: usize,
    pub log_scroll_offset: usize,
    pub last_browse_header_y: Option<usize>,
    pub last_downloads_header_y: Option<usize>,
    pub last_logs_header_y: Option<usize>,
    pub last_browse_header_range: Option<(usize, usize)>,
    pub last_downloads_header_range: Option<(usize, usize)>,
    pub last_logs_header_range: Option<(usize, usize)>,
    pub server_log_scroll_offset: usize,
    pub host_section: HostSection,
    pub upload_scroll_offset: usize,
    pub last_host_folders_header_range: Option<(usize, usize)>,
    pub last_host_uploads_header_range: Option<(usize, usize)>,
    pub last_host_logs_header_range: Option<(usize, usize)>,
    pub last_login_copy_bounds: Option<(usize, usize, usize)>,
    pub last_about_github_bounds: Option<(usize, usize, usize)>,
    pub last_about_updates_bounds: Option<(usize, usize, usize)>,

    // Client Activity Log (hidden by default)
    pub client_logs: VecDeque<String>,
    pub show_client_logs: bool,

    // Clipboard & Status Flash
    clipboard: Option<Clipboard>,
    pub status_flash: Option<(String, Instant)>,
    pub quit_confirmed: bool,
    pub stop_server_confirmed: bool,
}

impl LanShareTui {
    pub fn new(
        test_mode: bool,
        initial_secret: Option<String>,
        initial_host_folders: Vec<PathBuf>,
        autostart_host: bool,
    ) -> Self {
        let tokio_rt = Runtime::new().expect("Failed to initialize Tokio runtime");

        let (server_log_tokio_tx, mut server_log_tokio_rx) =
            tokio::sync::mpsc::unbounded_channel::<ServerLogEvent>();
        let (server_log_std_tx, server_log_std_rx) = channel::<ServerLogEvent>();

        tokio_rt.spawn(async move {
            while let Some(evt) = server_log_tokio_rx.recv().await {
                let _ = server_log_std_tx.send(evt);
            }
        });

        let (client_action_tx, client_action_rx) = channel::<ClientActionResult>();

        let (prog_tokio_tx, mut prog_tokio_rx) =
            tokio::sync::mpsc::unbounded_channel::<TransferProgress>();
        let (prog_std_tx, prog_std_rx) = channel::<TransferProgress>();

        tokio_rt.spawn(async move {
            while let Some(p) = prog_tokio_rx.recv().await {
                let _ = prog_std_tx.send(p);
            }
        });

        let default_download = if test_mode {
            let dir = test_downloads_dir();
            let _ = std::fs::create_dir_all(&dir);
            dir
        } else {
            dirs_fallback().join("Downloads")
        };

        let (ring_secret, secret_confirmed) = match initial_secret {
            Some(s) if s.trim().len() >= MIN_SECRET_LEN => (s.trim().to_string(), true),
            Some(s) => (s.trim().to_string(), false),
            None => (String::new(), false),
        };

        let local_ips = crate::network::get_all_local_lan_ips();
        let mut client_logs = VecDeque::new();
        let mut discovered_peers = Vec::new();

        if test_mode {
            discovered_peers = default_mock_peers();
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let entry = format!(
                "[{}] Test Mode active: 2 simulated hosts available. Press [p] (or ←/→) to select a computer!",
                ts
            );
            crate::core::spool_log_entry(&format!("[Client] {}", entry));
            client_logs.push_back(entry);
        }

        let mut valid_host_folders = Vec::new();
        let mut host_error = None;
        for f in initial_host_folders {
            match validate_shared_path(&f) {
                Ok(safe) => {
                    if !valid_host_folders.contains(&safe) {
                        valid_host_folders.push(safe);
                    }
                }
                Err(e) => host_error = Some(e),
            }
        }
        sort_shared_paths(&mut valid_host_folders);

        let current_tab = if autostart_host || !valid_host_folders.is_empty() {
            TuiTab::Host
        } else {
            TuiTab::Client
        };

        let mut app = Self {
            tokio_rt,
            should_quit: false,
            test_mode,
            mock_session: false,
            secret_confirmed,
            current_tab,
            show_how_it_works: false,
            active_prompt: None,

            ring_secret: ring_secret.clone(),
            secret_cursor_idx: ring_secret.chars().count(),
            show_secret_plain: false,
            last_scanned_secret: if test_mode {
                ring_secret
            } else {
                String::new()
            },
            last_auto_scan: Instant::now() - Duration::from_secs(10),
            local_ips,

            host_folders: valid_host_folders,
            host_share_sizes: SharedPathSizeResolver::new(),
            selected_host_folder_idx: 0,
            host_error,
            server_handle: None,
            server_logs: VecDeque::new(),
            server_log_rx: server_log_std_rx,
            server_log_tx: server_log_tokio_tx,
            show_server_logs: false,

            client_ip: String::new(),
            client_port: DEFAULT_TCP_PORT,
            selected_peer_name: String::new(),
            client_dest_folder: default_download,
            client_error: None,
            discovered_peers,
            is_scanning: false,
            scan_rx: None,

            client_connected: false,
            client_connection_lost: false,
            connected_via_direct_ip: false,
            client_handshake: None,
            client_stream: None,
            client_current_path: String::new(),
            client_file_list: Vec::new(),
            selected_file_idx: 0,
            file_scroll_offset: 0,
            client_loading: false,
            client_loading_started_at: None,

            client_action_rx,
            client_action_tx,

            next_queue_id: 1,
            download_queue: VecDeque::new(),
            active_queue_id: None,
            active_progress: None,
            progress_finished_at: None,
            active_eta_stabilizer: EtaStabilizer::new(),
            total_eta_stabilizer: EtaStabilizer::new(),
            upload_total_eta_stabilizer: EtaStabilizer::new(),
            progress_rx: prog_std_rx,
            progress_tx: prog_tokio_tx,
            transfer_cancel_tx: None,

            client_section: ClientSection::Browse,
            selected_queue_idx: 0,
            queue_scroll_offset: 0,
            log_scroll_offset: 0,
            last_browse_header_y: None,
            last_downloads_header_y: None,
            last_logs_header_y: None,
            last_browse_header_range: None,
            last_downloads_header_range: None,
            last_logs_header_range: None,
            server_log_scroll_offset: 0,
            host_section: HostSection::Folders,
            upload_scroll_offset: 0,
            last_host_folders_header_range: None,
            last_host_uploads_header_range: None,
            last_host_logs_header_range: None,
            last_login_copy_bounds: None,
            last_about_github_bounds: None,
            last_about_updates_bounds: None,

            client_logs,
            show_client_logs: false,

            clipboard: None,
            status_flash: None,
            quit_confirmed: false,
            stop_server_confirmed: false,
        };

        crate::core::spool_log_session_start("TUI");

        if autostart_host && !app.host_folders.is_empty() {
            app.toggle_server();
        }

        app
    }

    fn is_own_peer(&self, peer: &DiscoveredPeer) -> bool {
        if let Some(ref handle) = self.server_handle {
            if handle.is_running.load(std::sync::atomic::Ordering::Relaxed)
                && peer.port == handle.port
                && (self.local_ips.contains(&peer.ip)
                    || handle.all_ips.contains(&peer.ip)
                    || peer.ip == "127.0.0.1")
            {
                return true;
            }
        }
        false
    }

    fn set_flash(&mut self, msg: impl Into<String>) {
        self.status_flash = Some((msg.into(), Instant::now()));
    }

    fn copy_to_clipboard(&mut self, text: &str, label: &str) {
        if cfg!(test) {
            self.set_flash(format!("{} copied to clipboard!", label));
            return;
        }
        // Keep the arboard Clipboard handle alive on LanShareTui so X11/Wayland
        // selection ownership is not dropped right after copying.
        if self.clipboard.is_none() {
            self.clipboard = Clipboard::new().ok();
        }
        if let Some(ref mut cb) = self.clipboard {
            if cb.set_text(text.to_string()).is_ok() {
                self.set_flash(format!("{} copied to clipboard!", label));
                return;
            }
        }
        self.clipboard = Clipboard::new().ok();
        if let Some(ref mut cb) = self.clipboard {
            if cb.set_text(text.to_string()).is_ok() {
                self.set_flash(format!("{} copied to clipboard!", label));
                return;
            }
        }
        self.set_flash(format!("{} = {}", label, text));
    }

    fn get_clipboard_text(&mut self) -> Option<String> {
        if cfg!(test) {
            return None;
        }
        if self.clipboard.is_none() {
            self.clipboard = Clipboard::new().ok();
        }
        self.clipboard.as_mut().and_then(|cb| cb.get_text().ok())
    }

    fn insert_secret_char(&mut self, c: char) {
        let mut chars: Vec<char> = self.ring_secret.chars().collect();
        if self.secret_cursor_idx > chars.len() {
            self.secret_cursor_idx = chars.len();
        }
        chars.insert(self.secret_cursor_idx, c);
        self.secret_cursor_idx += 1;
        self.ring_secret = chars.into_iter().collect();
    }

    fn replace_secret_str(&mut self, s: &str) {
        let clean: String = s
            .chars()
            .filter(|c| !c.is_control() || *c == '\t')
            .collect();
        if clean.is_empty() {
            return;
        }
        self.ring_secret = clean;
        self.secret_cursor_idx = self.ring_secret.chars().count();
    }

    pub fn push_client_log(&mut self, entry: String) {
        crate::core::spool_log_entry(&format!("[Client] {}", entry));
        if self.client_logs.len() >= 500 {
            self.client_logs.pop_front();
        }
        self.client_logs.push_back(entry);
    }

    pub fn push_server_log(&mut self, evt: ServerLogEvent) {
        crate::core::spool_log_entry(&format!("[Server] [{}] {}", evt.timestamp, evt.message));
        if self.server_logs.len() >= 500 {
            self.server_logs.pop_front();
        }
        self.server_logs.push_back(evt);
    }

    pub fn poll_channels(&mut self) {
        while let Ok(evt) = self.server_log_rx.try_recv() {
            self.push_server_log(evt);
        }

        if let Some(ref rx) = self.scan_rx {
            if let Ok(mut peers) = rx.try_recv() {
                if self.test_mode {
                    for mp in default_mock_peers() {
                        if !peers.iter().any(|p| p.ip == mp.ip) {
                            peers.push(mp);
                        }
                    }
                }
                sort_peers_alphabetically(&mut peers);
                let connected_peer_missing = self.client_connected
                    && !self.mock_session
                    && !self.connected_via_direct_ip
                    && !peers.iter().any(|p| p.ip == self.client_ip);
                self.discovered_peers = peers;
                self.is_scanning = false;
                self.scan_rx = None;
                if connected_peer_missing {
                    self.mark_client_connection_lost();
                }
            }
        }

        while let Ok(prog) = self.progress_rx.try_recv() {
            if let Some(ref msg) = prog.log_message {
                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                self.push_client_log(format!("[{}] {}", ts, msg));
            }
            if let Some(active_id) = self.active_queue_id {
                if let Some(item) = self.download_queue.iter_mut().find(|i| i.id == active_id) {
                    if prog.bytes_total > 0 {
                        item.total_bytes = Some(prog.bytes_total);
                    } else if prog.bytes_done > 0 {
                        item.total_bytes = Some(prog.bytes_done);
                    }
                }
            }
            if prog.is_finished {
                self.progress_finished_at = Some(Instant::now());
            } else {
                self.progress_finished_at = None;
            }
            self.active_progress = Some(prog);
        }

        if let Some(done_time) = self.progress_finished_at {
            if self.active_queue_id.is_none() && done_time.elapsed() > Duration::from_secs(4) {
                self.active_progress = None;
                self.active_eta_stabilizer.reset();
                self.progress_finished_at = None;
            }
        }

        if let Some((_msg, flash_time)) = &self.status_flash {
            if flash_time.elapsed() > Duration::from_secs(3) {
                self.status_flash = None;
            }
        }

        while let Ok(res) = self.client_action_rx.try_recv() {
            match res {
                ClientActionResult::Connected(mut stream, resp, ip, port) => {
                    if !self.client_ip.trim().is_empty()
                        && (ip != self.client_ip.trim() || port != self.client_port)
                    {
                        self.tokio_rt.spawn(async move {
                            let _ = stream.shutdown().await;
                        });
                        continue;
                    }
                    self.client_loading = false;
                    self.client_connected = true;
                    self.client_connection_lost = false;
                    self.mock_session = false;
                    self.client_ip = ip.clone();
                    self.client_port = port;
                    self.selected_peer_name = resp.server_name.clone();
                    if !self
                        .discovered_peers
                        .iter()
                        .any(|p| p.ip == ip && p.port == port)
                    {
                        self.discovered_peers.push(DiscoveredPeer {
                            host_name: resp.server_name.clone(),
                            ip: ip.clone(),
                            port,
                            last_seen: Instant::now(),
                        });
                        sort_peers_alphabetically(&mut self.discovered_peers);
                    }
                    self.client_handshake = Some(resp.clone());
                    self.client_stream = Some(stream);
                    self.client_current_path.clear();
                    self.selected_file_idx = 0;
                    self.file_scroll_offset = 0;
                    self.client_error = None;

                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                    self.push_client_log(format!(
                        "[{}] Connected to '{}' ({}) [Read-Only]",
                        ts, resp.server_name, ip
                    ));
                    self.refresh_client_listing();
                }
                ClientActionResult::ConnectFailed(err) => {
                    self.set_client_loading(false);
                    self.mock_session = false;
                    self.client_stream = None;
                    if self.client_connected || !self.client_file_list.is_empty() {
                        self.client_connection_lost = true;
                    }
                    self.client_error = Some(err.clone());
                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                    self.push_client_log(format!("[{}] Connection failed: {}", ts, err));
                }
                ClientActionResult::ListingLoaded(stream, loaded_path, entries) => {
                    self.set_client_loading(false);
                    self.client_connection_lost = false;
                    self.client_stream = Some(stream);
                    let path_changed = self.client_current_path != loaded_path;
                    self.client_current_path = loaded_path;
                    self.client_file_list = entries;
                    if path_changed {
                        self.selected_file_idx = 0;
                        self.file_scroll_offset = 0;
                    } else if self.selected_file_idx >= self.client_file_list.len() {
                        self.selected_file_idx = self.client_file_list.len().saturating_sub(1);
                    }
                    self.client_error = None;
                }
                ClientActionResult::ListingFailed(stream, err) => {
                    self.set_client_loading(false);
                    let is_transport_loss = stream.is_none();
                    self.client_stream = stream;
                    if is_transport_loss {
                        self.client_connection_lost = true;
                    }
                    self.client_error = Some(err.clone());
                    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                    self.push_client_log(format!("[{}] Directory error: {}", ts, err));
                }
                ClientActionResult::FolderSizeResolved { id, total_bytes } => {
                    if let Some(item) = self.download_queue.iter_mut().find(|i| i.id == id) {
                        item.total_bytes = Some(total_bytes);
                        self.total_eta_stabilizer.reset();
                    }
                }
                ClientActionResult::QueueItemFinished { id, result } => {
                    let outcome = complete_queued_download(
                        &mut self.download_queue,
                        &mut self.active_queue_id,
                        &mut self.transfer_cancel_tx,
                        self.active_progress.as_ref(),
                        id,
                        &result,
                    );
                    if outcome.cancelled {
                        self.active_progress = None;
                        self.active_eta_stabilizer.reset();
                    } else if let Some(err) = outcome.error {
                        self.active_progress = None;
                        self.active_eta_stabilizer.reset();
                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        self.client_error = Some(err.clone());
                        self.push_client_log(format!("[{}] Transfer error: {}", ts, err));
                    } else {
                        self.progress_finished_at = Some(Instant::now());
                        self.set_flash(format!("Finished downloading '{}'", outcome.item_name));
                    }
                    self.active_eta_stabilizer.reset();
                    self.total_eta_stabilizer.reset();

                    self.start_next_queued_download();
                }
            }
        }

        // Note: Automatic periodic refresh is disabled. Use [s] to scan LAN manually.
    }

    pub fn trigger_lan_scan(&mut self) {
        if self.is_scanning {
            return;
        }
        let secret = self.ring_secret.trim().to_string();
        if secret.len() < MIN_SECRET_LEN {
            self.client_error = Some(format!(
                "Enter a LAN secret of at least {} characters to scan.",
                MIN_SECRET_LEN
            ));
            return;
        }
        self.client_error = None;
        self.is_scanning = true;
        self.last_auto_scan = Instant::now();
        let (tx, rx) = channel();
        self.scan_rx = Some(rx);

        self.tokio_rt.spawn(async move {
            let peers =
                client::scan_lan_for_hosts(Duration::from_millis(1500), Some(&secret)).await;
            let _ = tx.send(peers);
        });
    }

    fn host_unavailable_message(&self) -> String {
        let host = if self.selected_peer_name.trim().is_empty() {
            if self.client_ip.trim().is_empty() {
                "Host".to_string()
            } else {
                self.client_ip.clone()
            }
        } else {
            self.selected_peer_name.clone()
        };
        format!("Host '{}' is no longer available (connection lost).", host)
    }

    fn mark_client_connection_lost(&mut self) {
        self.client_connection_lost = true;
        self.client_stream = None;
        let msg = self.host_unavailable_message();
        self.client_error = Some(msg.clone());
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.push_client_log(format!("[{}] {}", ts, msg));
    }

    pub fn connect_mock_session(&mut self, host_label: &str, mock_ip: &str) {
        if let Some(mut old_stream) = self.client_stream.take() {
            self.tokio_rt.spawn(async move {
                let _ = old_stream.shutdown().await;
            });
        }
        self.client_connected = true;
        self.client_connection_lost = false;
        self.set_client_loading(false);
        self.connected_via_direct_ip = false;
        self.mock_session = true;
        self.client_ip = mock_ip.to_string();
        self.selected_peer_name = host_label.to_string();
        self.client_current_path.clear();
        self.selected_file_idx = 0;
        self.file_scroll_offset = 0;
        self.client_handshake = Some(HandshakeResponse {
            authenticated: true,
            server_name: host_label.to_string(),
            message: "Connected to simulated LAN host.".to_string(),
            server_auth_token: Vec::new(),
        });
        self.client_file_list = mock_directory_entries(mock_ip, "");
        self.client_error = None;
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.push_client_log(format!(
            "[{}] Connected to simulated LAN host '{}'.",
            ts, host_label
        ));
    }

    fn set_client_loading(&mut self, loading: bool) {
        if loading {
            self.client_loading = true;
            self.client_loading_started_at
                .get_or_insert_with(Instant::now);
        } else {
            self.client_loading = false;
            self.client_loading_started_at = None;
        }
    }

    pub fn clear_errors(&mut self) {
        self.host_error = None;
        self.client_error = None;
    }

    pub fn trigger_connect(&mut self) {
        self.clear_errors();
        let ip = self.client_ip.trim().to_string();
        if self.test_mode
            && (ip.starts_with("mock://") || (ip.is_empty() && self.server_handle.is_none()))
        {
            let (label, target_ip) = if ip.contains("alice") {
                ("Alice-Laptop (Test Mode)", "mock://alice-laptop")
            } else {
                ("Mock-Gaming-PC (Test Mode)", "mock://gaming-pc")
            };
            self.connect_mock_session(label, target_ip);
            return;
        }

        if let Some(mut old_stream) = self.client_stream.take() {
            self.tokio_rt.spawn(async move {
                let _ = old_stream.shutdown().await;
            });
        }
        self.client_connected = false;
        self.client_connection_lost = false;
        self.mock_session = false;
        self.client_handshake = None;
        self.client_current_path.clear();
        self.client_file_list.clear();
        self.selected_file_idx = 0;
        self.file_scroll_offset = 0;

        let pwd = self.ring_secret.trim().to_string();
        let port = self.client_port;
        let tx = self.client_action_tx.clone();
        self.set_client_loading(true);

        self.tokio_rt.spawn(async move {
            match client::connect_to_host(&ip, port, &pwd).await {
                Ok((stream, resp)) => {
                    let _ = tx.send(ClientActionResult::Connected(stream, resp, ip, port));
                }
                Err(e) => {
                    let _ = tx.send(ClientActionResult::ConnectFailed(e));
                }
            }
        });
    }

    fn request_listing_for_path(&mut self, target_path: String) {
        self.clear_errors();
        if self.mock_session {
            let path_changed = self.client_current_path != target_path;
            self.client_current_path = target_path;
            self.client_file_list =
                mock_directory_entries(&self.client_ip, &self.client_current_path);
            if path_changed {
                self.selected_file_idx = 0;
                self.file_scroll_offset = 0;
            } else if self.selected_file_idx >= self.client_file_list.len() {
                self.selected_file_idx = self.client_file_list.len().saturating_sub(1);
            }
            self.client_error = None;
            return;
        }

        if self.client_connection_lost {
            self.client_error = Some(self.host_unavailable_message());
            return;
        }

        if self.client_loading {
            return;
        }

        if let Some(mut stream) = self.client_stream.take() {
            let tx = self.client_action_tx.clone();
            self.client_current_path = target_path.clone();
            self.client_file_list.clear();
            self.selected_file_idx = 0;
            self.file_scroll_offset = 0;
            self.set_client_loading(true);

            self.tokio_rt.spawn(async move {
                match client::request_directory_listing_checked(&mut stream, &target_path).await {
                    Ok(entries) => {
                        let _ = tx.send(ClientActionResult::ListingLoaded(
                            stream,
                            target_path,
                            entries,
                        ));
                    }
                    Err(e) => {
                        if e.connection_lost {
                            let _ = stream.shutdown().await;
                            let _ = tx.send(ClientActionResult::ListingFailed(None, e.message));
                        } else {
                            let _ =
                                tx.send(ClientActionResult::ListingFailed(Some(stream), e.message));
                        }
                    }
                }
            });
        } else if self.client_connected {
            self.mark_client_connection_lost();
        }
    }

    pub fn refresh_client_listing(&mut self) {
        self.request_listing_for_path(self.client_current_path.clone());
    }

    pub fn navigate_into(&mut self, folder_name: &str) {
        let target_path = if self.client_current_path.is_empty() {
            folder_name.to_string()
        } else {
            format!("{}/{}", self.client_current_path, folder_name)
        };
        self.request_listing_for_path(target_path);
    }

    pub fn navigate_up(&mut self) {
        if self.client_current_path.is_empty() {
            if self.client_connection_lost {
                self.client_error = Some(self.host_unavailable_message());
            } else {
                self.clear_errors();
            }
            return;
        }
        let target_path = if let Some(idx) = self.client_current_path.rfind('/') {
            self.client_current_path[..idx].to_string()
        } else {
            String::new()
        };
        self.request_listing_for_path(target_path);
    }

    pub fn disconnect_client(&mut self) {
        if let Some(mut stream) = self.client_stream.take() {
            self.tokio_rt.spawn(async move {
                let _ = stream.shutdown().await;
            });
        }
        self.client_connected = false;
        self.client_connection_lost = false;
        self.connected_via_direct_ip = false;
        self.mock_session = false;
        self.client_handshake = None;
        self.client_file_list.clear();
        self.selected_file_idx = 0;
        self.file_scroll_offset = 0;
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.push_client_log(format!("[{}] Disconnected from peer.", ts));
    }

    pub fn cancel_active_transfer(&mut self) {
        if let Some(tx) = self.transfer_cancel_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(active_id) = self.active_queue_id.take() {
            self.download_queue.retain(|i| i.id != active_id);
        }
        self.active_progress = None;
        self.active_eta_stabilizer.reset();
        self.total_eta_stabilizer.reset();
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.push_client_log(format!("[{}] Transfer cancelled by user.", ts));
        self.set_flash("Cancelled active transfer.");
    }

    pub fn enqueue_download(&mut self, entry: FileEntry) {
        if !self.mock_session
            && (self.client_connection_lost
                || (self.client_connected && !self.client_loading && self.client_stream.is_none()))
        {
            self.mark_client_connection_lost();
            return;
        }
        let remote_subpath = if self.client_current_path.is_empty() {
            entry.name.clone()
        } else {
            format!("{}/{}", self.client_current_path, entry.name)
        };

        if self.download_queue.iter().any(|i| {
            i.conn_ctx.ip == self.client_ip
                && i.remote_subpath == remote_subpath
                && matches!(
                    i.status,
                    QueueItemStatus::Pending | QueueItemStatus::Downloading
                )
        }) {
            self.set_flash(format!(
                "'{}' is already in the download queue.",
                entry.name
            ));
            return;
        }

        let id = self.next_queue_id;
        self.next_queue_id += 1;

        let peer_name = self
            .client_handshake
            .as_ref()
            .map(|h| h.server_name.clone())
            .unwrap_or_else(|| self.client_ip.clone());

        let total_bytes = if entry.is_dir {
            if self.mock_session {
                Some(mock_folder_total_bytes(&self.client_ip, &remote_subpath))
            } else {
                None
            }
        } else {
            Some(entry.size)
        };

        let conn_ctx = ConnectionContext {
            ip: self.client_ip.clone(),
            port: self.client_port,
            password: self.ring_secret.trim().to_string(),
            peer_name: Some(peer_name.clone()),
        };

        let item = QueuedDownloadItem {
            id,
            peer_name: peer_name.clone(),
            conn_ctx: conn_ctx.clone(),
            is_mock: self.mock_session,
            entry: entry.clone(),
            remote_subpath: remote_subpath.clone(),
            local_dest_dir: self.client_dest_folder.clone(),
            status: QueueItemStatus::Pending,
            started_at: None,
            elapsed_duration: None,
            completed_at: None,
            total_bytes,
        };

        self.download_queue.push_back(item);
        self.total_eta_stabilizer.reset();

        if entry.is_dir && !self.mock_session {
            let tx = self.client_action_tx.clone();
            self.tokio_rt.spawn(async move {
                if let Some(total_bytes) =
                    resolve_remote_folder_total_bytes(conn_ctx, remote_subpath).await
                {
                    let _ = tx.send(ClientActionResult::FolderSizeResolved { id, total_bytes });
                }
            });
        }

        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let kind = if entry.is_dir { "folder" } else { "file" };
        self.push_client_log(format!(
            "[{}] Queued {} '{}' from {}.",
            ts, kind, entry.name, peer_name
        ));
        self.set_flash(format!("Queued {} '{}'", kind, entry.name));

        if self.active_queue_id.is_none() {
            self.start_next_queued_download();
        }
    }

    fn start_next_queued_download(&mut self) {
        spawn_next_queued_download(
            &self.tokio_rt,
            &mut self.download_queue,
            &mut self.active_queue_id,
            &mut self.transfer_cancel_tx,
            &self.client_action_tx,
            &self.progress_tx,
        );
    }

    pub fn cycle_peer(&mut self, forward: bool) {
        if self.discovered_peers.is_empty() {
            self.set_flash("No peers discovered yet. Press [s] to scan.");
            return;
        }
        let len = self.discovered_peers.len();
        let next_idx = match self.discovered_peers.iter().position(|p| {
            self.client_connected
                && !self.client_connection_lost
                && p.ip == self.client_ip
                && p.port == self.client_port
        }) {
            Some(cur_idx) => {
                if forward {
                    (cur_idx + 1) % len
                } else {
                    (cur_idx + len - 1) % len
                }
            }
            None => {
                if forward {
                    0
                } else {
                    len - 1
                }
            }
        };
        let peer = self.discovered_peers[next_idx].clone();
        self.connected_via_direct_ip = false;
        self.client_ip = peer.ip.clone();
        self.client_port = peer.port;
        self.selected_peer_name = peer.host_name.clone();
        self.trigger_connect();
    }

    pub fn active_server_downloads(&self) -> usize {
        self.server_handle
            .as_ref()
            .map(|h| {
                h.active_downloads
                    .load(std::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or(0)
    }

    pub fn has_active_client_downloads(&self) -> bool {
        core_has_active_client_downloads(
            self.active_progress.as_ref(),
            self.active_queue_id,
            &self.download_queue,
        )
    }

    pub fn is_hosting_active(&self) -> bool {
        self.server_handle
            .as_ref()
            .map(|h| h.is_running.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false)
    }

    pub fn can_change_secret(&self) -> bool {
        !self.is_hosting_active() && !self.has_active_client_downloads()
    }

    pub fn needs_close_confirmation(&self) -> bool {
        self.is_hosting_active()
            || self.active_server_downloads() > 0
            || self.has_active_client_downloads()
    }

    pub fn toggle_server(&mut self) {
        let is_running = self
            .server_handle
            .as_ref()
            .map(|h| h.is_running.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false);

        if is_running {
            self.clear_errors();
            let active_dl = self.active_server_downloads();
            if active_dl > 0 && !self.stop_server_confirmed {
                self.stop_server_confirmed = true;
                self.set_flash(format!(
                    "CRITICAL: Peer is downloading ({} active transfer{})! Press [S] again to abort transfer and stop sharing.",
                    active_dl,
                    if active_dl == 1 { "" } else { "s" }
                ));
                return;
            }

            self.stop_server_confirmed = false;
            let local_ips = self.local_ips.clone();
            let s_ip = self.server_handle.as_ref().map(|h| h.local_ip.clone());
            if let Some(handle) = self.server_handle.take() {
                let _ = handle.stop_sender.send(());
                if active_dl > 0 {
                    self.set_flash("Aborted peer transfer and stopped Share-Ring server.");
                } else {
                    self.set_flash("Stopped Share-Ring server.");
                }
            }
            self.discovered_peers.retain(|p| {
                !local_ips.contains(&p.ip) && s_ip.as_deref() != Some(&p.ip) && p.ip != "127.0.0.1"
            });
            return;
        }

        if self.host_folders.is_empty() {
            self.host_error =
                Some("Add at least one folder to share first (press [a]).".to_string());
            return;
        }
        if self.ring_secret.trim().len() < MIN_SECRET_LEN {
            self.host_error = Some(format!(
                "Share-Ring secret must be at least {} characters.",
                MIN_SECRET_LEN
            ));
            return;
        }

        let folders = self.host_folders.clone();
        let pwd = self.ring_secret.trim().to_string();
        let log_tx = self.server_log_tx.clone();

        match self
            .tokio_rt
            .block_on(server::start_server(folders, pwd, None, log_tx))
        {
            Ok(handle) => {
                if self.test_mode {
                    crate::core::spawn_mock_server_downloads(&self.tokio_rt, &handle);
                }
                self.host_error = None;
                self.set_flash(format!("Hosting read-only on {}", handle.local_ip));
                self.server_handle = Some(handle);
            }
            Err(e) => {
                self.host_error = Some(e.to_string());
            }
        }
    }

    fn expand_tilde(input: &str) -> PathBuf {
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

    pub fn handle_key(&mut self, key: KeyEvent) {
        if key == KeyEvent::CtrlC {
            self.should_quit = true;
            return;
        }

        // 0. Initial Secret Setup Dialog
        if !self.secret_confirmed {
            match key {
                KeyEvent::Esc => {
                    self.should_quit = true;
                }
                KeyEvent::Tab => {
                    self.ring_secret = generate_random_password();
                    self.secret_cursor_idx = self.ring_secret.chars().count();
                    self.set_flash("Generated new random Share-Ring secret.");
                }
                KeyEvent::F(2) | KeyEvent::CtrlInsert | KeyEvent::CtrlY => {
                    let s = self.ring_secret.trim().to_string();
                    self.copy_to_clipboard(&s, "Share-Ring Secret");
                }
                KeyEvent::MouseClick { col, row } => {
                    if let Some((btn_row, c_start, c_end)) = self.last_login_copy_bounds {
                        if row == btn_row && col >= c_start && col <= c_end {
                            let s = self.ring_secret.trim().to_string();
                            self.copy_to_clipboard(&s, "Share-Ring Secret");
                        }
                    }
                }
                KeyEvent::Enter => {
                    if self.ring_secret.trim().len() >= MIN_SECRET_LEN {
                        self.ring_secret = self.ring_secret.trim().to_string();
                        self.secret_cursor_idx = self.ring_secret.chars().count();
                        self.secret_confirmed = true;
                        self.show_secret_plain = false;
                        self.trigger_lan_scan();
                    } else {
                        self.set_flash(format!(
                            "Secret must be at least {} characters.",
                            MIN_SECRET_LEN
                        ));
                    }
                }
                KeyEvent::Left => {
                    if self.secret_cursor_idx > 0 {
                        self.secret_cursor_idx -= 1;
                    }
                }
                KeyEvent::Right => {
                    if self.secret_cursor_idx < self.ring_secret.chars().count() {
                        self.secret_cursor_idx += 1;
                    }
                }
                KeyEvent::Home => {
                    self.secret_cursor_idx = 0;
                }
                KeyEvent::End => {
                    self.secret_cursor_idx = self.ring_secret.chars().count();
                }
                KeyEvent::Backspace => {
                    let mut chars: Vec<char> = self.ring_secret.chars().collect();
                    if self.secret_cursor_idx > 0 && !chars.is_empty() {
                        self.secret_cursor_idx -= 1;
                        if self.secret_cursor_idx < chars.len() {
                            chars.remove(self.secret_cursor_idx);
                        }
                        self.ring_secret = chars.into_iter().collect();
                    }
                }
                KeyEvent::Delete => {
                    let mut chars: Vec<char> = self.ring_secret.chars().collect();
                    if self.secret_cursor_idx < chars.len() {
                        chars.remove(self.secret_cursor_idx);
                        self.ring_secret = chars.into_iter().collect();
                    }
                }
                KeyEvent::CtrlU => {
                    self.ring_secret.clear();
                    self.secret_cursor_idx = 0;
                }
                KeyEvent::ShiftInsert | KeyEvent::CtrlV => {
                    if let Some(text) = self.get_clipboard_text() {
                        self.replace_secret_str(&text);
                    } else {
                        self.set_flash("Clipboard is empty or unavailable.");
                    }
                }
                KeyEvent::Paste(ref text) => {
                    self.replace_secret_str(text);
                }
                KeyEvent::Char(c) if !c.is_control() => {
                    self.insert_secret_char(c);
                }
                _ => {}
            }
            return;
        }

        // 1. Modal: "How Share-Ring Works" / About
        if self.show_how_it_works {
            match key {
                KeyEvent::Esc
                | KeyEvent::Enter
                | KeyEvent::Char('?')
                | KeyEvent::Char('q')
                | KeyEvent::F(1) => {
                    self.show_how_it_works = false;
                    self.last_about_github_bounds = None;
                    self.last_about_updates_bounds = None;
                }
                KeyEvent::Char('g') | KeyEvent::Char('G') => {
                    self.open_about_url(GITHUB_REPO_URL, "GitHub repository");
                }
                KeyEvent::Char('u') | KeyEvent::Char('U') => {
                    self.open_about_url(GITHUB_RELEASES_URL, "GitHub Releases");
                }
                KeyEvent::MouseClick { col, row } => {
                    let hit = |bounds: Option<(usize, usize, usize)>| {
                        bounds.is_some_and(|(r, c0, c1)| row == r && col >= c0 && col <= c1)
                    };
                    if hit(self.last_about_github_bounds) {
                        self.open_about_url(GITHUB_REPO_URL, "GitHub repository");
                    } else if hit(self.last_about_updates_bounds) {
                        self.open_about_url(GITHUB_RELEASES_URL, "GitHub Releases");
                    }
                }
                _ => {}
            }
            return;
        }

        // 2. Inline Text Input Prompt Modal
        if let Some(mut prompt) = self.active_prompt.take() {
            match key {
                KeyEvent::Esc => {
                    // Cancel prompt
                }
                KeyEvent::Enter => {
                    let val = prompt.value.trim().to_string();
                    match prompt.kind {
                        InputPromptKind::EditSecret => {
                            if val.len() < MIN_SECRET_LEN {
                                prompt.error = Some(format!(
                                    "Share-Ring secret must be at least {} characters.",
                                    MIN_SECRET_LEN
                                ));
                                self.active_prompt = Some(prompt);
                                return;
                            }
                            self.ring_secret = val;
                            self.client_error = None;
                            self.host_error = None;
                            self.set_flash("Updated Share-Ring secret.");
                        }
                        InputPromptKind::DirectIp => {
                            if val.is_empty() {
                                prompt.error = Some("IP address cannot be empty.".to_string());
                                self.active_prompt = Some(prompt);
                                return;
                            }
                            let trimmed = val.trim();
                            let (host, port) = parse_host_and_port(trimmed, DEFAULT_TCP_PORT);
                            if host.parse::<std::net::IpAddr>().is_err()
                                && !trimmed.starts_with("mock://")
                            {
                                prompt.error = Some("Invalid IP address format.".to_string());
                                self.active_prompt = Some(prompt);
                                return;
                            }
                            self.connected_via_direct_ip = true;
                            self.client_ip = host;
                            self.client_port = port;
                            self.selected_peer_name = trimmed.to_string();
                            self.trigger_connect();
                        }
                        InputPromptKind::DestFolder => {
                            if val.is_empty() {
                                prompt.error =
                                    Some("Destination path cannot be empty.".to_string());
                                self.active_prompt = Some(prompt);
                                return;
                            }
                            let path = Self::expand_tilde(&val);
                            match crate::security::ensure_safe_client_dir(&path) {
                                Ok(()) => {
                                    self.client_dest_folder = path;
                                    self.client_error = None;
                                    self.set_flash("Updated download destination folder.");
                                }
                                Err(e) => {
                                    prompt.error = Some(e);
                                    self.active_prompt = Some(prompt);
                                    return;
                                }
                            }
                        }
                        InputPromptKind::AddHostFolder | InputPromptKind::AddHostFile => {
                            let is_file = prompt.kind == InputPromptKind::AddHostFile;
                            if val.is_empty() {
                                prompt.error = Some(if is_file {
                                    "File path cannot be empty.".to_string()
                                } else {
                                    "Folder path cannot be empty.".to_string()
                                });
                                self.active_prompt = Some(prompt);
                                return;
                            }
                            let path = Self::expand_tilde(&val);
                            let res = if is_file {
                                validate_shared_file(&path)
                            } else {
                                validate_shared_folder(&path)
                            };
                            match res {
                                Ok(safe) => {
                                    if !self.host_folders.contains(&safe) {
                                        self.host_share_sizes.invalidate(&safe);
                                        self.host_folders.push(safe.clone());
                                        sort_shared_paths(&mut self.host_folders);
                                        if let Some(pos) =
                                            self.host_folders.iter().position(|p| p == &safe)
                                        {
                                            self.selected_host_folder_idx = pos;
                                        }
                                        if let Some(ref handle) = self.server_handle {
                                            let _ = handle
                                                .update_shared_folders(self.host_folders.clone());
                                        } else if self.ring_secret.trim().len() >= MIN_SECRET_LEN {
                                            self.toggle_server();
                                        }
                                    }
                                    self.host_error = None;
                                    self.set_flash(if is_file {
                                        "Added file to read-only share list."
                                    } else {
                                        "Added folder to read-only share list."
                                    });
                                }
                                Err(e) => {
                                    prompt.error = Some(e);
                                    self.active_prompt = Some(prompt);
                                    return;
                                }
                            }
                        }
                    }
                }
                KeyEvent::Left => {
                    prompt.move_left();
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::Right => {
                    prompt.move_right();
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::Home => {
                    prompt.move_home();
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::End => {
                    prompt.move_end();
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::Backspace => {
                    prompt.delete_backspace();
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::Delete => {
                    prompt.delete_current();
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::CtrlU => {
                    prompt.clear();
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::F(2) | KeyEvent::CtrlInsert | KeyEvent::CtrlY => {
                    let val = prompt.value.trim().to_string();
                    self.active_prompt = Some(prompt);
                    self.copy_to_clipboard(&val, "Input");
                    return;
                }
                KeyEvent::ShiftInsert | KeyEvent::CtrlV => {
                    if let Some(text) = self.get_clipboard_text() {
                        prompt.replace_str(&text);
                    } else {
                        self.set_flash("Clipboard is empty or unavailable.");
                    }
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::Paste(ref text) => {
                    prompt.replace_str(text);
                    self.active_prompt = Some(prompt);
                }
                KeyEvent::Char(c) if !c.is_control() => {
                    prompt.insert_char(c);
                    self.active_prompt = Some(prompt);
                }
                _ => {
                    self.active_prompt = Some(prompt);
                }
            }
            return;
        }

        if key != KeyEvent::Char('q') && key != KeyEvent::Esc {
            self.quit_confirmed = false;
        }
        if key != KeyEvent::Char('S')
            && key != KeyEvent::Enter
            && key != KeyEvent::Delete
            && key != KeyEvent::Char('d')
        {
            self.stop_server_confirmed = false;
        }

        // Return from expanded non-Browse section to Browse (or non-Folders section to Folders) on Esc
        if key == KeyEvent::Esc {
            if self.current_tab == TuiTab::Client && self.client_section != ClientSection::Browse {
                self.client_section = ClientSection::Browse;
                return;
            }
            if self.current_tab == TuiTab::Host
                && self.effective_host_section() != HostSection::Folders
            {
                self.set_host_section(HostSection::Folders);
                return;
            }
        }

        // Mouse click on collapsed accordion headers
        if let KeyEvent::MouseClick { col: _, row } = key {
            if self.current_tab == TuiTab::Client {
                if let Some((start, end)) = self.last_browse_header_range {
                    if row >= start && row <= end && self.client_section != ClientSection::Browse {
                        self.client_section = ClientSection::Browse;
                        return;
                    }
                } else if Some(row) == self.last_browse_header_y {
                    self.client_section = ClientSection::Browse;
                    return;
                }
                if let Some((start, end)) = self.last_downloads_header_range {
                    if row >= start && row <= end && self.client_section != ClientSection::Downloads
                    {
                        self.client_section = ClientSection::Downloads;
                        return;
                    }
                } else if Some(row) == self.last_downloads_header_y {
                    self.client_section = ClientSection::Downloads;
                    return;
                }
                if let Some((start, end)) = self.last_logs_header_range {
                    if row >= start && row <= end && self.client_section != ClientSection::Logs {
                        self.client_section = ClientSection::Logs;
                        return;
                    }
                } else if Some(row) == self.last_logs_header_y {
                    self.client_section = ClientSection::Logs;
                    return;
                }
            } else if self.current_tab == TuiTab::Host {
                let active_sec = self.effective_host_section();
                if let Some((start, end)) = self.last_host_logs_header_range {
                    if row >= start && row <= end && active_sec != HostSection::Logs {
                        self.set_host_section(HostSection::Logs);
                        return;
                    }
                }
                if let Some((start, end)) = self.last_host_uploads_header_range {
                    if row >= start && row <= end && active_sec != HostSection::Uploads {
                        self.set_host_section(HostSection::Uploads);
                        return;
                    }
                }
                if let Some((start, end)) = self.last_host_folders_header_range {
                    if row >= start && row <= end && active_sec != HostSection::Folders {
                        self.set_host_section(HostSection::Folders);
                        return;
                    }
                }
            }
        }

        // 3. Global shortcuts across both tabs
        match key {
            KeyEvent::Char('q') | KeyEvent::Esc => {
                let active_server_dl = self.active_server_downloads();
                let active_client_dl = self.has_active_client_downloads();
                let is_hosting = self.is_hosting_active();

                if (active_server_dl > 0 || active_client_dl || is_hosting) && !self.quit_confirmed
                {
                    self.quit_confirmed = true;
                    if active_server_dl > 0 && active_client_dl {
                        self.set_flash(format!(
                            "CRITICAL: Peer downloading from you ({}) & active downloads in progress! Press [q] again to exit.",
                            active_server_dl
                        ));
                    } else if active_server_dl > 0 {
                        self.set_flash(format!(
                            "CRITICAL: Peer downloading from your share ({} active transfer{})! Press [q] again to exit.",
                            active_server_dl,
                            if active_server_dl == 1 { "" } else { "s" }
                        ));
                    } else if active_client_dl && is_hosting {
                        self.set_flash("Warning: Folder sharing & downloads in progress! Press [q] again to stop sharing and exit.");
                    } else if active_client_dl {
                        self.set_flash("Warning: File downloads currently in progress from peers! Press [q] again to abort downloads and exit.");
                    } else {
                        self.set_flash("Warning: Share-Ring hosting is active! Press [q] again to stop sharing and exit.");
                    }
                    return;
                }

                self.should_quit = true;
                return;
            }
            KeyEvent::Char('?') | KeyEvent::F(1) => {
                self.show_how_it_works = true;
                return;
            }
            KeyEvent::Tab | KeyEvent::BackTab => {
                self.clear_errors();
                self.current_tab = match self.current_tab {
                    TuiTab::Client => TuiTab::Host,
                    TuiTab::Host => TuiTab::Client,
                };
                return;
            }
            KeyEvent::Char('1') => {
                self.clear_errors();
                self.current_tab = TuiTab::Client;
                return;
            }
            KeyEvent::Char('2') => {
                self.clear_errors();
                self.current_tab = TuiTab::Host;
                return;
            }
            KeyEvent::Char('v') => {
                self.show_secret_plain = !self.show_secret_plain;
                return;
            }
            KeyEvent::Char('e') => {
                let server_active = self
                    .server_handle
                    .as_ref()
                    .map(|h| h.is_running.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(false);
                let client_downloading = self.has_active_client_downloads();
                if server_active && client_downloading {
                    self.set_flash("Stop hosting and wait for downloads to finish before changing the Share-Ring secret.");
                } else if server_active {
                    self.set_flash("Stop hosting first before changing the Share-Ring secret.");
                } else if client_downloading {
                    self.set_flash(
                        "Wait for downloads to finish before changing the Share-Ring secret.",
                    );
                } else {
                    self.active_prompt = Some(InputPrompt::new(
                        InputPromptKind::EditSecret,
                        "Edit Share-Ring Secret".to_string(),
                        format!("Enter shared LAN secret (min {} chars):", MIN_SECRET_LEN),
                        self.ring_secret.clone(),
                    ));
                }
                return;
            }
            KeyEvent::Char('r') => {
                let server_active = self
                    .server_handle
                    .as_ref()
                    .map(|h| h.is_running.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(false);
                let client_downloading = self.has_active_client_downloads();
                if server_active && client_downloading {
                    self.set_flash("Stop hosting and wait for downloads to finish before randomizing the Share-Ring secret.");
                } else if server_active {
                    self.set_flash("Stop hosting first before randomizing the Share-Ring secret.");
                } else if client_downloading {
                    self.set_flash(
                        "Wait for downloads to finish before randomizing the Share-Ring secret.",
                    );
                } else {
                    self.ring_secret = generate_random_password();
                    self.set_flash("Generated new random Share-Ring secret.");
                }
                return;
            }
            KeyEvent::Char('y') => {
                let s = self.ring_secret.trim().to_string();
                self.copy_to_clipboard(&s, "Share-Ring Secret");
                return;
            }
            KeyEvent::Char('b') => {
                if self.current_tab == TuiTab::Client {
                    self.client_section = ClientSection::Browse;
                    return;
                }
            }
            KeyEvent::Char('f') => {
                if self.current_tab == TuiTab::Host {
                    self.set_host_section(HostSection::Folders);
                    return;
                }
            }
            KeyEvent::Char('u') => {
                if self.current_tab == TuiTab::Host {
                    if self.effective_host_section() == HostSection::Uploads {
                        self.set_host_section(HostSection::Folders);
                    } else {
                        self.set_host_section(HostSection::Uploads);
                    }
                    return;
                }
            }
            KeyEvent::Char('d') => {
                if self.current_tab == TuiTab::Client {
                    if self.client_section == ClientSection::Downloads {
                        self.client_section = ClientSection::Browse;
                    } else {
                        self.client_section = ClientSection::Downloads;
                    }
                    return;
                }
            }
            KeyEvent::Char('l') => {
                match self.current_tab {
                    TuiTab::Client => {
                        if self.client_section == ClientSection::Logs {
                            self.client_section = ClientSection::Browse;
                        } else {
                            self.client_section = ClientSection::Logs;
                        }
                        self.show_client_logs = self.client_section == ClientSection::Logs;
                    }
                    TuiTab::Host => {
                        if self.effective_host_section() == HostSection::Logs {
                            self.set_host_section(HostSection::Folders);
                        } else {
                            self.set_host_section(HostSection::Logs);
                        }
                    }
                }
                return;
            }
            _ => {}
        }

        // 4. Tab-specific shortcuts
        match self.current_tab {
            TuiTab::Client => self.handle_client_key(key),
            TuiTab::Host => self.handle_host_key(key),
        }
    }

    fn handle_client_key(&mut self, key: KeyEvent) {
        match key {
            KeyEvent::Up | KeyEvent::ScrollUp | KeyEvent::Char('k') => match self.client_section {
                ClientSection::Browse => {
                    if self.selected_file_idx > 0 {
                        self.selected_file_idx -= 1;
                    }
                }
                ClientSection::Downloads => {
                    if self.selected_queue_idx > 0 {
                        self.selected_queue_idx -= 1;
                    }
                }
                ClientSection::Logs => {
                    if self.log_scroll_offset < self.client_logs.len() {
                        self.log_scroll_offset += 1;
                    }
                }
            },
            KeyEvent::Down | KeyEvent::ScrollDown | KeyEvent::Char('j') => {
                match self.client_section {
                    ClientSection::Browse => {
                        if self.selected_file_idx + 1 < self.client_file_list.len() {
                            self.selected_file_idx += 1;
                        }
                    }
                    ClientSection::Downloads => {
                        if self.selected_queue_idx + 1 < self.download_queue.len() {
                            self.selected_queue_idx += 1;
                        }
                    }
                    ClientSection::Logs => {
                        self.log_scroll_offset = self.log_scroll_offset.saturating_sub(1);
                    }
                }
            }
            KeyEvent::PageUp => match self.client_section {
                ClientSection::Browse => {
                    self.selected_file_idx = self.selected_file_idx.saturating_sub(10);
                }
                ClientSection::Downloads => {
                    self.selected_queue_idx = self.selected_queue_idx.saturating_sub(10);
                }
                ClientSection::Logs => {
                    self.log_scroll_offset =
                        (self.log_scroll_offset + 10).min(self.client_logs.len());
                }
            },
            KeyEvent::PageDown => match self.client_section {
                ClientSection::Browse => {
                    if !self.client_file_list.is_empty() {
                        self.selected_file_idx =
                            (self.selected_file_idx + 10).min(self.client_file_list.len() - 1);
                    }
                }
                ClientSection::Downloads => {
                    if !self.download_queue.is_empty() {
                        self.selected_queue_idx =
                            (self.selected_queue_idx + 10).min(self.download_queue.len() - 1);
                    }
                }
                ClientSection::Logs => {
                    self.log_scroll_offset = self.log_scroll_offset.saturating_sub(10);
                }
            },
            KeyEvent::Home => match self.client_section {
                ClientSection::Browse => self.selected_file_idx = 0,
                ClientSection::Downloads => self.selected_queue_idx = 0,
                ClientSection::Logs => self.log_scroll_offset = self.client_logs.len(),
            },
            KeyEvent::End => match self.client_section {
                ClientSection::Browse => {
                    if !self.client_file_list.is_empty() {
                        self.selected_file_idx = self.client_file_list.len() - 1;
                    }
                }
                ClientSection::Downloads => {
                    if !self.download_queue.is_empty() {
                        self.selected_queue_idx = self.download_queue.len() - 1;
                    }
                }
                ClientSection::Logs => self.log_scroll_offset = 0,
            },
            KeyEvent::Enter => {
                if self.client_section == ClientSection::Browse {
                    if let Some(entry) = self.client_file_list.get(self.selected_file_idx).cloned()
                    {
                        if entry.is_dir {
                            self.navigate_into(&entry.name);
                        }
                    }
                }
            }
            KeyEvent::Char(' ') | KeyEvent::Char('g') => {
                if self.client_section == ClientSection::Browse {
                    if let Some(entry) = self.client_file_list.get(self.selected_file_idx).cloned()
                    {
                        self.enqueue_download(entry);
                    }
                }
            }
            KeyEvent::Backspace | KeyEvent::Char('u') => {
                if self.client_section == ClientSection::Browse {
                    self.navigate_up();
                }
            }
            KeyEvent::F(5) => {
                if self.client_connected {
                    self.refresh_client_listing();
                } else {
                    self.trigger_lan_scan();
                }
            }
            KeyEvent::Char('s') => {
                self.trigger_lan_scan();
            }
            KeyEvent::Char('p') | KeyEvent::Right => {
                self.cycle_peer(true);
            }
            KeyEvent::Left => {
                self.cycle_peer(false);
            }
            KeyEvent::Char('i') => {
                self.active_prompt = Some(InputPrompt::new(
                    InputPromptKind::DirectIp,
                    "Direct IP Connect".to_string(),
                    "Enter LAN peer IP:".to_string(),
                    String::new(),
                ));
            }
            KeyEvent::Char('o') => {
                self.active_prompt = Some(InputPrompt::new(
                    InputPromptKind::DestFolder,
                    "Change Download Destination Folder".to_string(),
                    "Enter local directory path for downloads:".to_string(),
                    clean_display_path(&self.client_dest_folder),
                ));
            }
            KeyEvent::Char('D') => {
                if self.client_connected {
                    self.disconnect_client();
                }
            }
            KeyEvent::Char('c') => {
                if self.client_section == ClientSection::Logs {
                    self.client_logs.clear();
                    self.log_scroll_offset = 0;
                    self.set_flash("Cleared client activity log.");
                } else if self.active_queue_id.is_some() {
                    self.cancel_active_transfer();
                }
            }
            KeyEvent::Char('x') => {
                self.download_queue.retain(|i| {
                    matches!(
                        i.status,
                        QueueItemStatus::Pending | QueueItemStatus::Downloading
                    )
                });
                self.set_flash("Cleared finished queue items.");
            }
            KeyEvent::Delete => {
                if self.client_section == ClientSection::Downloads {
                    let mut visible_items: Vec<_> = self
                        .download_queue
                        .iter()
                        .filter(|i| !matches!(i.status, QueueItemStatus::Cancelled))
                        .map(|i| (i.id, i.status.clone(), i.entry.name.clone()))
                        .collect();
                    visible_items.sort_by_key(|(_, status, _)| queue_status_sort_rank(status));
                    if let Some((target_id, target_status, target_name)) =
                        visible_items.get(self.selected_queue_idx)
                    {
                        if *target_status == QueueItemStatus::Pending {
                            let tid = *target_id;
                            self.download_queue.retain(|i| i.id != tid);
                            self.total_eta_stabilizer.reset();
                            self.set_flash(format!("Removed '{}' from queue.", target_name));
                            if self.selected_queue_idx >= self.download_queue.len()
                                && !self.download_queue.is_empty()
                            {
                                self.selected_queue_idx = self.download_queue.len() - 1;
                            }
                        } else {
                            self.set_flash("Only pending items can be removed with Delete.");
                        }
                    }
                } else if let Some(pos) = self
                    .download_queue
                    .iter()
                    .rposition(|i| i.status == QueueItemStatus::Pending)
                {
                    if let Some(removed) = self.download_queue.remove(pos) {
                        self.total_eta_stabilizer.reset();
                        self.set_flash(format!("Removed '{}' from queue.", removed.entry.name));
                    }
                }
            }
            _ => {}
        }
    }

    fn effective_host_section(&self) -> HostSection {
        if self.show_server_logs {
            HostSection::Logs
        } else {
            self.host_section
        }
    }

    fn set_host_section(&mut self, section: HostSection) {
        self.host_section = section;
        self.show_server_logs = section == HostSection::Logs;
    }

    fn handle_host_key(&mut self, key: KeyEvent) {
        if key == KeyEvent::Char('S') {
            self.toggle_server();
            return;
        }
        if key == KeyEvent::Char('Y') {
            let ip = self
                .server_handle
                .as_ref()
                .map(|h| h.local_ip.clone())
                .unwrap_or_else(|| {
                    self.local_ips
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "127.0.0.1".to_string())
                });
            self.copy_to_clipboard(&ip, "Host IP");
            return;
        }

        let server_active = self
            .server_handle
            .as_ref()
            .map(|h| h.is_running.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false);

        match self.effective_host_section() {
            HostSection::Logs => match key {
                KeyEvent::Up | KeyEvent::ScrollUp | KeyEvent::Char('k') => {
                    if self.server_log_scroll_offset < self.server_logs.len() {
                        self.server_log_scroll_offset += 1;
                    }
                    return;
                }
                KeyEvent::Down | KeyEvent::ScrollDown | KeyEvent::Char('j') => {
                    self.server_log_scroll_offset = self.server_log_scroll_offset.saturating_sub(1);
                    return;
                }
                KeyEvent::PageUp => {
                    self.server_log_scroll_offset =
                        (self.server_log_scroll_offset + 10).min(self.server_logs.len());
                    return;
                }
                KeyEvent::PageDown => {
                    self.server_log_scroll_offset =
                        self.server_log_scroll_offset.saturating_sub(10);
                    return;
                }
                KeyEvent::Home => {
                    self.server_log_scroll_offset = self.server_logs.len();
                    return;
                }
                KeyEvent::End => {
                    self.server_log_scroll_offset = 0;
                    return;
                }
                KeyEvent::Char('c') => {
                    self.server_logs.clear();
                    self.server_log_scroll_offset = 0;
                    self.set_flash("Cleared server activity log.");
                    return;
                }
                KeyEvent::Char('b') | KeyEvent::Char('f') => {
                    self.set_host_section(HostSection::Folders);
                    return;
                }
                _ => return,
            },
            HostSection::Uploads => {
                let upload_count = self
                    .server_handle
                    .as_ref()
                    .map(|h| h.active_uploads_snapshot().len())
                    .unwrap_or(0);
                match key {
                    KeyEvent::Up | KeyEvent::ScrollUp | KeyEvent::Char('k') => {
                        self.upload_scroll_offset = self.upload_scroll_offset.saturating_sub(1);
                        return;
                    }
                    KeyEvent::Down | KeyEvent::ScrollDown | KeyEvent::Char('j') => {
                        if self.upload_scroll_offset + 1 < upload_count {
                            self.upload_scroll_offset += 1;
                        }
                        return;
                    }
                    KeyEvent::PageUp | KeyEvent::Home => {
                        self.upload_scroll_offset = 0;
                        return;
                    }
                    KeyEvent::PageDown | KeyEvent::End => {
                        self.upload_scroll_offset = upload_count.saturating_sub(1);
                        return;
                    }
                    KeyEvent::Char('b') | KeyEvent::Char('f') => {
                        self.set_host_section(HostSection::Folders);
                        return;
                    }
                    _ => return,
                }
            }
            HostSection::Folders => {}
        }

        match key {
            KeyEvent::Up | KeyEvent::Char('k') => {
                if self.selected_host_folder_idx > 0 {
                    self.selected_host_folder_idx -= 1;
                }
            }
            KeyEvent::Down | KeyEvent::Char('j') => {
                if self.selected_host_folder_idx + 1 < self.host_folders.len() {
                    self.selected_host_folder_idx += 1;
                }
            }
            KeyEvent::Char('a') => {
                self.active_prompt = Some(InputPrompt::new(
                    InputPromptKind::AddHostFolder,
                    "Add Folder to Share (Read-Only)".to_string(),
                    "Enter local folder path to share into the ring:".to_string(),
                    String::new(),
                ));
            }
            KeyEvent::Char('F') => {
                self.active_prompt = Some(InputPrompt::new(
                    InputPromptKind::AddHostFile,
                    "Add File to Share (Read-Only)".to_string(),
                    "Enter local file path to share into the ring:".to_string(),
                    String::new(),
                ));
            }
            KeyEvent::Delete | KeyEvent::Char('d') => {
                self.clear_errors();
                if self.selected_host_folder_idx < self.host_folders.len() {
                    let target_folder = &self.host_folders[self.selected_host_folder_idx];
                    let is_last = self.host_folders.len() <= 1;
                    let folder_dl = self
                        .server_handle
                        .as_ref()
                        .map(|h| h.active_downloads_for_folder(target_folder))
                        .unwrap_or(0);
                    let active_dl = if is_last {
                        self.active_server_downloads().max(folder_dl)
                    } else {
                        folder_dl
                    };

                    if server_active && active_dl > 0 && !self.stop_server_confirmed {
                        self.stop_server_confirmed = true;
                        let action = if is_last {
                            "remove last share and stop sharing"
                        } else {
                            "abort transfer and remove share"
                        };
                        self.set_flash(format!(
                            "CRITICAL: Peer is downloading ({} active transfer{})! Press [Delete/d] again to {}.",
                            active_dl,
                            if active_dl == 1 { "" } else { "s" },
                            action
                        ));
                    } else if is_last && server_active {
                        self.stop_server_confirmed = false;
                        let removed = self.host_folders.remove(self.selected_host_folder_idx);
                        self.host_share_sizes.invalidate(&removed);
                        self.selected_host_folder_idx = 0;
                        self.toggle_server();
                        self.set_flash(format!(
                            "Removed last share '{}' and stopped sharing.",
                            clean_display_path(&removed)
                        ));
                    } else {
                        self.stop_server_confirmed = false;
                        let removed = self.host_folders.remove(self.selected_host_folder_idx);
                        self.host_share_sizes.invalidate(&removed);
                        if self.selected_host_folder_idx >= self.host_folders.len() {
                            self.selected_host_folder_idx =
                                self.host_folders.len().saturating_sub(1);
                        }
                        if let Some(ref handle) = self.server_handle {
                            let _ = handle.update_shared_folders(self.host_folders.clone());
                        }
                        self.set_flash(format!("Removed share '{}'", clean_display_path(&removed)));
                    }
                }
            }
            KeyEvent::Char('C') if !server_active => {
                self.clear_errors();
                self.host_folders.clear();
                self.host_share_sizes.clear();
                self.selected_host_folder_idx = 0;
                self.set_flash("Cleared shared items list.");
            }
            _ => {}
        }
    }

    pub fn render(&mut self, buf: &mut ScreenBuffer) {
        if !self.secret_confirmed {
            self.render_secret_setup_screen(buf);
            return;
        }

        let w = buf.width;
        let h = buf.height;

        // 1. Top Header & Navigation Bar (Rows 0..2)
        buf.fill_rect(0, 0, w, 1, Color::White, Color::DarkBlue);
        let brand = if self.test_mode {
            " LanShare TUI [TEST MODE] "
        } else {
            " LanShare TUI "
        };
        let b_len = buf.draw_text(0, 0, w, brand, Color::LightCyan, Color::DarkBlue, true);

        let active_dl_count = self
            .download_queue
            .iter()
            .filter(|i| {
                matches!(
                    i.status,
                    QueueItemStatus::Downloading | QueueItemStatus::Pending
                )
            })
            .count();
        let dl_count = if active_dl_count > 0 {
            active_dl_count
        } else if self.has_active_client_downloads() {
            1
        } else {
            0
        };
        let hosting_active = self.is_hosting_active();
        let upload_count = self.active_server_downloads();
        let tab1 = if dl_count > 0 {
            format!(" [1] Browse LAN ● ↓{} ", dl_count)
        } else {
            " [1] Browse LAN ".to_string()
        };
        let tab2 = if upload_count > 0 {
            format!(" [2] Share Folders ● ↑{} ", upload_count)
        } else if hosting_active {
            " [2] Share Folders ● ".to_string()
        } else {
            " [2] Share Folders ".to_string()
        };
        let tab1_w = UnicodeWidthStr::width(tab1.as_str());
        let tab2_w = UnicodeWidthStr::width(tab2.as_str());
        let t1_x = b_len + 1;
        let t2_x = t1_x + tab1_w + 1;
        if self.current_tab == TuiTab::Client {
            buf.draw_text(t1_x, 0, tab1_w, &tab1, Color::White, Color::Cyan, true);
            buf.draw_text(t2_x, 0, tab2_w, &tab2, Color::Gray, Color::DarkBlue, false);
        } else {
            buf.draw_text(t1_x, 0, tab1_w, &tab1, Color::Gray, Color::DarkBlue, false);
            buf.draw_text(t2_x, 0, tab2_w, &tab2, Color::White, Color::Cyan, true);
        }

        let right_help = if w >= 124 {
            "[?] About  [Tab] Switch  [q] Quit "
        } else {
            "[?] About  [q] Quit "
        };
        let right_help_w = UnicodeWidthStr::width(right_help);
        if w > t2_x + tab2_w + right_help_w {
            buf.draw_text(
                w - right_help_w,
                0,
                right_help_w,
                right_help,
                Color::Yellow,
                Color::DarkBlue,
                false,
            );
        }

        // 2. Unified LAN Secret Box (Rows 1..4)
        buf.draw_box(0, 1, w, 3, "LAN Secret", Color::Cyan, Color::Reset);
        let displayed_secret = if self.show_secret_plain {
            self.ring_secret.clone()
        } else {
            "•".repeat(self.ring_secret.chars().count().max(6))
        };
        let secret_line = format!(
            "Secret: [ {} ]   [e] Edit  [v] {}  [r] New  [y] Copy",
            displayed_secret,
            if self.show_secret_plain {
                "Hide"
            } else {
                "Show"
            }
        );
        buf.draw_text(
            2,
            2,
            w.saturating_sub(4),
            &secret_line,
            Color::Green,
            Color::Reset,
            true,
        );

        if let Some((ref flash, _)) = self.status_flash {
            let fw = flash.chars().count() + 2;
            if w > fw + 4 {
                buf.draw_text(w - fw - 2, 2, fw, flash, Color::Yellow, Color::Reset, true);
            }
        }

        // 3. Main Tab Area (Rows 4 .. h-1)
        let content_y = 4;
        let content_h = h.saturating_sub(5);
        match self.current_tab {
            TuiTab::Client => self.render_client_tab(buf, 0, content_y, w, content_h),
            TuiTab::Host => self.render_host_tab(buf, 0, content_y, w, content_h),
        }

        // 4. Bottom Keybinding Status Bar (Row h-1)
        let footer_y = h - 1;
        buf.fill_rect(0, footer_y, w, 1, Color::White, Color::DarkBlue);
        let footer_text = match self.current_tab {
            TuiTab::Client => match self.client_section {
                ClientSection::Browse => {
                    " ↑/↓/Wheel:Scroll  Space:Queue  Enter:Open  b:Browse  d:Downloads  l:Logs  p:Next PC  s:Scan  c:Cancel  ?:About"
                }
                ClientSection::Downloads => {
                    " ↑/↓/Wheel:Scroll  d/b/Esc:Browse  l:Logs  Del:Remove  c:Cancel  x:Clear Done  ?:About"
                }
                ClientSection::Logs => {
                    " ↑/↓/PgUp/PgDn/Wheel:Scroll  End:Live  l/b/Esc:Browse  d:Downloads  c:Clear  ?:About"
                }
            },
            TuiTab::Host => match self.effective_host_section() {
                HostSection::Folders => {
                    " S:Start/Stop Sharing  a:Add Folder  F:Add File  Del:Remove  u:Uploads  l:Logs  Y:Copy IP  ?:About"
                }
                HostSection::Uploads => {
                    " ↑/↓/Wheel:Scroll  u/f/Esc:Folders  l:Logs  S:Start/Stop  Y:Copy IP  ?:About"
                }
                HostSection::Logs => {
                    " ↑/↓/PgUp/PgDn/Wheel:Scroll  End:Live  l/f/Esc:Folders  u:Uploads  c:Clear  S:Start/Stop  ?:About"
                }
            },
        };
        buf.draw_text(
            0,
            footer_y,
            w,
            footer_text,
            Color::White,
            Color::DarkBlue,
            false,
        );

        // 5. Overlays / Modals
        if self.show_how_it_works {
            self.render_how_it_works_modal(buf);
        }
        if let Some(ref prompt) = self.active_prompt {
            self.render_input_prompt_modal(buf, prompt);
        }
    }

    fn render_client_tab(
        &mut self,
        buf: &mut ScreenBuffer,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) {
        // Reset header positions and ranges for mouse click detection
        self.last_browse_header_y = None;
        self.last_downloads_header_y = None;
        self.last_logs_header_y = None;
        self.last_browse_header_range = None;
        self.last_downloads_header_range = None;
        self.last_logs_header_range = None;

        // Row A: Vertical list of Computers on LAN & Destination Bar
        sort_peers_alphabetically(&mut self.discovered_peers);
        let peer_rows = self.discovered_peers.len().clamp(1, 3);
        let err_rows = if self.client_error.is_some() { 1 } else { 0 };
        let top_box_h = peer_rows + 3 + err_rows;
        buf.draw_box(
            x,
            y,
            w,
            top_box_h,
            "Computers on LAN ([s] Scan LAN  [p/←/→] Switch  [i] Direct IP  [o] Save Folder)",
            Color::Blue,
            Color::Reset,
        );

        if self.is_scanning {
            buf.draw_text(
                x + 2,
                y + 1,
                w.saturating_sub(4),
                "Scanning LAN for peers...",
                Color::LightCyan,
                Color::Reset,
                false,
            );
        } else if self.discovered_peers.is_empty() {
            buf.draw_text(
                x + 2,
                y + 1,
                w.saturating_sub(4),
                "(No computers listed yet — press [s] to Scan LAN or [i] for Direct IP)",
                Color::Gray,
                Color::Reset,
                false,
            );
        } else {
            for (idx, p) in self.discovered_peers.iter().take(peer_rows).enumerate() {
                let is_sel = self.client_connected
                    && !self.client_connection_lost
                    && self.client_ip == p.ip
                    && self.client_port == p.port;
                let own_tag = if self.is_own_peer(p) {
                    " (This PC)"
                } else {
                    ""
                };
                let has_duplicate_ip = self
                    .discovered_peers
                    .iter()
                    .filter(|o| o.ip == p.ip)
                    .count()
                    > 1;
                let addr_label = if has_duplicate_ip || p.port != DEFAULT_TCP_PORT {
                    format!("{}:{}", p.ip, p.port)
                } else {
                    p.ip.clone()
                };
                let marker = if is_sel { "[*]" } else { "[ ]" };
                let row_str = format!(
                    " {} {}. {}{} ({})",
                    marker,
                    idx + 1,
                    p.host_name,
                    own_tag,
                    addr_label
                );
                let fg = if is_sel {
                    Color::Green
                } else {
                    Color::LightCyan
                };
                buf.draw_text(
                    x + 2,
                    y + 1 + idx,
                    w.saturating_sub(4),
                    &row_str,
                    fg,
                    Color::Reset,
                    is_sel,
                );
            }
        }

        let dest_line = format!("Save To: {}", clean_display_path(&self.client_dest_folder));
        buf.draw_text(
            x + 2,
            y + 1 + peer_rows,
            w.saturating_sub(4),
            &dest_line,
            Color::Gray,
            Color::Reset,
            false,
        );

        if let Some(ref err) = self.client_error {
            buf.draw_text(
                x + 2,
                y + 2 + peer_rows,
                w.saturating_sub(4),
                &format!("[!] {}", err),
                Color::Red,
                Color::Reset,
                true,
            );
        }

        // Accordion Dimensions:
        // Top section takes top_box_h.
        // There are 3 sections: Browse, Downloads, Logs.
        // Exactly ONE section is expanded; the other TWO are collapsed into 2-line framed header boxes.
        let content_y = y + top_box_h;
        let content_h = h.saturating_sub(top_box_h);
        let expanded_h = content_h.saturating_sub(4).max(4);

        let mut cur_y = content_y;

        // --------------------------------------------------------------------
        // 1. Browse Section (Remote Files)
        // --------------------------------------------------------------------
        if self.client_section == ClientSection::Browse {
            let has_browser_view = self.client_connected || !self.client_file_list.is_empty();
            self.last_browse_header_y = Some(cur_y);
            self.last_browse_header_range = Some((cur_y, cur_y + expanded_h.saturating_sub(1)));
            let browser_title = if has_browser_view {
                let status_tag = if self.client_connection_lost {
                    " [HOST UNAVAILABLE]"
                } else {
                    ""
                };
                format!(
                    "▼ Remote Files — {} — /{}{}",
                    self.selected_peer_name, self.client_current_path, status_tag
                )
            } else {
                "▼ Remote Files (Not Connected)".to_string()
            };
            buf.draw_box(
                x,
                cur_y,
                w,
                expanded_h,
                &browser_title,
                Color::Cyan,
                Color::Reset,
            );

            let show_spinner = crate::core::should_show_loading_spinner(
                self.client_loading,
                self.client_loading_started_at,
            );
            if !has_browser_view {
                if show_spinner {
                    let spin_y = cur_y + (expanded_h / 2).max(1);
                    let spin_x = x + (w / 2).saturating_sub(1);
                    buf.draw_text(
                        spin_x,
                        spin_y,
                        w.saturating_sub(4),
                        current_tui_spinner_frame(),
                        Color::Cyan,
                        Color::Reset,
                        true,
                    );
                } else if !self.client_loading {
                    let msg = if !self.discovered_peers.is_empty() {
                        "Press [p] (or ←/→) to select a computer above, [s] to Scan LAN, or [i] for Direct IP."
                    } else {
                        "Press [s] to Scan LAN or [i] to connect via Direct IP."
                    };
                    buf.draw_text(
                        x + 2,
                        cur_y + 1,
                        w.saturating_sub(4),
                        msg,
                        Color::Yellow,
                        Color::Reset,
                        false,
                    );
                }
            } else {
                let hdr_y = cur_y + 1;
                let nav_info = if self.client_connection_lost {
                    format!(
                        "Path: /{}   ({} items)   [Host unavailable — actions disabled]",
                        self.client_current_path,
                        self.client_file_list.len()
                    )
                } else {
                    format!(
                        "Path: /{}   ({} items)   [Bksp/u] Up   [F5] Refresh   [Space] Queue Selected",
                        self.client_current_path,
                        self.client_file_list.len()
                    )
                };
                buf.draw_text(
                    x + 2,
                    hdr_y,
                    w.saturating_sub(4),
                    &nav_info,
                    if self.client_connection_lost {
                        Color::Red
                    } else {
                        Color::Yellow
                    },
                    Color::Reset,
                    false,
                );

                let col_hdr_y = cur_y + 2;
                let col_hdr = format!(
                    " {:<36} {:>10}  {:<16}  {:<8}",
                    "NAME", "SIZE", "MODIFIED", "STATUS"
                );
                buf.draw_text(
                    x + 2,
                    col_hdr_y,
                    w.saturating_sub(4),
                    &col_hdr,
                    Color::White,
                    Color::DarkGray,
                    true,
                );

                let list_start_y = cur_y + 3;
                let visible_rows = expanded_h.saturating_sub(4).max(1);

                if self.selected_file_idx < self.file_scroll_offset {
                    self.file_scroll_offset = self.selected_file_idx;
                } else if self.selected_file_idx >= self.file_scroll_offset + visible_rows {
                    self.file_scroll_offset = self.selected_file_idx + 1 - visible_rows;
                }

                if self.client_loading && self.client_file_list.is_empty() {
                    if crate::core::should_show_loading_spinner(
                        self.client_loading,
                        self.client_loading_started_at,
                    ) {
                        let spin_y = list_start_y + visible_rows.saturating_sub(1) / 3;
                        let spin_x = x + (w / 2).saturating_sub(1);
                        buf.draw_text(
                            spin_x,
                            spin_y,
                            w.saturating_sub(4),
                            current_tui_spinner_frame(),
                            Color::Cyan,
                            Color::Reset,
                            true,
                        );
                    }
                } else if self.client_file_list.is_empty() {
                    buf.draw_text(
                        x + 2,
                        list_start_y,
                        w.saturating_sub(4),
                        "(This folder is empty)",
                        Color::DarkGray,
                        Color::Reset,
                        false,
                    );
                } else {
                    for row_idx in 0..visible_rows {
                        let item_idx = self.file_scroll_offset + row_idx;
                        let Some(entry) = self.client_file_list.get(item_idx) else {
                            break;
                        };
                        let row_y = list_start_y + row_idx;
                        let is_selected = item_idx == self.selected_file_idx;

                        let row_subpath = if self.client_current_path.is_empty() {
                            entry.name.clone()
                        } else {
                            format!("{}/{}", self.client_current_path, entry.name)
                        };

                        let queue_state = self
                            .download_queue
                            .iter()
                            .find(|i| {
                                i.conn_ctx.ip == self.client_ip
                                    && i.remote_subpath == row_subpath
                                    && matches!(
                                        i.status,
                                        QueueItemStatus::Pending | QueueItemStatus::Downloading
                                    )
                            })
                            .map(|i| &i.status);

                        let status_str = match queue_state {
                            Some(QueueItemStatus::Downloading) => "[ACTIVE]",
                            Some(QueueItemStatus::Pending) => "[QUEUED]",
                            _ => "",
                        };

                        let icon_name = if entry.is_dir {
                            format!("{}/", entry.name)
                        } else {
                            entry.name.clone()
                        };

                        let size_str = if entry.is_dir {
                            "<DIR>".to_string()
                        } else {
                            format_file_size(entry.size)
                        };

                        let date_str = if entry.modified_timestamp > 0 {
                            Local
                                .timestamp_opt(entry.modified_timestamp as i64, 0)
                                .single()
                                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                                .unwrap_or_else(|| "-".to_string())
                        } else {
                            "-".to_string()
                        };

                        let truncated_name: String = icon_name.chars().take(35).collect();
                        let line = format!(
                            " {:<36} {:>10}  {:<16}  {:<8}",
                            truncated_name, size_str, date_str, status_str
                        );

                        let (fg, bg, bold) = if is_selected {
                            (Color::White, Color::Cyan, true)
                        } else if matches!(queue_state, Some(QueueItemStatus::Downloading)) {
                            (Color::Green, Color::Reset, true)
                        } else if matches!(queue_state, Some(QueueItemStatus::Pending)) {
                            (Color::Yellow, Color::Reset, false)
                        } else if entry.is_dir {
                            (Color::LightCyan, Color::Reset, true)
                        } else {
                            (Color::Gray, Color::Reset, false)
                        };

                        buf.fill_rect(x + 1, row_y, w.saturating_sub(2), 1, fg, bg);
                        buf.draw_text(x + 2, row_y, w.saturating_sub(4), &line, fg, bg, bold);
                    }
                }
            }
            cur_y += expanded_h;
        } else {
            self.last_browse_header_y = Some(cur_y);
            self.last_browse_header_range = Some((cur_y, cur_y + 1));
            let has_browser_view = self.client_connected || !self.client_file_list.is_empty();
            let browse_summary = if has_browser_view {
                let status_tag = if self.client_connection_lost {
                    " [HOST UNAVAILABLE]"
                } else {
                    ""
                };
                format!(
                    "▶ [b] Remote Files: {} (/{}) — {} item(s){}  [Press 'b' to expand]",
                    self.selected_peer_name,
                    self.client_current_path,
                    self.client_file_list.len(),
                    status_tag
                )
            } else {
                "▶ [b] Remote Files (Not Connected)  [Press 'b' to expand]".to_string()
            };
            buf.draw_box(x, cur_y, w, 2, &browse_summary, Color::Cyan, Color::Reset);
            cur_y += 2;
        }

        // --------------------------------------------------------------------
        // 2. Downloads Section (Queue & Live Progress)
        // --------------------------------------------------------------------
        let pending_count = self
            .download_queue
            .iter()
            .filter(|i| i.status == QueueItemStatus::Pending)
            .count();
        let done_count = self
            .download_queue
            .iter()
            .filter(|i| i.status == QueueItemStatus::Completed)
            .count();

        let QueueEtaSummary {
            active_remaining,
            total_remaining_bytes,
            active_speed,
            active_eta,
            total_eta,
            ..
        } = compute_queue_etas(
            &self.download_queue,
            self.active_queue_id,
            self.active_progress.as_ref(),
            &mut self.active_eta_stabilizer,
            &mut self.total_eta_stabilizer,
        );

        if self.client_section == ClientSection::Downloads {
            self.last_downloads_header_y = Some(cur_y);
            self.last_downloads_header_range = Some((cur_y, cur_y + expanded_h.saturating_sub(1)));
            let total_eta_str =
                if total_remaining_bytes > 0 || self.active_progress.is_some() || pending_count > 0
                {
                    let tot_val = total_eta
                        .filter(|_| total_remaining_bytes > 0)
                        .map(format_remaining_time)
                        .unwrap_or_else(|| "--".to_string());
                    format!(" | Total ETA: {:<5}", tot_val)
                } else {
                    String::new()
                };
            let q_title = format!(
                "▼ Download Queue — {} pending, {} completed{} | [d] Collapse  [c] Cancel  [Del] Remove  [x] Clear Done",
                pending_count, done_count, total_eta_str
            );
            buf.draw_box(
                x,
                cur_y,
                w,
                expanded_h,
                &q_title,
                Color::Green,
                Color::Reset,
            );

            if let Some(ref prog) = self.active_progress {
                let ratio = if prog.bytes_total > 0 {
                    (prog.bytes_done as f32 / prog.bytes_total as f32).clamp(0.0, 1.0)
                } else {
                    1.0
                };
                let eta_val = active_eta
                    .filter(|_| active_remaining > 0)
                    .map(format_remaining_time)
                    .unwrap_or_else(|| "--".to_string());
                let eta_info = format!(" | ETA: {:<5}", eta_val);
                let total_info = if pending_count > 0 && total_remaining_bytes > 0 {
                    let tot_val = total_eta
                        .map(format_remaining_time)
                        .unwrap_or_else(|| "--".to_string());
                    format!(" | Total: {:<5}", tot_val)
                } else {
                    String::new()
                };
                let target_label =
                    if prog.file_name == prog.selected_target || prog.selected_target.is_empty() {
                        prog.file_name.clone()
                    } else {
                        format!("{} ({})", prog.file_name, prog.selected_target)
                    };
                let file_num_w = prog.total_files.max(1).to_string().len();
                let target_info = format!(
                    "{:>6.1} MB/s{}{} | {:>10} / {:<10} | File ({:>file_num_w$}/{}) — {}",
                    prog.speed_mbps,
                    eta_info,
                    total_info,
                    format_file_size(prog.bytes_done),
                    format_file_size(prog.bytes_total),
                    prog.current_file,
                    prog.total_files,
                    target_label,
                );
                let is_waiting = crate::core::is_transfer_waiting_status(&prog.file_name);
                let text_color = if is_waiting {
                    Color::Yellow
                } else {
                    Color::White
                };
                let gauge_color = if is_waiting {
                    Color::Yellow
                } else {
                    Color::Green
                };
                buf.draw_text(
                    x + 2,
                    cur_y + 1,
                    w.saturating_sub(4),
                    &target_info,
                    text_color,
                    Color::Reset,
                    true,
                );
                let pct_label = format!("{:>3.0}%  (ETA: {:<5})", ratio * 100.0, eta_val);
                buf.draw_gauge(
                    x + 2,
                    cur_y + 2,
                    w.saturating_sub(4),
                    ratio,
                    &pct_label,
                    gauge_color,
                    Color::Reset,
                );
            } else if self.download_queue.is_empty() {
                buf.draw_text(
                    x + 2,
                    cur_y + 1,
                    w.saturating_sub(4),
                    "Queue is empty. Select files in Browse and press [Space] to queue downloads.",
                    Color::DarkGray,
                    Color::Reset,
                    false,
                );
            }

            let q_list_start = if self.active_progress.is_some() {
                cur_y + 3
            } else {
                cur_y + 1
            };
            let max_q_rows = (cur_y + expanded_h)
                .saturating_sub(1)
                .saturating_sub(q_list_start);

            if !self.download_queue.is_empty() {
                if self.selected_queue_idx >= self.download_queue.len() {
                    self.selected_queue_idx = self.download_queue.len() - 1;
                }
                let mut visible_items: Vec<_> = self
                    .download_queue
                    .iter()
                    .filter(|i| !matches!(i.status, QueueItemStatus::Cancelled))
                    .collect();
                visible_items.sort_by_key(|item| queue_status_sort_rank(&item.status));
                if self.selected_queue_idx >= visible_items.len() && !visible_items.is_empty() {
                    self.selected_queue_idx = visible_items.len() - 1;
                }
                if self.selected_queue_idx < self.queue_scroll_offset {
                    self.queue_scroll_offset = self.selected_queue_idx;
                } else if max_q_rows > 0
                    && self.selected_queue_idx >= self.queue_scroll_offset + max_q_rows
                {
                    self.queue_scroll_offset = self.selected_queue_idx + 1 - max_q_rows;
                }

                for row_idx in 0..max_q_rows {
                    let item_idx = self.queue_scroll_offset + row_idx;
                    let Some(item) = visible_items.get(item_idx) else {
                        break;
                    };
                    let row_y = q_list_start + row_idx;
                    let is_sel = item_idx == self.selected_queue_idx;
                    let badge = match &item.status {
                        QueueItemStatus::Downloading => ("[ACTIVE] ", Color::Green),
                        QueueItemStatus::Pending => ("[PENDING]", Color::Yellow),
                        QueueItemStatus::Completed => ("[DONE]   ", Color::Cyan),
                        QueueItemStatus::Cancelled => ("[CANCEL] ", Color::DarkGray),
                        QueueItemStatus::Failed(_) => ("[FAILED] ", Color::Red),
                    };
                    let kind_icon = if item.entry.is_dir { "[DIR]" } else { "[FILE]" };
                    let est_col = match &item.status {
                        QueueItemStatus::Downloading => {
                            // Active ETA is shown in active download header, not needed in list
                            String::new()
                        }
                        QueueItemStatus::Pending => {
                            let item_bytes = item.total_bytes.unwrap_or(item.entry.size);
                            if item_bytes > 0 {
                                let sz_str = format_file_size(item_bytes);
                                let prefix = if item.entry.is_dir {
                                    format!("Folder ({})", sz_str)
                                } else {
                                    sz_str
                                };
                                if let Some(spd) = active_speed {
                                    if let Some(item_s) =
                                        estimate_remaining_seconds(item_bytes, spd)
                                    {
                                        format!(
                                            "{} (ETA: {:<4})",
                                            prefix,
                                            format_remaining_time(item_s)
                                        )
                                    } else {
                                        prefix
                                    }
                                } else {
                                    prefix
                                }
                            } else if item.entry.is_dir {
                                "Folder (sizing...)".to_string()
                            } else {
                                String::new()
                            }
                        }
                        QueueItemStatus::Completed => {
                            let final_bytes = item.total_bytes.unwrap_or(item.entry.size);
                            let sz_str = format_file_size(final_bytes);
                            let took_str = item.elapsed_duration.map(|dur| {
                                if dur.as_secs() == 0 {
                                    "< 1s".to_string()
                                } else {
                                    format_remaining_time(dur.as_secs())
                                }
                            });
                            let time_str = item.completed_at.map(format_completed_timestamp);

                            match (took_str, time_str) {
                                (Some(took), Some(ts)) => {
                                    format!("{} (took {} • {})", sz_str, took, ts)
                                }
                                (Some(took), None) => format!("{} (took {})", sz_str, took),
                                (None, Some(ts)) => format!("{} ({})", sz_str, ts),
                                (None, None) => sz_str,
                            }
                        }
                        _ => String::new(),
                    };
                    let q_line = format!(
                        "{}  {:<6} {:<34} | {}  (from {})",
                        badge.0, kind_icon, est_col, item.entry.name, item.peer_name
                    );
                    let (fg, bg) = if is_sel {
                        (Color::White, Color::Cyan)
                    } else {
                        (badge.1, Color::Reset)
                    };
                    buf.fill_rect(x + 1, row_y, w.saturating_sub(2), 1, fg, bg);
                    buf.draw_text(x + 2, row_y, w.saturating_sub(4), &q_line, fg, bg, is_sel);
                }
            }

            cur_y += expanded_h;
        } else {
            self.last_downloads_header_y = Some(cur_y);
            self.last_downloads_header_range = Some((cur_y, cur_y + 1));
            let dl_summary = if let Some(ref prog) = self.active_progress {
                let ratio = if prog.bytes_total > 0 {
                    (prog.bytes_done as f32 / prog.bytes_total as f32).clamp(0.0, 1.0)
                } else {
                    1.0
                };
                let act_eta_val = active_eta
                    .filter(|_| active_remaining > 0)
                    .map(format_remaining_time)
                    .unwrap_or_else(|| "--".to_string());
                let act_eta_str = format!(" | ETA: {:<5}", act_eta_val);
                let tot_eta_str = if pending_count > 0 && total_remaining_bytes > active_remaining {
                    let tot_val = total_eta
                        .map(format_remaining_time)
                        .unwrap_or_else(|| "--".to_string());
                    format!(" | Total: {:<5}", tot_val)
                } else {
                    String::new()
                };
                format!(
                    "▶ [d] Downloads: {:>3.0}% | {:>6.1} MB/s{}{} | {:>2} pending, {:>2} done [Press 'd' to expand] — '{}'",
                    ratio * 100.0,
                    prog.speed_mbps,
                    act_eta_str,
                    tot_eta_str,
                    pending_count,
                    done_count,
                    prog.file_name,
                )
            } else if pending_count > 0 || done_count > 0 {
                format!(
                    "▶ [d] Downloads: {} pending, {} completed  [Press 'd' to expand]",
                    pending_count, done_count
                )
            } else {
                "▶ [d] Downloads: (Queue empty)  [Press 'd' to expand]".to_string()
            };
            buf.draw_box(x, cur_y, w, 2, &dl_summary, Color::Green, Color::Reset);
            cur_y += 2;
        }

        // --------------------------------------------------------------------
        // 3. Activity Log Section
        // --------------------------------------------------------------------
        if self.client_section == ClientSection::Logs {
            self.last_logs_header_y = Some(cur_y);
            self.last_logs_header_range = Some((cur_y, cur_y + expanded_h.saturating_sub(1)));
            let log_full_path = clean_display_path(&crate::core::get_log_file_path());
            let scroll_tag = if self.log_scroll_offset > 0 {
                format!(" [Scrolled +{} - 'End' for live]", self.log_scroll_offset)
            } else {
                String::new()
            };
            let title = format!(
                "▼ Client Activity Log{} — [l] Collapse  [c] Clear  [↑/↓/PgUp/PgDn] Scroll",
                scroll_tag
            );
            buf.draw_box(
                x,
                cur_y,
                w,
                expanded_h,
                &title,
                Color::DarkGray,
                Color::Reset,
            );

            buf.draw_text(
                x + 2,
                cur_y + 1,
                w.saturating_sub(4),
                &format!("Log file: {}", log_full_path),
                Color::LightCyan,
                Color::Reset,
                false,
            );

            let rows = expanded_h.saturating_sub(3);
            let total_logs = self.client_logs.len();
            let max_offset = total_logs.saturating_sub(rows);
            if self.log_scroll_offset > max_offset {
                self.log_scroll_offset = max_offset;
            }
            let end_idx = total_logs.saturating_sub(self.log_scroll_offset);
            let start_idx = end_idx.saturating_sub(rows);

            for (i, idx) in (start_idx..end_idx).enumerate() {
                if let Some(line) = self.client_logs.get(idx) {
                    buf.draw_text(
                        x + 2,
                        cur_y + 2 + i,
                        w.saturating_sub(4),
                        line,
                        Color::Gray,
                        Color::Reset,
                        false,
                    );
                }
            }
        } else {
            self.last_logs_header_y = Some(cur_y);
            self.last_logs_header_range = Some((cur_y, cur_y + 1));
            let last_log = self
                .client_logs
                .back()
                .map(|s| s.as_str())
                .unwrap_or("(No activity yet)");
            let log_summary = format!("▶ [l] Activity Log: {}  [Press 'l' to expand]", last_log);
            buf.draw_box(x, cur_y, w, 2, &log_summary, Color::DarkGray, Color::Reset);
        }
    }

    fn render_host_tab(&mut self, buf: &mut ScreenBuffer, x: usize, y: usize, w: usize, h: usize) {
        let server_active = self
            .server_handle
            .as_ref()
            .map(|sh| sh.is_running.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false);

        // Top section: Server Status & Controls (height 6)
        let status_title = if server_active {
            "Sharing Status: ACTIVE ON LAN"
        } else {
            "Sharing Status: STOPPED"
        };
        let status_color = if server_active {
            Color::Green
        } else {
            Color::Yellow
        };
        buf.draw_box(x, y, w, 6, status_title, status_color, Color::Reset);

        if server_active {
            if let Some(ref handle) = self.server_handle {
                let line1 = format!(
                    "Sharing {} folder(s) on LAN   |   Host IP: {}   [Y] Copy IP",
                    handle.current_shared_folders().len(),
                    handle.local_ip
                );
                buf.draw_text(
                    x + 2,
                    y + 1,
                    w.saturating_sub(4),
                    &line1,
                    Color::Green,
                    Color::Reset,
                    true,
                );
                buf.draw_text(
                    x + 2,
                    y + 2,
                    w.saturating_sub(4),
                    "Read-Only access on LAN",
                    Color::LightCyan,
                    Color::Reset,
                    false,
                );

                if self.stop_server_confirmed {
                    let active_dl = self.active_server_downloads();
                    buf.draw_text(
                        x + 2,
                        y + 3,
                        w.saturating_sub(4),
                        &format!(
                            "ALERT: Someone is downloading ({} active transfer{})!",
                            active_dl,
                            if active_dl == 1 { "" } else { "s" }
                        ),
                        Color::Red,
                        Color::Reset,
                        true,
                    );
                    buf.draw_text(
                        x + 2,
                        y + 4,
                        w.saturating_sub(4),
                        "Press [S] again to ABORT transfer & STOP sharing",
                        Color::Red,
                        Color::Reset,
                        true,
                    );
                } else {
                    buf.draw_text(
                        x + 2,
                        y + 4,
                        w.saturating_sub(4),
                        "Press [S] to STOP Sharing",
                        Color::Red,
                        Color::Reset,
                        true,
                    );
                }
            }
        } else {
            buf.draw_text(
                x + 2,
                y + 1,
                w.saturating_sub(4),
                "Hosted folders are shared read-only on your LAN.",
                Color::Gray,
                Color::Reset,
                false,
            );
            if let Some(ref err) = self.host_error {
                buf.draw_text(
                    x + 2,
                    y + 2,
                    w.saturating_sub(4),
                    &format!("[!] {}", err),
                    Color::Red,
                    Color::Reset,
                    true,
                );
            }
            let local_ip = self
                .local_ips
                .first()
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".to_string());
            buf.draw_text(
                x + 2,
                y + 3,
                w.saturating_sub(4),
                &format!("Host IP: {}   [Y] Copy IP", local_ip),
                Color::LightCyan,
                Color::Reset,
                false,
            );
            if !self.host_folders.is_empty() {
                buf.draw_text(
                    x + 2,
                    y + 4,
                    w.saturating_sub(4),
                    "Press [S] to START Sharing",
                    Color::Green,
                    Color::Reset,
                    true,
                );
            } else {
                buf.draw_text(
                    x + 2,
                    y + 4,
                    w.saturating_sub(4),
                    "Add folders [a] or files [F] below to start sharing",
                    Color::DarkGray,
                    Color::Reset,
                    false,
                );
            }
        }

        // Bottom accordion sections: Shared Folders, Uploads (collapsed by default), & Server Activity Log
        self.last_host_folders_header_range = None;
        self.last_host_uploads_header_range = None;
        self.last_host_logs_header_range = None;

        let folders_y = y + 6;
        let body_h = h.saturating_sub(6);
        let collapsed_h = 2usize;
        let expanded_h = body_h.saturating_sub(collapsed_h * 2).max(4);
        let log_full_path = clean_display_path(&crate::core::get_log_file_path());
        let active_sec = self.effective_host_section();

        let active_uploads = self
            .server_handle
            .as_ref()
            .map(|h| h.active_uploads_snapshot())
            .unwrap_or_default();
        let upload_total_eta = crate::core::compute_active_uploads_total_eta(
            &active_uploads,
            &mut self.upload_total_eta_stabilizer,
        );
        if self.upload_scroll_offset >= active_uploads.len() {
            self.upload_scroll_offset = active_uploads.len().saturating_sub(1);
        }

        let mut cur_y = folders_y;

        // 1. Folders & Files to Share Section
        if active_sec == HostSection::Folders {
            self.last_host_folders_header_range =
                Some((cur_y, cur_y + expanded_h.saturating_sub(1)));
            buf.draw_box(
                x,
                cur_y,
                w,
                expanded_h,
                "▼ Folders to Share on LAN ([a] Add Folder  [F] Add File  [Del/d] Remove  [C] Clear)",
                Color::Cyan,
                Color::Reset,
            );

            if self.host_folders.is_empty() {
                buf.draw_text(
                    x + 2,
                    cur_y + 2,
                    w.saturating_sub(4),
                    "No items added yet. Press [a] to add a folder or [F] to add a file.",
                    Color::Yellow,
                    Color::Reset,
                    false,
                );
            } else {
                let max_rows = expanded_h.saturating_sub(2);
                for (idx, folder) in self.host_folders.iter().take(max_rows).enumerate() {
                    let is_sel = idx == self.selected_host_folder_idx;
                    let (fg, bg) = if is_sel {
                        (Color::White, Color::Cyan)
                    } else {
                        (Color::White, Color::Reset)
                    };
                    let row_y = cur_y + 1 + idx;
                    buf.fill_rect(x + 1, row_y, w.saturating_sub(2), 1, fg, bg);
                    let clean_folder = clean_path(
                        &std::fs::canonicalize(folder).unwrap_or_else(|_| folder.clone()),
                    );
                    let up_cnt = active_uploads
                        .iter()
                        .filter(|u| {
                            clean_path(
                                &std::fs::canonicalize(&u.folder_root)
                                    .unwrap_or_else(|_| u.folder_root.clone()),
                            ) == clean_folder
                        })
                        .count();
                    let kind_tag = if folder.is_dir() { "[DIR]" } else { "[FILE]" };
                    let size_part = match self.host_share_sizes.get_or_request(folder, None) {
                        SharedPathSizeStatus::Ready(bytes) => {
                            format!(" ({})", format_file_size(bytes))
                        }
                        SharedPathSizeStatus::Calculating => " (...)".to_string(),
                        SharedPathSizeStatus::Unavailable => String::new(),
                    };
                    let suffix = if up_cnt > 0 {
                        format!("  [↑ {} uploading]", up_cnt)
                    } else {
                        String::new()
                    };
                    let label = format!(
                        "  {}. {} {}{}{}",
                        idx + 1,
                        kind_tag,
                        clean_display_path(folder),
                        size_part,
                        suffix
                    );
                    buf.draw_text(x + 2, row_y, w.saturating_sub(4), &label, fg, bg, is_sel);
                }
            }
            cur_y += expanded_h;
        } else {
            self.last_host_folders_header_range = Some((cur_y, cur_y + 1));
            let folders_summary = if active_sec == HostSection::Logs {
                format!(
                    "▶ [l/f] Folders to Share: {} folder(s)  [Press 'l' to collapse logs]",
                    self.host_folders.len()
                )
            } else {
                format!(
                    "▶ [f] Folders to Share: {} folder(s)  [Press 'f' to expand]",
                    self.host_folders.len()
                )
            };
            buf.draw_box(
                x,
                cur_y,
                w,
                collapsed_h,
                &folders_summary,
                Color::Cyan,
                Color::Reset,
            );
            cur_y += collapsed_h;
        }

        // 2. Active Uploads Section (collapsed by default like Client Downloads)
        let tot_eta_part = if !active_uploads.is_empty() {
            let val = upload_total_eta
                .map(format_remaining_time)
                .unwrap_or_else(|| "--".to_string());
            format!(" | Total ETA: {:<5}", val)
        } else {
            String::new()
        };
        if active_sec == HostSection::Uploads {
            self.last_host_uploads_header_range =
                Some((cur_y, cur_y + expanded_h.saturating_sub(1)));
            let utitle = format!(
                "▼ Uploads — Active: {}{} — [u] Collapse  [f] Folders  [↑/↓] Scroll",
                active_uploads.len(),
                tot_eta_part
            );
            buf.draw_box(x, cur_y, w, expanded_h, &utitle, Color::Green, Color::Reset);
            let inner_h = expanded_h.saturating_sub(2);
            if active_uploads.is_empty() && inner_h > 0 {
                buf.draw_text(
                    x + 2,
                    cur_y + 1,
                    w.saturating_sub(4),
                    "No active uploads.",
                    Color::DarkGray,
                    Color::Reset,
                    false,
                );
            } else {
                let mut row_off = 0usize;
                for upload in active_uploads.iter().skip(self.upload_scroll_offset) {
                    if row_off >= inner_h {
                        break;
                    }
                    let pct = if upload.total_size > 0 {
                        (upload.bytes_sent as f64 / upload.total_size as f64).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    let rem_bytes = upload.total_size.saturating_sub(upload.bytes_sent);
                    let eta_str = if upload.bytes_sent >= upload.total_size && upload.total_size > 0
                    {
                        "0s".to_string()
                    } else if let Some(s) = estimate_remaining_seconds(rem_bytes, upload.speed_mbps)
                    {
                        format_remaining_time(s)
                    } else {
                        "--".to_string()
                    };
                    let speed_col = format!("{:>6.1} MB/s", upload.speed_mbps);
                    let eta_col = format!("ETA: {:<5}", eta_str);
                    let size_col = format!(
                        "{:>10} / {:<10}",
                        format_file_size(upload.bytes_sent),
                        format_file_size(upload.total_size),
                    );
                    let line = format!(
                        "↑ {} | {} | {} | {} ({})",
                        speed_col, eta_col, size_col, upload.file_name, upload.peer,
                    );
                    buf.draw_text(
                        x + 2,
                        cur_y + 1 + row_off,
                        w.saturating_sub(4),
                        &line,
                        Color::White,
                        Color::Reset,
                        false,
                    );
                    row_off += 1;
                    if row_off < inner_h {
                        let gauge_label = format!("{:.0}%", pct * 100.0);
                        buf.draw_gauge(
                            x + 2,
                            cur_y + 1 + row_off,
                            w.saturating_sub(4),
                            pct as f32,
                            &gauge_label,
                            Color::Green,
                            Color::Reset,
                        );
                        row_off += 1;
                    }
                }
            }
            cur_y += expanded_h;
        } else if cur_y + 1 < y + h {
            self.last_host_uploads_header_range = Some((cur_y, cur_y + 1));
            let uploads_summary = match active_uploads.as_slice() {
                [] => "▶ [u] Uploads: (No active uploads)  [Press 'u' to expand]".to_string(),
                [single] => {
                    let pct = if single.total_size > 0 {
                        (single.bytes_sent as f64 / single.total_size as f64).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    let rem = single.total_size.saturating_sub(single.bytes_sent);
                    let eta_str = if single.bytes_sent >= single.total_size && single.total_size > 0
                    {
                        " | ETA: 0s   ".to_string()
                    } else if let Some(s) = estimate_remaining_seconds(rem, single.speed_mbps) {
                        format!(" | ETA: {:<5}", format_remaining_time(s))
                    } else {
                        " | ETA: --   ".to_string()
                    };
                    format!(
                        "▶ [u] Uploads: 1 active{} | {:>3.0}% | {:>6.1} MB/s{}  [Press 'u' to expand] — '{}'",
                        tot_eta_part,
                        pct * 100.0,
                        single.speed_mbps,
                        eta_str,
                        single.file_name,
                    )
                }
                _ => {
                    let total_speed_mbps: f32 = active_uploads.iter().map(|u| u.speed_mbps).sum();
                    format!(
                        "▶ [u] Uploads: {} active (multiple){} | {:>6.1} MB/s total  [Press 'u' to expand]",
                        active_uploads.len(),
                        tot_eta_part,
                        total_speed_mbps,
                    )
                }
            };
            buf.draw_box(
                x,
                cur_y,
                w,
                collapsed_h,
                &uploads_summary,
                Color::Green,
                Color::Reset,
            );
            cur_y += collapsed_h;
        }

        // 3. Server Activity Log Section
        if active_sec == HostSection::Logs {
            self.last_host_logs_header_range = Some((cur_y, cur_y + expanded_h.saturating_sub(1)));
            let scroll_tag = if self.server_log_scroll_offset > 0 {
                format!(
                    " [Scrolled +{} - 'End' for live]",
                    self.server_log_scroll_offset
                )
            } else {
                String::new()
            };
            let title = format!(
                "▼ Server Activity Log{} — [l] Collapse  [c] Clear  [↑/↓/PgUp/PgDn] Scroll",
                scroll_tag
            );
            buf.draw_box(
                x,
                cur_y,
                w,
                expanded_h,
                &title,
                Color::DarkGray,
                Color::Reset,
            );

            buf.draw_text(
                x + 2,
                cur_y + 1,
                w.saturating_sub(4),
                &format!("Log file: {}", log_full_path),
                Color::LightCyan,
                Color::Reset,
                false,
            );

            let rows = expanded_h.saturating_sub(3);
            let total_logs = self.server_logs.len();
            let max_offset = total_logs.saturating_sub(rows);
            if self.server_log_scroll_offset > max_offset {
                self.server_log_scroll_offset = max_offset;
            }
            let end_idx = total_logs.saturating_sub(self.server_log_scroll_offset);
            let start_idx = end_idx.saturating_sub(rows);

            for (i, idx) in (start_idx..end_idx).enumerate() {
                if let Some(evt) = self.server_logs.get(idx) {
                    let fg = if evt.is_error {
                        Color::Red
                    } else {
                        Color::Gray
                    };
                    let line = format!("[{}] {}", evt.timestamp, evt.message);
                    buf.draw_text(
                        x + 2,
                        cur_y + 2 + i,
                        w.saturating_sub(4),
                        &line,
                        fg,
                        Color::Reset,
                        false,
                    );
                }
            }
        } else if cur_y + 1 < y + h {
            self.last_host_logs_header_range = Some((cur_y, cur_y + 1));
            let last_log = self
                .server_logs
                .back()
                .map(|evt| format!("[{}] {}", evt.timestamp, evt.message))
                .unwrap_or_else(|| "(No activity yet)".to_string());
            let log_summary = format!("▶ [l] Activity Log: {}  [Press 'l' to expand]", last_log);
            buf.draw_box(
                x,
                cur_y,
                w,
                collapsed_h,
                &log_summary,
                Color::DarkGray,
                Color::Reset,
            );
        }
    }

    fn render_secret_setup_screen(&mut self, buf: &mut ScreenBuffer) {
        let w = buf.width;
        let h = buf.height;

        buf.fill_rect(0, 0, w, 1, Color::White, Color::DarkBlue);
        buf.draw_text(
            0,
            0,
            w,
            " LanShare TUI — Share-Ring Setup ",
            Color::LightCyan,
            Color::DarkBlue,
            true,
        );

        let mw = w.saturating_sub(6).min(88);
        let mh = 13;
        let mx = (w.saturating_sub(mw)) / 2;
        let my = (h.saturating_sub(mh)) / 2;

        buf.draw_box(
            mx,
            my,
            mw,
            mh,
            "Enter Share-Ring Secret",
            Color::Cyan,
            Color::Reset,
        );

        buf.draw_text(
            mx + 2,
            my + 1,
            mw.saturating_sub(4),
            "Join an existing ring by entering a secret others shared with you,",
            Color::White,
            Color::Reset,
            false,
        );
        buf.draw_text(
            mx + 2,
            my + 2,
            mw.saturating_sub(4),
            "or create a new ring by typing a secret or pressing [Tab] for random.",
            Color::Gray,
            Color::Reset,
            false,
        );

        let secret_label = format!("Secret (min {} characters):", MIN_SECRET_LEN);
        buf.draw_text(
            mx + 2,
            my + 4,
            mw.saturating_sub(4),
            &secret_label,
            Color::LightCyan,
            Color::Reset,
            true,
        );

        buf.draw_cursor_input(
            mx + 2,
            my + 5,
            mw.saturating_sub(4),
            "> ",
            &self.ring_secret,
            self.secret_cursor_idx,
            Color::Green,
            Color::Reset,
        );

        let secret_len = self.ring_secret.trim().len();
        let is_valid = secret_len >= MIN_SECRET_LEN;
        let status_msg = if is_valid {
            format!("Status: Ready to connect ({} chars)", secret_len)
        } else if secret_len == 0 {
            "Status: Enter Share-Ring secret to begin".to_string()
        } else {
            format!(
                "Status: Too short ({} / {} chars required)",
                secret_len, MIN_SECRET_LEN
            )
        };
        let status_color = if is_valid {
            Color::Green
        } else if secret_len == 0 {
            Color::Gray
        } else {
            Color::Yellow
        };
        buf.draw_text(
            mx + 2,
            my + 7,
            mw.saturating_sub(4),
            &status_msg,
            status_color,
            Color::Reset,
            false,
        );

        let copy_hint = "[Enter] Confirm  [Tab] Random Secret  [F2] Copy (or Click)";
        let copy_row = my + 9;
        if let Some(rel_idx) = copy_hint.find("[F2] Copy") {
            let start = mx + 2 + rel_idx;
            let end = start + "[F2] Copy (or Click)".len().saturating_sub(1);
            self.last_login_copy_bounds = Some((copy_row, start, end));
        }
        buf.draw_text(
            mx + 2,
            copy_row,
            mw.saturating_sub(4),
            copy_hint,
            Color::Gray,
            Color::Reset,
            false,
        );
        buf.draw_text(
            mx + 2,
            my + 10,
            mw.saturating_sub(4),
            "[Ctrl+V / Shift+Ins] Paste (Replace)   [Ctrl+U] Clear   [Esc] Quit",
            Color::Gray,
            Color::Reset,
            false,
        );

        if let Some((ref flash, _)) = self.status_flash {
            buf.draw_text(
                mx + 2,
                my + 11,
                mw.saturating_sub(4),
                flash,
                Color::Magenta,
                Color::Reset,
                true,
            );
        }

        // Bottom footer
        let footer_y = h.saturating_sub(1);
        buf.fill_rect(0, footer_y, w, 1, Color::White, Color::DarkBlue);
        buf.draw_text(
            0,
            footer_y,
            w,
            " Type secret, [Tab] Random, [F2] Copy, [Ctrl+V/Shift+Ins] Replace, [Enter] Start.",
            Color::White,
            Color::DarkBlue,
            false,
        );
    }

    fn open_about_url(&mut self, url: &str, label: &str) {
        match open_url(url) {
            Ok(()) => self.set_flash(format!("Opened {} in browser.", label)),
            Err(e) => self.set_flash(format!("Could not open {} ({}): {}", label, e, url)),
        }
    }

    fn render_how_it_works_modal(&mut self, buf: &mut ScreenBuffer) {
        self.last_about_github_bounds = None;
        self.last_about_updates_bounds = None;

        let mw = buf.width.saturating_sub(6).min(84);
        let mh = 18.min(buf.height.saturating_sub(2));
        let mx = (buf.width.saturating_sub(mw)) / 2;
        let my = (buf.height.saturating_sub(mh)) / 2;

        buf.draw_box(
            mx,
            my,
            mw,
            mh,
            "About LanShare — How LanShare Works",
            Color::Cyan,
            Color::Black,
        );

        let github_line = format!("[g] GitHub: {}", GITHUB_REPO_URL);
        let updates_line = format!("[u] Updates: {}", GITHUB_RELEASES_URL);
        let lines = [
            (
                format!(
                    "LanShare v{} — Peer-to-Peer LAN Folder Sharing",
                    env!("CARGO_PKG_VERSION")
                ),
                Color::LightCyan,
                true,
            ),
            ("Author: Jokke Heikkilä".to_string(), Color::White, false),
            (github_line, Color::Cyan, false),
            (updates_line, Color::Cyan, false),
            ("".to_string(), Color::Gray, false),
            (
                "Encrypted peer-to-peer LAN folder sharing powered by Share-Ring.".to_string(),
                Color::Gray,
                false,
            ),
            (
                "1. Enter your Share-Ring Secret to discover computers or share folders."
                    .to_string(),
                Color::White,
                false,
            ),
            (
                "2. In 'Browse LAN', press [s] to scan peers, or [i] to connect directly by IP."
                    .to_string(),
                Color::White,
                false,
            ),
            (
                "3. In 'Share Folders', add folders and press [S] to start sharing read-only."
                    .to_string(),
                Color::White,
                false,
            ),
            ("".to_string(), Color::Gray, false),
            ("Security Guarantees:".to_string(), Color::Green, true),
            (
                "• Zero-Trust mutual TLS authentication (mTLS) with ephemeral in-memory certs."
                    .to_string(),
                Color::Gray,
                false,
            ),
            (
                "• 100% Read-Only: Guests cannot write, upload, modify, or delete any files."
                    .to_string(),
                Color::Gray,
                false,
            ),
            (
                "• Zero Cloud: Direct peer-to-peer transfers over local Wi-Fi / Ethernet."
                    .to_string(),
                Color::Gray,
                false,
            ),
            ("".to_string(), Color::Gray, false),
            (
                "Click links or press [g] GitHub / [u] Updates. [Enter]/[Esc]/[?] to close."
                    .to_string(),
                Color::Yellow,
                true,
            ),
        ];

        let max_w = mw.saturating_sub(4);
        for (i, (text, color, bold)) in lines.iter().enumerate() {
            if i + 2 >= mh {
                break;
            }
            let row = my + 1 + i;
            let start = mx + 2;
            let visible_chars = text.chars().count().min(max_w);
            if visible_chars > 0 {
                let end = start + visible_chars - 1;
                if i == 2 {
                    self.last_about_github_bounds = Some((row, start, end));
                } else if i == 3 {
                    self.last_about_updates_bounds = Some((row, start, end));
                }
            }
            buf.draw_text(start, row, max_w, text, *color, Color::Black, *bold);
        }
    }

    fn render_input_prompt_modal(&self, buf: &mut ScreenBuffer, prompt: &InputPrompt) {
        let mw = buf.width.saturating_sub(8).min(76);
        let mh = 9;
        let mx = (buf.width.saturating_sub(mw)) / 2;
        let my = (buf.height.saturating_sub(mh)) / 2;

        buf.draw_box(mx, my, mw, mh, &prompt.title, Color::Yellow, Color::Black);
        buf.draw_text(
            mx + 2,
            my + 1,
            mw.saturating_sub(4),
            &prompt.hint,
            Color::LightCyan,
            Color::Black,
            false,
        );

        buf.draw_cursor_input(
            mx + 2,
            my + 3,
            mw.saturating_sub(4),
            "> ",
            &prompt.value,
            prompt.cursor_idx,
            Color::Green,
            Color::Black,
        );

        if let Some(ref err) = prompt.error {
            buf.draw_text(
                mx + 2,
                my + 5,
                mw.saturating_sub(4),
                &format!("[!] {}", err),
                Color::Red,
                Color::Black,
                true,
            );
        } else if prompt.kind == InputPromptKind::AddHostFolder
            || prompt.kind == InputPromptKind::AddHostFile
        {
            let val = prompt.value.trim();
            if !val.is_empty() {
                let path = Self::expand_tilde(val);
                let res = if prompt.kind == InputPromptKind::AddHostFile {
                    validate_shared_file(&path)
                } else {
                    validate_shared_folder(&path)
                };
                match res {
                    Ok(safe) => {
                        let size_suffix = if safe.is_file() {
                            std::fs::metadata(&safe)
                                .map(|m| format!(" ({})", format_file_size(m.len())))
                                .unwrap_or_default()
                        } else {
                            String::new()
                        };
                        buf.draw_text(
                            mx + 2,
                            my + 5,
                            mw.saturating_sub(4),
                            &format!("Resolves to: {}{}", safe.display(), size_suffix),
                            Color::Green,
                            Color::Black,
                            false,
                        );
                    }
                    Err(e) => {
                        buf.draw_text(
                            mx + 2,
                            my + 5,
                            mw.saturating_sub(4),
                            &format!("[!] {}", e),
                            Color::Yellow,
                            Color::Black,
                            false,
                        );
                    }
                }
            }
        } else if prompt.kind == InputPromptKind::DestFolder {
            let val = prompt.value.trim();
            if !val.is_empty() {
                let path = Self::expand_tilde(val);
                match crate::security::ensure_safe_client_dir(&path) {
                    Ok(()) => {
                        buf.draw_text(
                            mx + 2,
                            my + 5,
                            mw.saturating_sub(4),
                            &format!("Resolves to: {}", path.display()),
                            Color::Green,
                            Color::Black,
                            false,
                        );
                    }
                    Err(e) => {
                        buf.draw_text(
                            mx + 2,
                            my + 5,
                            mw.saturating_sub(4),
                            &format!("[!] {}", e),
                            Color::Yellow,
                            Color::Black,
                            false,
                        );
                    }
                }
            }
        }

        buf.draw_text(
            mx + 2,
            my + 7,
            mw.saturating_sub(4),
            "[Enter] Confirm  [Esc] Cancel  [F2] Copy  [Ctrl+V/Shift+Ins] Paste",
            Color::Gray,
            Color::Black,
            false,
        );
    }
}

// ============================================================================
// Cross-Platform Raw Terminal Guard & Non-Blocking Input Reader
// ============================================================================

pub struct TerminalGuard {
    #[cfg(unix)]
    orig_termios: Option<libc::termios>,
    #[cfg(windows)]
    orig_in_mode: u32,
    #[cfg(windows)]
    orig_out_mode: u32,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        #[cfg(unix)]
        let guard = {
            // SAFETY: `libc::termios` is a plain C struct with valid all-zero bit pattern before `tcgetattr`.
            let mut termios: libc::termios = unsafe { std::mem::zeroed() };
            // SAFETY: `STDIN_FILENO` is a valid fd and `&mut termios` is valid for writes.
            let orig = if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) } == 0 {
                let saved = termios;
                termios.c_iflag &=
                    !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
                termios.c_oflag &= !(libc::OPOST);
                termios.c_cflag |= libc::CS8;
                termios.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
                termios.c_cc[libc::VMIN] = 0;
                termios.c_cc[libc::VTIME] = 0;
                // SAFETY: `&termios` points to an initialized `libc::termios` structure.
                unsafe {
                    libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios);
                }
                Some(saved)
            } else {
                None
            };
            Self { orig_termios: orig }
        };

        #[cfg(windows)]
        let guard = {
            extern "system" {
                fn GetStdHandle(nStdHandle: u32) -> isize;
                fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
                fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
            }
            const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
            const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
            const ENABLE_ECHO_INPUT: u32 = 0x0004;
            const ENABLE_LINE_INPUT: u32 = 0x0002;
            const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
            const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
            const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

            let mut orig_in = 0u32;
            let mut orig_out = 0u32;
            // SAFETY: Standard Win32 console APIs operating on valid stack output integers.
            unsafe {
                let h_in = GetStdHandle(STD_INPUT_HANDLE);
                let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
                GetConsoleMode(h_in, &mut orig_in);
                GetConsoleMode(h_out, &mut orig_out);
                let new_in = (orig_in
                    & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT;
                let new_out = orig_out | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(h_in, new_in);
                SetConsoleMode(h_out, new_out);
            }
            Self {
                orig_in_mode: orig_in,
                orig_out_mode: orig_out,
            }
        };

        let mut stdout = io::stdout();
        stdout.write_all(b"\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[2J")?;
        stdout.flush()?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let mut stdout = io::stdout();
        let _ = stdout.write_all(b"\x1b[?1006l\x1b[?1000l\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = stdout.flush();

        #[cfg(unix)]
        if let Some(ref orig) = self.orig_termios {
            // SAFETY: `orig` is a valid `libc::termios` previously populated by `tcgetattr`.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
            }
        }

        #[cfg(windows)]
        // SAFETY: Restores console modes captured earlier in `TerminalGuard::enter`.
        unsafe {
            extern "system" {
                fn GetStdHandle(nStdHandle: u32) -> isize;
                fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
            }
            const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
            const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
            let h_in = GetStdHandle(STD_INPUT_HANDLE);
            let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
            SetConsoleMode(h_in, self.orig_in_mode);
            SetConsoleMode(h_out, self.orig_out_mode);
        }
    }
}

pub fn terminal_size() -> (usize, usize) {
    #[cfg(unix)]
    // SAFETY: `ws` is a POD struct zeroed before `ioctl(TIOCGWINSZ)` writes terminal dimensions.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0
            && ws.ws_col > 0
            && ws.ws_row > 0
        {
            return (ws.ws_col as usize, ws.ws_row as usize);
        }
    }

    #[cfg(windows)]
    // SAFETY: Standard Win32 console buffer query with a properly sized stack output struct.
    unsafe {
        #[repr(C)]
        struct Coord {
            x: i16,
            y: i16,
        }
        #[repr(C)]
        struct SmallRect {
            left: i16,
            top: i16,
            right: i16,
            bottom: i16,
        }
        #[repr(C)]
        struct ConsoleScreenBufferInfo {
            size: Coord,
            cursor_pos: Coord,
            attributes: u16,
            window: SmallRect,
            max_window_size: Coord,
        }
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> isize;
            fn GetConsoleScreenBufferInfo(
                hConsoleOutput: isize,
                lpConsoleScreenBufferInfo: *mut ConsoleScreenBufferInfo,
            ) -> i32;
        }
        const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
        let mut info: ConsoleScreenBufferInfo = std::mem::zeroed();
        let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
        if GetConsoleScreenBufferInfo(h_out, &mut info) != 0 {
            let cols = (info.window.right - info.window.left + 1) as usize;
            let rows = (info.window.bottom - info.window.top + 1) as usize;
            if cols > 0 && rows > 0 {
                return (cols, rows);
            }
        }
    }

    (100, 30)
}

pub fn poll_key_events() -> Vec<KeyEvent> {
    #[cfg(windows)]
    // SAFETY: `_kbhit` is a stateless CRT check taking no pointers.
    unsafe {
        extern "C" {
            fn _kbhit() -> i32;
        }
        if _kbhit() == 0 {
            return Vec::new();
        }
    }

    let mut buf = [0u8; 4096];
    let n = match io::stdin().read(&mut buf) {
        Ok(0) | Err(_) => return Vec::new(),
        Ok(n) => n,
    };
    parse_key_events(&buf[..n])
}

pub fn parse_key_events(bytes: &[u8]) -> Vec<KeyEvent> {
    let mut events = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (ev, consumed) = parse_next_key_event(&bytes[offset..]);
        if let Some(key) = ev {
            events.push(key);
        }
        offset += consumed.max(1);
    }
    events
}

pub fn parse_key_bytes(bytes: &[u8]) -> Option<KeyEvent> {
    parse_key_events(bytes).into_iter().next()
}

fn parse_next_key_event(bytes: &[u8]) -> (Option<KeyEvent>, usize) {
    if bytes.is_empty() {
        return (None, 0);
    }

    // 1. Bracketed paste: \x1b[200~ ... \x1b[201~
    const PASTE_START: &[u8] = b"\x1b[200~";
    const PASTE_END: &[u8] = b"\x1b[201~";
    if bytes.starts_with(PASTE_START) {
        let rest = &bytes[PASTE_START.len()..];
        let (content_bytes, consumed) =
            if let Some(end_idx) = rest.windows(PASTE_END.len()).position(|w| w == PASTE_END) {
                (
                    &rest[..end_idx],
                    PASTE_START.len() + end_idx + PASTE_END.len(),
                )
            } else {
                (rest, bytes.len())
            };
        if let Ok(text) = std::str::from_utf8(content_bytes) {
            let clean: String = text.chars().filter(|c| *c != '\r' && *c != '\n').collect();
            return (Some(KeyEvent::Paste(clean)), consumed);
        }
        return (None, consumed);
    }

    // 2. Control characters & special keys
    match bytes[0] {
        3 => return (Some(KeyEvent::CtrlC), 1),
        21 => return (Some(KeyEvent::CtrlU), 1),
        22 => return (Some(KeyEvent::CtrlV), 1),
        25 => return (Some(KeyEvent::CtrlY), 1),
        9 => return (Some(KeyEvent::Tab), 1),
        13 => {
            let consumed = if bytes.get(1) == Some(&10) { 2 } else { 1 };
            return (Some(KeyEvent::Enter), consumed);
        }
        10 => return (Some(KeyEvent::Enter), 1),
        8 | 127 => return (Some(KeyEvent::Backspace), 1),
        27 => {
            if bytes.len() == 1 {
                return (Some(KeyEvent::Esc), 1);
            }
            if bytes.starts_with(b"\x1b[<") {
                if let Ok(s) = std::str::from_utf8(&bytes[3..]) {
                    if let Some(term_idx) = s.find(['M', 'm']) {
                        let consumed = 3 + term_idx + 1;
                        let is_press = s.as_bytes()[term_idx] == b'M';
                        let content = &s[..term_idx];
                        let mut parts = content.split(';');
                        if let (Some(btn_s), Some(col_s), Some(row_s)) =
                            (parts.next(), parts.next(), parts.next())
                        {
                            if let (Ok(btn), Ok(col), Ok(row)) = (
                                btn_s.parse::<usize>(),
                                col_s.parse::<usize>(),
                                row_s.parse::<usize>(),
                            ) {
                                let col_0 = col.saturating_sub(1);
                                let row_0 = row.saturating_sub(1);
                                if btn == 64 {
                                    return (Some(KeyEvent::ScrollUp), consumed);
                                } else if btn == 65 {
                                    return (Some(KeyEvent::ScrollDown), consumed);
                                } else if is_press && btn == 0 {
                                    return (
                                        Some(KeyEvent::MouseClick {
                                            col: col_0,
                                            row: row_0,
                                        }),
                                        consumed,
                                    );
                                }
                            }
                        }
                        return (None, consumed);
                    }
                }
                return (None, bytes.len());
            }
            if bytes[1] == b'[' {
                if let Some(term_rel) = bytes[2..].iter().position(
                    |&b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'~' | b'^' | b'$' | b'@'),
                ) {
                    let seq = &bytes[..2 + term_rel + 1];
                    let ev = if seq == b"\x1b[A" {
                        Some(KeyEvent::Up)
                    } else if seq == b"\x1b[B" {
                        Some(KeyEvent::Down)
                    } else if seq == b"\x1b[C" {
                        Some(KeyEvent::Right)
                    } else if seq == b"\x1b[D" {
                        Some(KeyEvent::Left)
                    } else if seq == b"\x1b[H" || seq == b"\x1b[1~" || seq == b"\x1b[7~" {
                        Some(KeyEvent::Home)
                    } else if seq == b"\x1b[F" || seq == b"\x1b[4~" || seq == b"\x1b[8~" {
                        Some(KeyEvent::End)
                    } else if seq == b"\x1b[Z" {
                        Some(KeyEvent::BackTab)
                    } else if seq == b"\x1b[11~" || seq == b"\x1b[1P" {
                        Some(KeyEvent::F(1))
                    } else if seq == b"\x1b[12~" || seq == b"\x1b[1Q" {
                        Some(KeyEvent::F(2))
                    } else if seq == b"\x1b[13~" || seq == b"\x1b[1R" {
                        Some(KeyEvent::F(3))
                    } else if seq == b"\x1b[14~" || seq == b"\x1b[1S" {
                        Some(KeyEvent::F(4))
                    } else if seq == b"\x1b[15~" {
                        Some(KeyEvent::F(5))
                    } else if seq == b"\x1b[2^"
                        || seq == b"\x1b[0;5~"
                        || seq == b"\x1b[1;5p"
                        || seq.starts_with(b"\x1b[2;5")
                        || seq.starts_with(b"\x1b[2;6")
                        || seq.starts_with(b"\x1b[57348;5")
                        || seq.starts_with(b"\x1b[57348;6")
                    {
                        Some(KeyEvent::CtrlInsert)
                    } else if seq == b"\x1b[2~" || seq == b"\x1b[2$" || seq.starts_with(b"\x1b[2;2")
                    {
                        Some(KeyEvent::ShiftInsert)
                    } else if seq == b"\x1b[3~" {
                        Some(KeyEvent::Delete)
                    } else if seq == b"\x1b[5~" {
                        Some(KeyEvent::PageUp)
                    } else if seq == b"\x1b[6~" {
                        Some(KeyEvent::PageDown)
                    } else {
                        None
                    };
                    return (ev, seq.len());
                }
                return (Some(KeyEvent::Esc), 1);
            } else if bytes[1] == b'O' && bytes.len() >= 3 {
                let ev = match bytes[2] {
                    b'P' => Some(KeyEvent::F(1)),
                    b'Q' => Some(KeyEvent::F(2)),
                    b'R' => Some(KeyEvent::F(3)),
                    b'S' => Some(KeyEvent::F(4)),
                    b'H' => Some(KeyEvent::Home),
                    b'F' => Some(KeyEvent::End),
                    _ => None,
                };
                return (ev, 3);
            }
            return (Some(KeyEvent::Esc), 1);
        }
        _ => {}
    }

    // 3. Single UTF-8 character (do not treat multi-char fast typing as Paste;
    // real pastes use bracketed paste `\x1b[200~...\x1b[201~` or Shift+Ins).
    let max_len = bytes.len().min(4);
    for len in 1..=max_len {
        if let Ok(s) = std::str::from_utf8(&bytes[..len]) {
            if let Some(ch) = s.chars().next() {
                return (Some(KeyEvent::Char(ch)), len);
            }
        }
    }
    (None, 1)
}

pub fn run_tui(mut app: LanShareTui) -> io::Result<()> {
    let _guard = TerminalGuard::enter()?;
    let mut stdout = io::stdout();
    let mut last_frame = String::new();

    while !app.should_quit {
        app.poll_channels();

        let (cols, rows) = terminal_size();
        let mut screen = ScreenBuffer::new(cols, rows);
        app.render(&mut screen);
        let frame = screen.to_ansi_frame();

        if frame != last_frame {
            stdout.write_all(frame.as_bytes())?;
            stdout.flush()?;
            last_frame = frame;
        }

        let events = poll_key_events();
        if events.is_empty() {
            std::thread::sleep(Duration::from_millis(30));
        } else {
            for ev in events {
                app.handle_key(ev);
                if app.should_quit {
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tui_render_and_navigation_in_test_mode() {
        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        let mut buf = ScreenBuffer::new(110, 32);
        tui.render(&mut buf);
        let text = buf.to_plain_text();

        assert!(text.contains("LanShare TUI [TEST MODE]"));
        assert!(text.contains("•••••••••••••"));
        assert!(text.contains("[v] Show"));

        // Toggle [v] to reveal secret
        tui.handle_key(KeyEvent::Char('v'));
        let mut buf_v = ScreenBuffer::new(110, 32);
        tui.render(&mut buf_v);
        let text_v = buf_v.to_plain_text();
        assert!(text_v.contains("party-ring-42"));
        assert!(text_v.contains("[v] Hide"));

        // Initially no peer is selected even in test mode; peers are listed with [ ]
        assert!(!tui.client_connected);
        assert!(text_v.contains("[ ] 1. Alice-Laptop (Test Mode)"));
        assert!(text_v.contains("[ ] 2. Mock-Gaming-PC (Test Mode)"));
        assert!(text_v.contains("Press [p] (or ←/→) to select a computer above"));

        // First press of 'p' selects peer #1 (Alice-Laptop), second press selects peer #2 (Mock-Gaming-PC)
        tui.handle_key(KeyEvent::Char('p'));
        assert!(tui.client_connected);
        assert_eq!(tui.selected_peer_name, "Alice-Laptop (Test Mode)");

        tui.handle_key(KeyEvent::Char('p'));
        assert_eq!(tui.selected_peer_name, "Mock-Gaming-PC (Test Mode)");

        let mut buf_p = ScreenBuffer::new(110, 32);
        tui.render(&mut buf_p);
        let text_p = buf_p.to_plain_text();
        assert!(text_p.contains("[*] 2. Mock-Gaming-PC (Test Mode)"));
        assert!(text_p.contains("Games_Patches"));
        assert!(!text_p.contains("[Space/Ent]"));

        // Press Space to queue first item (Games_Patches folder)
        tui.handle_key(KeyEvent::Char(' '));
        assert_eq!(tui.download_queue.len(), 1);

        // Enter opens folders in Browse, and never queues a file for download
        let file_idx = tui
            .client_file_list
            .iter()
            .position(|e| !e.is_dir)
            .expect("mock host must list files");
        tui.selected_file_idx = file_idx;
        tui.handle_key(KeyEvent::Enter);
        assert_eq!(tui.download_queue.len(), 1);
        assert!(tui.client_current_path.is_empty());

        tui.selected_file_idx = 0; // Games_Patches folder
        tui.handle_key(KeyEvent::Enter);
        assert_eq!(tui.client_current_path, "Games_Patches");
        tui.handle_key(KeyEvent::Backspace);
        assert!(tui.client_current_path.is_empty());

        // Press '?' to open "How LanShare Works" modal
        tui.handle_key(KeyEvent::Char('?'));
        assert!(tui.show_how_it_works);
        let mut modal_buf = ScreenBuffer::new(110, 32);
        tui.render(&mut modal_buf);
        assert!(modal_buf.to_plain_text().contains("How LanShare Works"));

        // Close modal and switch to Host tab
        tui.handle_key(KeyEvent::Esc);
        assert!(!tui.show_how_it_works);
        tui.handle_key(KeyEvent::Tab);
        assert_eq!(tui.current_tab, TuiTab::Host);

        // Enter must not start or stop sharing on the Host tab
        tui.handle_key(KeyEvent::Enter);
        assert!(tui.server_handle.is_none());
        assert!(tui.host_error.is_none());

        let mut host_buf = ScreenBuffer::new(110, 32);
        tui.render(&mut host_buf);
        let host_text = host_buf.to_plain_text();
        assert!(host_text.contains("Hosted folders are shared read-only on your LAN."));
        assert!(!host_text.contains("Auto-Stop Timer"));
        assert!(!host_text.contains("t:Timer"));
        assert!(host_text.contains("S:Start/Stop Sharing"));
    }

    #[test]
    fn test_tui_secret_setup_screen_and_about_modal() {
        let mut tui = LanShareTui::new(false, None, Vec::new(), false);
        assert!(!tui.secret_confirmed);
        assert!(
            tui.ring_secret.is_empty(),
            "Ring secret should be empty by default on login screen"
        );
        assert_eq!(tui.secret_cursor_idx, 0);
        let mut buf = ScreenBuffer::new(100, 30);
        tui.render(&mut buf);
        let text = buf.to_plain_text();
        assert!(text.contains("Share-Ring Setup"));
        assert!(text.contains("Enter Share-Ring Secret"));
        assert!(text.contains("Join an existing ring by entering a secret others shared with you,"));
        assert!(
            text.contains("or create a new ring by typing a secret or pressing [Tab] for random.")
        );
        assert!(text.contains("[Tab] Random Secret"));
        assert!(text.contains("[F2] Copy"));
        assert!(text.contains("[Ctrl+V / Shift+Ins] Paste (Replace)"));
        assert!(text.contains("[Ctrl+U] Clear"));

        // Press Tab to generate a random secret, then copy on login setup screen with F2, mouse click, Ctrl+Insert, Ctrl+Y
        tui.handle_key(KeyEvent::Tab);
        assert!(!tui.ring_secret.is_empty());
        let initial_secret = tui.ring_secret.clone();
        tui.handle_key(KeyEvent::F(2));
        assert_eq!(tui.ring_secret, initial_secret);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Share-Ring Secret copied to clipboard!"));

        tui.status_flash = None;
        tui.handle_key(KeyEvent::CtrlInsert);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Share-Ring Secret copied to clipboard!"));

        tui.status_flash = None;
        tui.handle_key(KeyEvent::CtrlY);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Share-Ring Secret copied to clipboard!"));

        tui.status_flash = None;
        let (btn_row, c_start, _) = tui
            .last_login_copy_bounds
            .expect("Login copy bounds must be recorded");
        tui.handle_key(KeyEvent::MouseClick {
            col: c_start,
            row: btn_row,
        });
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Share-Ring Secret copied to clipboard!"));

        // Ctrl+U clears the secret on login setup screen
        tui.handle_key(KeyEvent::CtrlU);
        assert!(tui.ring_secret.is_empty());
        assert_eq!(tui.secret_cursor_idx, 0);

        // Confirm with a valid secret (>= 10 chars)
        tui.ring_secret = "secret-123".to_string();
        tui.handle_key(KeyEvent::Enter);
        assert!(tui.secret_confirmed);

        let mut buf2 = ScreenBuffer::new(100, 30);
        tui.render(&mut buf2);
        let text2 = buf2.to_plain_text();
        assert!(text2.contains("Browse LAN"));
        assert!(text2.contains("Share Folders"));

        // Open About modal
        tui.handle_key(KeyEvent::Char('?'));
        assert!(tui.show_how_it_works);
        let mut modal_buf = ScreenBuffer::new(110, 32);
        tui.render(&mut modal_buf);
        let about_text = modal_buf.to_plain_text();
        assert!(about_text.contains("About LanShare"));
        assert!(about_text.contains("Jokke Heikkilä"));
        assert!(about_text.contains("github.com/jokkeheikkila/LanShare"));
        assert!(about_text.contains("github.com/jokkeheikkila/LanShare/releases"));

        // Clicking GitHub and Updates links in About modal opens them
        let (gh_row, gh_c0, _gh_c1) = tui
            .last_about_github_bounds
            .expect("GitHub link bounds recorded");
        tui.handle_key(KeyEvent::MouseClick {
            col: gh_c0 + 2,
            row: gh_row,
        });
        assert!(tui
            .status_flash
            .as_ref()
            .is_some_and(|(msg, _)| msg.contains("GitHub repository")));

        let (up_row, up_c0, _up_c1) = tui
            .last_about_updates_bounds
            .expect("Updates link bounds recorded");
        tui.handle_key(KeyEvent::MouseClick {
            col: up_c0 + 2,
            row: up_row,
        });
        assert!(tui
            .status_flash
            .as_ref()
            .is_some_and(|(msg, _)| msg.contains("GitHub Releases")));

        // Keyboard shortcut 'u' also triggers Updates link
        tui.status_flash = None;
        tui.handle_key(KeyEvent::Char('u'));
        assert!(tui
            .status_flash
            .as_ref()
            .is_some_and(|(msg, _)| msg.contains("GitHub Releases")));
    }

    #[test]
    fn test_tui_add_folder_modal_resolving_and_typo_correction() {
        let mut tui = LanShareTui::new(
            false,
            Some("secret-test-ring".to_string()),
            Vec::new(),
            false,
        );
        tui.current_tab = TuiTab::Host;

        // Press 'a' to open Add Folder modal
        tui.handle_key(KeyEvent::Char('a'));
        assert!(tui.active_prompt.is_some());
        let prompt = tui.active_prompt.as_ref().unwrap();
        assert_eq!(prompt.kind, InputPromptKind::AddHostFolder);

        // Type a path with a typo that does not exist
        for c in "/nonexistent/typo_dir_12345".chars() {
            tui.handle_key(KeyEvent::Char(c));
        }

        // Render modal: live resolving should detect it cannot resolve the path
        let mut buf = ScreenBuffer::new(100, 30);
        tui.render(&mut buf);
        let plain = buf.to_plain_text();
        assert!(plain.contains("Cannot resolve path"));

        // Press Enter: Window should NOT hide! It must stay open for typo correction.
        tui.handle_key(KeyEvent::Enter);
        assert!(
            tui.active_prompt.is_some(),
            "Modal window must remain open on resolution error"
        );
        assert!(
            tui.active_prompt.as_ref().unwrap().error.is_some(),
            "Error must be populated inside the modal prompt"
        );

        // Verify the rendered modal still displays the error in the window
        let mut buf2 = ScreenBuffer::new(100, 30);
        tui.render(&mut buf2);
        let plain2 = buf2.to_plain_text();
        assert!(plain2.contains("Cannot resolve path"));
        assert!(plain2.contains("/nonexistent/typo_dir_12345"));
        assert!(plain2.contains("[F2] Copy  [Ctrl+V/Shift+Ins] Paste"));

        // Correct the typo using Ctrl+U to clear and type a valid path
        tui.handle_key(KeyEvent::CtrlU);
        assert!(tui.active_prompt.as_ref().unwrap().value.is_empty());

        let base = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("target");
        let valid_test_dir = base.join(format!("lanshare_tui_test_dir_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&valid_test_dir);
        let valid_str = valid_test_dir.to_string_lossy().to_string();

        for c in valid_str.chars() {
            tui.handle_key(KeyEvent::Char(c));
        }

        // Render modal: live resolving should show "Resolves to:"
        let mut buf3 = ScreenBuffer::new(100, 30);
        tui.render(&mut buf3);
        let plain3 = buf3.to_plain_text();
        assert!(plain3.contains("Resolves to:"));

        // Press Enter: now it succeeds, modal closes, and folder is added!
        tui.handle_key(KeyEvent::Enter);
        assert!(
            tui.active_prompt.is_none(),
            "Modal window should close upon successful add"
        );
        assert_eq!(tui.host_folders.len(), 1);

        let _ = std::fs::remove_dir_all(&valid_test_dir);
    }

    #[test]
    fn test_tui_cursor_navigation_and_editing_in_prompt() {
        let mut prompt = InputPrompt::new(
            InputPromptKind::AddHostFolder,
            "Add Folder".to_string(),
            "Hint".to_string(),
            "hello".to_string(),
        );
        assert_eq!(prompt.cursor_idx, 5);

        // Move left twice -> cursor at 3 (under second 'l')
        prompt.move_left();
        prompt.move_left();
        assert_eq!(prompt.cursor_idx, 3);

        // Insert character 'X' -> "helXlo", cursor at 4
        prompt.insert_char('X');
        assert_eq!(prompt.value, "helXlo");
        assert_eq!(prompt.cursor_idx, 4);

        // Move right once -> cursor at 5
        prompt.move_right();
        assert_eq!(prompt.cursor_idx, 5);

        // Move home -> cursor at 0
        prompt.move_home();
        assert_eq!(prompt.cursor_idx, 0);

        // Insert string (paste) at start
        prompt.insert_str("start-");
        assert_eq!(prompt.value, "start-helXlo");
        assert_eq!(prompt.cursor_idx, 6);

        // Delete current char ('h')
        prompt.delete_current();
        assert_eq!(prompt.value, "start-elXlo");
        assert_eq!(prompt.cursor_idx, 6);

        // Backspace deletes '-'
        prompt.delete_backspace();
        assert_eq!(prompt.value, "startelXlo");
        assert_eq!(prompt.cursor_idx, 5);

        // Move end
        prompt.move_end();
        assert_eq!(prompt.cursor_idx, prompt.value.chars().count());
    }

    #[test]
    fn test_tui_secret_dialog_cursor_and_paste() {
        let mut tui = LanShareTui::new(false, None, Vec::new(), false);
        tui.ring_secret = "secret".to_string();
        tui.secret_cursor_idx = 6;

        // Move left 3 times
        tui.handle_key(KeyEvent::Left);
        tui.handle_key(KeyEvent::Left);
        tui.handle_key(KeyEvent::Left);
        assert_eq!(tui.secret_cursor_idx, 3);

        // Type '1'
        tui.handle_key(KeyEvent::Char('1'));
        assert_eq!(tui.ring_secret, "sec1ret");
        assert_eq!(tui.secret_cursor_idx, 4);

        // Paste replaces existing secret text cleanly and moves cursor to end
        tui.handle_key(KeyEvent::Paste("new-pasted-secret".to_string()));
        assert_eq!(tui.ring_secret, "new-pasted-secret");
        assert_eq!(tui.secret_cursor_idx, "new-pasted-secret".chars().count());

        // Move Home
        tui.handle_key(KeyEvent::Home);
        assert_eq!(tui.secret_cursor_idx, 0);

        // Move End
        tui.handle_key(KeyEvent::End);
        assert_eq!(tui.secret_cursor_idx, tui.ring_secret.chars().count());
    }

    #[test]
    fn test_parse_key_bytes_paste_and_arrows() {
        // Arrow keys
        assert_eq!(parse_key_bytes(b"\x1b[D"), Some(KeyEvent::Left));
        assert_eq!(parse_key_bytes(b"\x1b[C"), Some(KeyEvent::Right));
        assert_eq!(parse_key_bytes(b"\x1b[H"), Some(KeyEvent::Home));
        assert_eq!(parse_key_bytes(b"\x1b[F"), Some(KeyEvent::End));

        // Function keys F1-F5 (SS3, xterm CSI tilde, Kitty CSI P/Q/R/S) and legacy Insert combos
        assert_eq!(parse_key_bytes(b"\x1bOP"), Some(KeyEvent::F(1)));
        assert_eq!(parse_key_bytes(b"\x1b[11~"), Some(KeyEvent::F(1)));
        assert_eq!(parse_key_bytes(b"\x1b[1P"), Some(KeyEvent::F(1)));
        assert_eq!(parse_key_bytes(b"\x1bOQ"), Some(KeyEvent::F(2)));
        assert_eq!(parse_key_bytes(b"\x1b[12~"), Some(KeyEvent::F(2)));
        assert_eq!(parse_key_bytes(b"\x1b[1Q"), Some(KeyEvent::F(2)));
        assert_eq!(parse_key_bytes(b"\x1bOR"), Some(KeyEvent::F(3)));
        assert_eq!(parse_key_bytes(b"\x1b[13~"), Some(KeyEvent::F(3)));
        assert_eq!(parse_key_bytes(b"\x1b[1R"), Some(KeyEvent::F(3)));
        assert_eq!(parse_key_bytes(b"\x1bOS"), Some(KeyEvent::F(4)));
        assert_eq!(parse_key_bytes(b"\x1b[14~"), Some(KeyEvent::F(4)));
        assert_eq!(parse_key_bytes(b"\x1b[1S"), Some(KeyEvent::F(4)));
        assert_eq!(parse_key_bytes(b"\x1b[15~"), Some(KeyEvent::F(5)));
        assert_eq!(parse_key_bytes(b"\x1b[2;5~"), Some(KeyEvent::CtrlInsert));
        assert_eq!(parse_key_bytes(b"\x1b[2;6~"), Some(KeyEvent::CtrlInsert));
        assert_eq!(parse_key_bytes(b"\x1b[2^"), Some(KeyEvent::CtrlInsert));
        assert_eq!(
            parse_key_bytes(b"\x1b[57348;5u"),
            Some(KeyEvent::CtrlInsert)
        );
        assert_eq!(parse_key_bytes(b"\x1b[2;2~"), Some(KeyEvent::ShiftInsert));
        assert_eq!(parse_key_bytes(b"\x1b[2~"), Some(KeyEvent::ShiftInsert));
        assert_eq!(parse_key_bytes(b"\x1b[2$"), Some(KeyEvent::ShiftInsert));
        assert_eq!(parse_key_bytes(&[22]), Some(KeyEvent::CtrlV));
        assert_eq!(parse_key_bytes(&[25]), Some(KeyEvent::CtrlY));

        // Bracketed paste
        let bracketed = b"\x1b[200~my_shared_folder_path\x1b[201~";
        assert_eq!(
            parse_key_bytes(bracketed),
            Some(KeyEvent::Paste("my_shared_folder_path".to_string()))
        );

        // Fast typing multiple bytes in a single read produces individual Char events (not Paste)
        let fast_typed = b"192.168";
        assert_eq!(
            parse_key_events(fast_typed),
            vec![
                KeyEvent::Char('1'),
                KeyEvent::Char('9'),
                KeyEvent::Char('2'),
                KeyEvent::Char('.'),
                KeyEvent::Char('1'),
                KeyEvent::Char('6'),
                KeyEvent::Char('8'),
            ]
        );

        // Chained arrows + characters in a single buffer parse individually in order
        assert_eq!(
            parse_key_events(b"\x1b[D\x1b[Cab"),
            vec![
                KeyEvent::Left,
                KeyEvent::Right,
                KeyEvent::Char('a'),
                KeyEvent::Char('b'),
            ]
        );
    }

    #[test]
    fn test_tui_quit_confirmation_when_hosting_or_downloading() {
        use crate::server::{ServerHandle, SharedFolderRegistry};
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::Arc;

        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);

        // 1. Initially without hosting, pressing 'q' quits immediately
        tui.handle_key(KeyEvent::Char('q'));
        assert!(tui.should_quit);

        // Reset
        tui.should_quit = false;

        // 2. Mock active ServerHandle
        let (stop_tx, _stop_rx) = tokio::sync::oneshot::channel();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let active_downloads = Arc::new(AtomicUsize::new(0));
        let handle = ServerHandle {
            is_running: Arc::new(AtomicBool::new(true)),
            local_ip: "192.168.1.100".to_string(),
            all_ips: vec!["192.168.1.100".to_string()],
            port: 4433,
            password: "secret123".to_string(),
            stop_sender: stop_tx,
            shared_folders: Arc::new(std::sync::RwLock::new(vec![])),
            duration_hours: None,
            registry: Arc::new(std::sync::RwLock::new(SharedFolderRegistry::new(vec![]))),
            log_tx,
            active_downloads: active_downloads.clone(),
            active_folder_downloads: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            active_uploads: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            registry_notify_tx: tokio::sync::watch::channel(0u64).0,
        };
        tui.server_handle = Some(handle);

        // Pressing 'q' while hosting is active does NOT quit immediately
        tui.handle_key(KeyEvent::Char('q'));
        assert!(!tui.should_quit);
        assert!(tui.quit_confirmed);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("hosting is active"));

        // Pressing another key resets confirmation
        tui.handle_key(KeyEvent::Char('1'));
        assert!(!tui.quit_confirmed);

        // 3. Now simulate active peer download
        active_downloads.store(1, std::sync::atomic::Ordering::SeqCst);
        tui.handle_key(KeyEvent::Char('q'));
        assert!(!tui.should_quit);
        assert!(tui.quit_confirmed);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("CRITICAL: Peer downloading"));

        // Pressing 'q' again confirms and quits
        tui.handle_key(KeyEvent::Char('q'));
        assert!(tui.should_quit);

        // 4. Client download only (no hosting active)
        tui.server_handle = None;
        tui.should_quit = false;
        tui.quit_confirmed = false;
        assert!(!tui.needs_close_confirmation());

        tui.active_progress = Some(crate::client::TransferProgress {
            selected_target: "downloads".to_string(),
            file_name: "test.iso".to_string(),
            bytes_done: 100,
            bytes_total: 1000,
            speed_mbps: 1.0,
            is_finished: false,
            current_file: 1,
            total_files: 1,
            log_message: None,
        });
        assert!(tui.has_active_client_downloads());
        assert!(tui.needs_close_confirmation());

        // Pressing 'q' does not quit immediately, warns about downloads
        tui.handle_key(KeyEvent::Char('q'));
        assert!(!tui.should_quit);
        assert!(tui.quit_confirmed);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("File downloads currently in progress"));

        // Pressing another key resets confirmation
        tui.handle_key(KeyEvent::Char('m'));
        assert!(!tui.quit_confirmed);

        // Pressing 'q' again warns, next 'q' confirms and quits
        tui.handle_key(KeyEvent::Char('q'));
        assert!(tui.quit_confirmed);
        assert!(!tui.should_quit);
        tui.handle_key(KeyEvent::Char('q'));
        assert!(tui.should_quit);
    }

    #[test]
    fn test_tui_stop_server_confirmation_and_clean_ip_display() {
        use crate::server::{ServerHandle, SharedFolderRegistry};
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::Arc;

        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.current_tab = TuiTab::Host;

        // Before sharing starts, Host IP and [Y] Copy IP still render and copy cleanly
        tui.local_ips = vec!["192.168.1.100".to_string()];
        let mut stopped_buf = ScreenBuffer::new(110, 32);
        tui.render(&mut stopped_buf);
        let stopped_text = stopped_buf.to_plain_text();
        assert!(stopped_text.contains("Host IP: 192.168.1.100"));
        assert!(stopped_text.contains("[Y] Copy IP"));
        tui.handle_key(KeyEvent::Char('Y'));
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Host IP copied to clipboard!"));

        let (stop_tx, _stop_rx) = tokio::sync::oneshot::channel();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let active_downloads = Arc::new(AtomicUsize::new(0));
        let handle = ServerHandle {
            is_running: Arc::new(AtomicBool::new(true)),
            local_ip: "192.168.1.100".to_string(),
            all_ips: vec![
                "192.168.1.100".to_string(),
                "10.0.0.1".to_string(),
                "100.64.0.1".to_string(),
            ],
            port: 4433,
            password: "secret123".to_string(),
            stop_sender: stop_tx,
            shared_folders: Arc::new(std::sync::RwLock::new(vec![])),
            duration_hours: None,
            registry: Arc::new(std::sync::RwLock::new(SharedFolderRegistry::new(vec![]))),
            log_tx,
            active_downloads: active_downloads.clone(),
            active_folder_downloads: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            active_uploads: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            registry_notify_tx: tokio::sync::watch::channel(0u64).0,
        };
        tui.server_handle = Some(handle);

        // Render host tab: verifies only local_ip is shown, NOT extra all_ips (VPN/virtual IPs)
        let mut buf = ScreenBuffer::new(110, 32);
        tui.render(&mut buf);
        let host_text = buf.to_plain_text();
        assert!(host_text.contains("Host IP: 192.168.1.100"));
        assert!(!host_text.contains("10.0.0.1"));
        assert!(!host_text.contains("100.64.0.1"));

        // Simulate active download
        active_downloads.store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(tui.active_server_downloads(), 1);

        // Press 'S' to stop sharing: requires confirmation because of active download
        tui.handle_key(KeyEvent::Char('S'));
        assert!(tui.server_handle.is_some());
        assert!(tui.stop_server_confirmed);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("CRITICAL: Peer is downloading"));

        // Verify host tab UI shows the alert
        let mut alert_buf = ScreenBuffer::new(110, 32);
        tui.render(&mut alert_buf);
        let alert_text = alert_buf.to_plain_text();
        assert!(alert_text.contains("ALERT: Someone is downloading"));
        assert!(alert_text.contains("ABORT transfer & STOP sharing"));

        // Press another key resets confirmation
        tui.handle_key(KeyEvent::Char('a'));
        assert!(!tui.stop_server_confirmed);
        tui.active_prompt = None; // Dismiss add folder prompt

        // Enter must not stop sharing; confirm with 'S' instead
        tui.handle_key(KeyEvent::Enter);
        assert!(!tui.stop_server_confirmed);
        assert!(tui.server_handle.is_some());

        // Re-trigger confirmation and confirm with 'S'
        tui.handle_key(KeyEvent::Char('S'));
        assert!(tui.stop_server_confirmed);
        tui.handle_key(KeyEvent::Char('S'));
        assert!(!tui.stop_server_confirmed);
        assert!(tui.server_handle.is_none());
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Aborted peer transfer"));
    }

    #[test]
    fn test_tui_accordion_sections_scrolling_and_mouse() {
        // 1. Mouse parsing
        assert_eq!(
            parse_key_bytes(b"\x1b[<64;20;10M"),
            Some(KeyEvent::ScrollUp)
        );
        assert_eq!(
            parse_key_bytes(b"\x1b[<65;20;10M"),
            Some(KeyEvent::ScrollDown)
        );
        assert_eq!(
            parse_key_bytes(b"\x1b[<0;15;6M"),
            Some(KeyEvent::MouseClick { col: 14, row: 5 })
        );
        assert_eq!(parse_key_bytes(b"\x1b[<0;15;6m"), None);

        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        assert_eq!(tui.client_section, ClientSection::Browse);
        // Select a peer so Browse has files to scroll
        tui.handle_key(KeyEvent::Char('p'));
        tui.handle_key(KeyEvent::Char('p'));

        // Render Browse section expanded
        let mut buf = ScreenBuffer::new(100, 30);
        tui.render(&mut buf);
        let text1 = buf.to_plain_text();
        assert!(text1.contains("▼ Remote Files"));
        assert!(text1.contains("▶ [d] Downloads:"));
        assert!(text1.contains("▶ [l] Activity Log:"));

        // Mouse scroll in Browse section moves selected_file_idx
        assert_eq!(tui.selected_file_idx, 0);
        tui.handle_key(KeyEvent::ScrollDown);
        assert_eq!(tui.selected_file_idx, 1);
        tui.handle_key(KeyEvent::ScrollUp);
        assert_eq!(tui.selected_file_idx, 0);

        // Press 'd' to open Downloads section
        tui.handle_key(KeyEvent::Char('d'));
        assert_eq!(tui.client_section, ClientSection::Downloads);

        let mut buf2 = ScreenBuffer::new(100, 30);
        tui.render(&mut buf2);
        let text2 = buf2.to_plain_text();
        assert!(text2.contains("▶ [b] Remote Files:"));
        assert!(text2.contains("▼ Download Queue"));
        assert!(text2.contains("▶ [l] Activity Log:"));

        // Press 'Esc' returns to Browse
        tui.handle_key(KeyEvent::Esc);
        assert_eq!(tui.client_section, ClientSection::Browse);
        assert!(!tui.should_quit);

        // Press 'l' opens Logs section
        tui.handle_key(KeyEvent::Char('l'));
        assert_eq!(tui.client_section, ClientSection::Logs);

        let mut buf3 = ScreenBuffer::new(100, 30);
        tui.render(&mut buf3);
        let text3 = buf3.to_plain_text();
        assert!(text3.contains("▶ [b] Remote Files:"));
        assert!(text3.contains("▶ [d] Downloads:"));
        assert!(text3.contains("▼ Client Activity Log"));

        // Mouse scroll in Logs section adjusts log_scroll_offset
        assert_eq!(tui.log_scroll_offset, 0);
        tui.handle_key(KeyEvent::ScrollUp);
        assert_eq!(tui.log_scroll_offset, 1);
        tui.handle_key(KeyEvent::ScrollDown);
        assert_eq!(tui.log_scroll_offset, 0);

        // Press 'b' returns to Browse
        tui.handle_key(KeyEvent::Char('b'));
        assert_eq!(tui.client_section, ClientSection::Browse);

        // Mouse click on collapsed header expands it
        let dl_y = tui
            .last_downloads_header_y
            .expect("Downloads header Y must be recorded");
        tui.handle_key(KeyEvent::MouseClick { col: 5, row: dl_y });
        assert_eq!(tui.client_section, ClientSection::Downloads);

        // Return to browse
        tui.handle_key(KeyEvent::Esc);
        assert_eq!(tui.client_section, ClientSection::Browse);

        // Click on bottom border (dl_y + 1) of collapsed Downloads frame also expands it
        tui.handle_key(KeyEvent::MouseClick {
            col: 10,
            row: dl_y + 1,
        });
        assert_eq!(tui.client_section, ClientSection::Downloads);

        let log_y = tui
            .last_logs_header_y
            .expect("Logs header Y must be recorded");
        tui.handle_key(KeyEvent::MouseClick { col: 5, row: log_y });
        assert_eq!(tui.client_section, ClientSection::Logs);

        let browse_y = tui
            .last_browse_header_y
            .expect("Browse header Y must be recorded");
        tui.handle_key(KeyEvent::MouseClick {
            col: 5,
            row: browse_y,
        });
        assert_eq!(tui.client_section, ClientSection::Browse);
    }

    #[test]
    fn test_tui_host_tab_logs_minimize_maximize_and_scroll() {
        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.current_tab = TuiTab::Host;
        for i in 1..=30 {
            tui.server_logs.push_back(ServerLogEvent {
                timestamp: format!("12:00:{:02}", i),
                message: format!("Server event #{}", i),
                is_error: false,
            });
        }

        // Default: Folders maximized, Activity Log minimized summary visible at bottom
        let mut buf = ScreenBuffer::new(110, 32);
        tui.render(&mut buf);
        let text1 = buf.to_plain_text();
        assert!(text1.contains("▼ Folders to Share on LAN"));
        assert!(text1.contains("▶ [l] Activity Log:"));
        assert!(!tui.show_server_logs);

        // Press 'l' to maximize Server Activity Log (Folders minimizes)
        tui.handle_key(KeyEvent::Char('l'));
        assert!(tui.show_server_logs);
        let mut buf2 = ScreenBuffer::new(110, 32);
        tui.render(&mut buf2);
        let text2 = buf2.to_plain_text();
        assert!(text2.contains("▶ [l/f] Folders to Share:"));
        assert!(text2.contains("▼ Server Activity Log"));

        // Scroll server logs up/down with wheel or arrows
        assert_eq!(tui.server_log_scroll_offset, 0);
        tui.handle_key(KeyEvent::ScrollUp);
        assert_eq!(tui.server_log_scroll_offset, 1);
        tui.handle_key(KeyEvent::ScrollDown);
        assert_eq!(tui.server_log_scroll_offset, 0);

        // Mouse click on collapsed Folders header collapses logs back
        let (folders_start, _) = tui
            .last_host_folders_header_range
            .expect("Host folders header range must be recorded");
        tui.handle_key(KeyEvent::MouseClick {
            col: 5,
            row: folders_start,
        });
        assert!(!tui.show_server_logs);

        // Mouse click on collapsed Activity Log header expands logs again
        let (logs_start, _) = tui
            .last_host_logs_header_range
            .expect("Host logs header range must be recorded");
        tui.handle_key(KeyEvent::MouseClick {
            col: 5,
            row: logs_start,
        });
        assert!(tui.show_server_logs);

        // Enter must NOT toggle sharing while server logs are expanded; 'S' toggles it
        assert!(tui.host_error.is_none());
        tui.handle_key(KeyEvent::Enter);
        assert!(tui.host_error.is_none());
        tui.handle_key(KeyEvent::Char('S'));
        assert!(tui.host_error.is_some());
        tui.host_error = None;

        // Esc collapses logs back to Folders without quitting
        tui.handle_key(KeyEvent::Esc);
        assert!(!tui.show_server_logs);
        assert!(!tui.should_quit);
    }

    #[test]
    fn test_hosts_sorted_alphabetically() {
        let mut tui = LanShareTui::new(false, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.discovered_peers = vec![
            DiscoveredPeer {
                host_name: "Zebra-PC".to_string(),
                ip: "192.168.1.50".to_string(),
                port: 22222,
                last_seen: Instant::now(),
            },
            DiscoveredPeer {
                host_name: "Apple-MacBook".to_string(),
                ip: "192.168.1.20".to_string(),
                port: 22222,
                last_seen: Instant::now(),
            },
            DiscoveredPeer {
                host_name: "bravo-desktop".to_string(),
                ip: "192.168.1.30".to_string(),
                port: 22222,
                last_seen: Instant::now(),
            },
        ];

        let mut buf = ScreenBuffer::new(100, 30);
        tui.render(&mut buf);
        let text = buf.to_plain_text();

        // Verifies order: Apple-MacBook -> bravo-desktop -> Zebra-PC
        let apple_pos = text
            .find("Apple-MacBook")
            .expect("Apple-MacBook must be listed");
        let bravo_pos = text
            .find("bravo-desktop")
            .expect("bravo-desktop must be listed");
        let zebra_pos = text.find("Zebra-PC").expect("Zebra-PC must be listed");

        assert!(apple_pos < bravo_pos);
        assert!(bravo_pos < zebra_pos);
    }

    #[test]
    fn test_tui_download_queue_estimates() {
        let mut tui = LanShareTui::new(false, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.active_progress = Some(TransferProgress {
            selected_target: "Downloads".to_string(),
            file_name: "test.iso".to_string(),
            bytes_done: 50 * 1024 * 1024,
            bytes_total: 100 * 1024 * 1024,
            speed_mbps: 5.0, // 5 MB/s -> 50 MB remaining / 5 MB/s = 10s
            is_finished: false,
            current_file: 1,
            total_files: 1,
            log_message: None,
        });

        tui.download_queue.push_back(QueuedDownloadItem {
            id: 1,
            peer_name: "Host-A".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.10".to_string(),
                port: 22222,
                password: "party-ring-42".to_string(),
                peer_name: None,
            },
            is_mock: false,
            entry: FileEntry {
                name: "test.iso".to_string(),
                is_dir: false,
                size: 100 * 1024 * 1024,
                modified_timestamp: 0,
            },
            remote_subpath: "test.iso".to_string(),
            local_dest_dir: PathBuf::from("/tmp"),
            status: QueueItemStatus::Downloading,
            started_at: Some(Instant::now()),
            elapsed_duration: None,
            completed_at: None,
            total_bytes: Some(100 * 1024 * 1024),
        });

        // 300 MB pending item -> at 5 MB/s = 60s -> 1m
        tui.download_queue.push_back(QueuedDownloadItem {
            id: 2,
            peer_name: "Host-A".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.10".to_string(),
                port: 22222,
                password: "party-ring-42".to_string(),
                peer_name: None,
            },
            is_mock: false,
            entry: FileEntry {
                name: "big_data.tar".to_string(),
                is_dir: false,
                size: 300 * 1024 * 1024,
                modified_timestamp: 0,
            },
            remote_subpath: "big_data.tar".to_string(),
            local_dest_dir: PathBuf::from("/tmp"),
            status: QueueItemStatus::Pending,
            started_at: None,
            elapsed_duration: None,
            completed_at: None,
            total_bytes: Some(300 * 1024 * 1024),
        });

        // 40 MB completed item that took 45s
        tui.download_queue.push_back(QueuedDownloadItem {
            id: 3,
            peer_name: "Host-A".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.10".to_string(),
                port: 22222,
                password: "party-ring-42".to_string(),
                peer_name: None,
            },
            is_mock: false,
            entry: FileEntry {
                name: "finished_docs.pdf".to_string(),
                is_dir: false,
                size: 40 * 1024 * 1024,
                modified_timestamp: 0,
            },
            remote_subpath: "finished_docs.pdf".to_string(),
            local_dest_dir: PathBuf::from("/tmp"),
            status: QueueItemStatus::Completed,
            started_at: None,
            elapsed_duration: Some(Duration::from_secs(45)),
            completed_at: Some(Local::now()),
            total_bytes: Some(40 * 1024 * 1024),
        });

        // 1. Expanded view: check queue title has Total ETA and rows have item estimates & elapsed time
        tui.client_section = ClientSection::Downloads;
        let mut buf = ScreenBuffer::new(120, 30);
        tui.render(&mut buf);
        let text = buf.to_plain_text();

        assert!(text.contains("Total ETA:"));
        assert!(text.contains("ETA: 10s"));
        assert!(text.contains("ETA: 1m"));
        assert!(text.contains("took 45s"));
        let now_h = chrono::Local::now().format("%H:").to_string();
        assert!(
            text.contains(&now_h),
            "Done item in TUI must contain finished timestamp"
        );

        let active_pos = text.find("[ACTIVE]").expect("Active item must be present");
        let pending_pos = text
            .find("[PENDING]")
            .expect("Pending item must be present");
        let done_pos = text.find("[DONE]").expect("Done item must be present");
        assert!(
            active_pos < pending_pos,
            "Active item must be listed before Pending"
        );
        assert!(
            pending_pos < done_pos,
            "Pending item must be listed before Done"
        );

        // 2. Collapsed view: check summary line contains active ETA and Total ETA
        tui.client_section = ClientSection::Browse;
        let mut buf2 = ScreenBuffer::new(120, 30);
        tui.render(&mut buf2);
        let text2 = buf2.to_plain_text();

        assert!(text2.contains("ETA: 10s"));
        assert!(text2.contains("Total:"));

        // 3. Expanded view: changing ETA/file index/folder size does not shift filenames horizontally
        tui.client_section = ClientSection::Downloads;
        tui.download_queue[1].entry.is_dir = true;
        tui.download_queue[1].total_bytes = Some(250 * 1024 * 1024 * 1024);
        tui.active_progress.as_mut().unwrap().current_file = 1;
        tui.active_progress.as_mut().unwrap().total_files = 120;
        tui.active_progress.as_mut().unwrap().speed_mbps = 5.0;
        let mut buf_a = ScreenBuffer::new(140, 30);
        tui.render(&mut buf_a);
        let text_a = buf_a.to_plain_text();

        tui.active_progress.as_mut().unwrap().current_file = 115;
        tui.active_progress.as_mut().unwrap().speed_mbps = 120.0;
        let mut buf_b = ScreenBuffer::new(140, 30);
        tui.render(&mut buf_b);
        let text_b = buf_b.to_plain_text();

        let pending_line_a = text_a
            .lines()
            .find(|l| l.contains("big_data.tar"))
            .expect("Pending row missing in frame A");
        let pending_line_b = text_b
            .lines()
            .find(|l| l.contains("big_data.tar"))
            .expect("Pending row missing in frame B");
        let done_line_a = text_a
            .lines()
            .find(|l| l.contains("finished_docs.pdf"))
            .expect("Done row missing in frame A");
        let char_col = |line: &str, needle: &str| {
            line.find(needle)
                .map(|byte_idx| line[..byte_idx].chars().count())
        };
        assert_eq!(
            char_col(pending_line_a, "big_data.tar"),
            char_col(pending_line_b, "big_data.tar"),
            "Large folder queue filename column must stay aligned when ETA changes: '{pending_line_a}' vs '{pending_line_b}'"
        );
        assert_eq!(
            char_col(pending_line_a, "|"),
            char_col(done_line_a, "|"),
            "Pending and Done queue '|' separator must stay aligned: '{pending_line_a}' vs '{done_line_a}'"
        );

        let active_line_a = text_a
            .lines()
            .find(|l| l.contains("File ("))
            .expect("Active line missing in frame A");
        let active_line_b = text_b
            .lines()
            .find(|l| l.contains("File ("))
            .expect("Active line missing in frame B");
        assert_eq!(
            char_col(active_line_a, "— test.iso"),
            char_col(active_line_b, "— test.iso"),
            "Active download filename position must not shift when speed/ETA/file-index change: '{active_line_a}' vs '{active_line_b}'"
        );
    }

    #[test]
    fn test_tui_secret_change_disabled_when_hosting_or_downloading() {
        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);

        // 1. Idle: 'e' opens prompt, 'r' randomizes
        assert!(tui.can_change_secret());
        tui.handle_key(KeyEvent::Char('e'));
        assert!(tui.active_prompt.is_some());
        assert_eq!(
            tui.active_prompt.as_ref().unwrap().kind,
            InputPromptKind::EditSecret
        );
        tui.active_prompt = None;

        let original_secret = tui.ring_secret.clone();
        tui.handle_key(KeyEvent::Char('r'));
        assert_ne!(tui.ring_secret, original_secret);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Generated new random"));

        // 2. Active client download: 'e' and 'r' are blocked
        tui.active_queue_id = Some(99);
        assert!(tui.has_active_client_downloads());
        assert!(!tui.can_change_secret());

        let cur_secret = tui.ring_secret.clone();
        tui.handle_key(KeyEvent::Char('e'));
        assert!(tui.active_prompt.is_none());
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Wait for downloads to finish"));

        tui.handle_key(KeyEvent::Char('r'));
        assert_eq!(tui.ring_secret, cur_secret);
        assert!(tui
            .status_flash
            .as_ref()
            .unwrap()
            .0
            .contains("Wait for downloads to finish"));

        tui.active_queue_id = None;
        assert!(tui.can_change_secret());
    }

    #[test]
    fn test_tui_connection_loss_preserves_view_and_blocks_navigation() {
        let mut tui = LanShareTui::new(false, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.client_connected = true;
        tui.client_ip = "192.168.1.44".to_string();
        tui.selected_peer_name = "Studio-PC".to_string();
        tui.client_current_path = "Projects".to_string();
        tui.client_file_list = vec![
            FileEntry {
                name: "SubFolder".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: 1700000000,
            },
            FileEntry {
                name: "clip.mov".to_string(),
                is_dir: false,
                size: 512,
                modified_timestamp: 1700000000,
            },
        ];

        // Scan completes without Studio-PC
        let (scan_tx, scan_rx) = std::sync::mpsc::channel();
        scan_tx.send(Vec::new()).unwrap();
        tui.scan_rx = Some(scan_rx);
        tui.poll_channels();

        assert!(tui.client_connection_lost);
        assert!(tui.client_error.is_some());
        assert_eq!(tui.client_current_path, "Projects");
        assert_eq!(tui.client_file_list.len(), 2);

        // Folder navigation must not append path and must keep error
        tui.clear_errors();
        tui.navigate_into("SubFolder");
        assert_eq!(tui.client_current_path, "Projects");
        assert!(tui.client_error.is_some());

        // Enqueue download must be blocked
        tui.clear_errors();
        let entry = tui.client_file_list[1].clone();
        tui.enqueue_download(entry);
        assert!(tui.download_queue.is_empty());
        assert!(tui.client_error.is_some());

        // Rendered TUI keeps Remote Files view visible with HOST UNAVAILABLE banner
        let mut buf = ScreenBuffer::new(120, 30);
        tui.render(&mut buf);
        let text = buf.to_plain_text();
        assert!(text.contains("HOST UNAVAILABLE"));
        assert!(text.contains("SubFolder"));
        assert!(text.contains("clip.mov"));
    }

    #[test]
    fn test_tui_fast_typing_preserves_direct_ip_and_secret() {
        // 1. Secret setup screen fast typing (multi-byte bursts must append, not clear)
        let mut tui = LanShareTui::new(true, None, Vec::new(), false);
        assert!(!tui.secret_confirmed);
        tui.handle_key(KeyEvent::CtrlU);
        for chunk in [b"party" as &[u8], b"-ring-", b"2026"] {
            for ev in parse_key_events(chunk) {
                tui.handle_key(ev);
            }
        }
        assert_eq!(tui.ring_secret, "party-ring-2026");

        // Enter main screen and open Direct IP modal
        tui.handle_key(KeyEvent::Enter);
        assert!(tui.secret_confirmed);
        tui.handle_key(KeyEvent::Char('i'));
        assert!(matches!(
            tui.active_prompt,
            Some(InputPrompt {
                kind: InputPromptKind::DirectIp,
                ..
            })
        ));

        // 2. Direct IP fast typing (multi-byte bursts + backspace must edit cleanly, not clear)
        for chunk in [b"192.1" as &[u8], b"68.1.", b"49\x7f2"] {
            for ev in parse_key_events(chunk) {
                tui.handle_key(ev);
            }
        }
        let prompt = tui.active_prompt.as_ref().unwrap();
        assert_eq!(prompt.value, "192.168.1.42");
    }

    #[test]
    fn test_tui_client_error_renders_in_computers_panel_and_no_browse_collapse() {
        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.client_error = Some("Connection refused by 192.168.1.42".to_string());

        let mut buf = ScreenBuffer::new(120, 30);
        tui.render(&mut buf);
        let text = buf.to_plain_text();

        // No non-functional [b] Collapse hint in expanded Remote Files header
        assert!(text.contains("▼ Remote Files"));
        assert!(!text.contains("[b] Collapse"));

        // Connection error renders above Remote Files (inside Computers on LAN)
        let err_pos = text
            .find("[!] Connection refused by 192.168.1.42")
            .expect("client_error should be rendered");
        let remote_pos = text
            .find("▼ Remote Files")
            .expect("Remote Files header should be rendered");
        assert!(
            err_pos < remote_pos,
            "connection error must appear inside Computers on LAN above Remote Files"
        );
    }

    #[test]
    fn test_tui_active_uploads_nav_badges_and_large_gb_formatting() {
        use crate::server::SharedFolderRegistry;
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::Arc;

        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.secret_confirmed = true;
        tui.current_tab = TuiTab::Host;

        let folder = std::env::temp_dir().join("lanshare_tui_upload_test_dir");
        let _ = std::fs::create_dir_all(&folder);
        tui.host_folders = vec![folder.clone()];

        let (stop_tx, _stop_rx) = tokio::sync::oneshot::channel();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let active_downloads = Arc::new(AtomicUsize::new(1));
        let active_uploads = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        // 1.50 GiB sent of 2.00 GiB total (distinct decimal GB values, not "2 GB / 2 GB")
        let sent_bytes: u64 = 1610612736;
        let total_bytes: u64 = 2147483648;
        active_uploads.write().unwrap().insert(
            1,
            crate::server::ActiveUploadInfo {
                id: 1,
                peer: "192.168.1.77".to_string(),
                folder_root: folder.clone(),
                file_name: "backup.tar".to_string(),
                bytes_sent: sent_bytes,
                total_size: total_bytes,
                speed_mbps: 100.0,
                started_at: Instant::now(),
            },
        );
        tui.server_handle = Some(ServerHandle {
            is_running: Arc::new(AtomicBool::new(true)),
            local_ip: "192.168.1.10".to_string(),
            all_ips: vec!["192.168.1.10".to_string()],
            port: 4433,
            password: "party-ring-42".to_string(),
            stop_sender: stop_tx,
            shared_folders: Arc::new(std::sync::RwLock::new(vec![folder.clone()])),
            duration_hours: None,
            registry: Arc::new(std::sync::RwLock::new(SharedFolderRegistry::new(vec![
                folder.clone(),
            ]))),
            log_tx,
            active_downloads,
            active_folder_downloads: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            active_uploads,
            registry_notify_tx: tokio::sync::watch::channel(0u64).0,
        });

        // Also add an active client download to exercise both tab indicators
        tui.download_queue.push_back(QueuedDownloadItem {
            id: 10,
            peer_name: "Peer-1".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.20".to_string(),
                port: 4433,
                password: "party-ring-42".to_string(),
                peer_name: Some("Peer-1".to_string()),
            },
            is_mock: true,
            entry: FileEntry {
                name: "vm.img".to_string(),
                is_dir: false,
                size: 1_500_000_000,
                modified_timestamp: 0,
            },
            remote_subpath: "vm.img".to_string(),
            local_dest_dir: folder.clone(),
            status: QueueItemStatus::Downloading,
            started_at: Some(Instant::now() - Duration::from_secs(4)),
            elapsed_duration: None,
            completed_at: None,
            total_bytes: Some(1_500_000_000),
        });
        tui.active_queue_id = Some(10);
        tui.active_progress = Some(TransferProgress {
            selected_target: "vm.img".to_string(),
            file_name: "vm.img".to_string(),
            bytes_done: 1_000_000_000,
            bytes_total: 1_500_000_000,
            speed_mbps: 10.0,
            current_file: 1,
            total_files: 1,
            log_message: None,
            is_finished: false,
        });

        let mut buf = ScreenBuffer::new(120, 30);
        tui.render(&mut buf);
        let host_text = buf.to_plain_text();
        assert!(host_text.contains("[1] Browse LAN ● ↓1"));
        assert!(host_text.contains("[2] Share Folders ● ↑1"));
        assert!(host_text.contains("[↑ 1 uploading]"));
        assert!(host_text.contains("▶ [u] Uploads: 1 active | Total ETA:"));
        assert!(host_text.contains("backup.tar"));
        assert!(host_text.contains("ETA:"));
        assert!(!host_text.contains("▼ Uploads — Active: 1"));

        // Press 'u' to expand Active Uploads accordion and inspect detailed GB progress & Total ETA
        tui.handle_key(KeyEvent::Char('u'));
        assert_eq!(tui.host_section, HostSection::Uploads);
        let mut ubuf = ScreenBuffer::new(120, 30);
        tui.render(&mut ubuf);
        let uploads_text = ubuf.to_plain_text();
        assert!(uploads_text.contains("▼ Uploads — Active: 1 | Total ETA:"));
        assert!(uploads_text.contains("backup.tar"));
        assert!(uploads_text.contains("1.50 GB / 2.00 GB"));
        let upload_row = uploads_text
            .lines()
            .find(|l| l.contains("backup.tar"))
            .expect("Upload row should render");
        assert!(
            upload_row.find("ETA:").unwrap() < upload_row.find("backup.tar").unwrap(),
            "Upload ETA must appear left of filename so changing filenames do not shift metrics: {upload_row}"
        );

        // With multiple active uploads and section collapsed, say 'multiple' without showing individual filenames
        tui.server_handle
            .as_ref()
            .unwrap()
            .active_uploads
            .write()
            .unwrap()
            .insert(
                2,
                crate::server::ActiveUploadInfo {
                    id: 2,
                    peer: "192.168.1.88".to_string(),
                    folder_root: folder.clone(),
                    file_name: "second.iso".to_string(),
                    bytes_sent: 100_000_000,
                    total_size: 900_000_000,
                    speed_mbps: 50.0,
                    started_at: Instant::now(),
                },
            );
        tui.handle_key(KeyEvent::Char('f'));
        assert_eq!(tui.host_section, HostSection::Folders);
        let mut multi_buf = ScreenBuffer::new(120, 30);
        tui.render(&mut multi_buf);
        let multi_text = multi_buf.to_plain_text();
        assert!(
            multi_text.contains("▶ [u] Uploads: 2 active (multiple) | Total ETA:"),
            "{}",
            multi_text
        );
        assert!(!multi_text.contains("backup.tar"));
        assert!(!multi_text.contains("second.iso"));

        // Switch to Client Downloads panel and verify Total ETA consistency & immediate enqueue update
        tui.current_tab = TuiTab::Client;
        tui.client_section = ClientSection::Downloads;
        let mut cbuf1 = ScreenBuffer::new(120, 30);
        tui.render(&mut cbuf1);
        let ctext1 = cbuf1.to_plain_text();
        let active_eta_val = ctext1
            .split("ETA:")
            .nth(1)
            .and_then(|s| s.split(['—', '|', '\n']).next())
            .map(|s| s.trim().to_string())
            .expect("Active ETA should render");
        assert!(!active_eta_val.is_empty());
        let total_eta_line_1 = ctext1
            .lines()
            .find(|l| l.contains("Total ETA:"))
            .expect("Total ETA should render")
            .to_string();
        assert!(
            total_eta_line_1.contains(&format!("Total ETA: {}", active_eta_val)),
            "Total ETA ({}) should match active ETA ({})",
            total_eta_line_1,
            active_eta_val
        );

        tui.enqueue_download(FileEntry {
            name: "extra_pack.bin".to_string(),
            is_dir: false,
            size: 100_000_000,
            modified_timestamp: 0,
        });
        let mut cbuf2 = ScreenBuffer::new(120, 30);
        tui.render(&mut cbuf2);
        let ctext2 = cbuf2.to_plain_text();
        let total_eta_line_2 = ctext2
            .lines()
            .find(|l| l.contains("Total ETA:"))
            .expect("Updated Total ETA should render")
            .to_string();
        assert_ne!(
            total_eta_line_1, total_eta_line_2,
            "Total ETA must update immediately after enqueue"
        );

        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn test_tui_host_switch_and_folder_loading_clear_list_and_show_populating() {
        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.secret_confirmed = true;

        // Seed previous host session and files
        tui.client_connected = true;
        tui.client_ip = "192.168.1.10".to_string();
        tui.client_port = 4433;
        tui.selected_peer_name = "Old-Host".to_string();
        tui.client_current_path = "OldDir/Nested".to_string();
        tui.client_file_list = vec![FileEntry {
            name: "stale_prev_host.bin".to_string(),
            is_dir: false,
            size: 2048,
            modified_timestamp: 0,
        }];

        // Switching to a new host clears stale host files immediately and renders a loading spinner icon
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let busy_port = listener.local_addr().unwrap().port();
        tui.discovered_peers = vec![
            DiscoveredPeer {
                host_name: "Old-Host".to_string(),
                ip: "192.168.1.10".to_string(),
                port: 4433,
                last_seen: Instant::now(),
            },
            DiscoveredPeer {
                host_name: "New-Host".to_string(),
                ip: "127.0.0.1".to_string(),
                port: busy_port,
                last_seen: Instant::now(),
            },
        ];
        tui.cycle_peer(true);
        assert!(tui.client_loading);
        assert!(!tui.client_connected);
        assert!(tui.client_current_path.is_empty());
        assert!(tui.client_file_list.is_empty());

        // Immediately on switch (<250ms), stale files are cleared without flashing spinner
        let mut buf_fast = ScreenBuffer::new(120, 30);
        tui.render(&mut buf_fast);
        let text_fast = buf_fast.to_plain_text();
        assert!(!text_fast.contains("stale_prev_host.bin"));
        assert!(!TUI_SPINNER_FRAMES.iter().any(|f| text_fast.contains(f)));

        // Once loading exceeds the 250ms delay, spinner animation renders
        tui.client_loading_started_at =
            Some(Instant::now() - crate::core::LOADING_SPINNER_DELAY - Duration::from_millis(50));
        let mut buf1 = ScreenBuffer::new(120, 30);
        tui.render(&mut buf1);
        let text1 = buf1.to_plain_text();
        assert!(TUI_SPINNER_FRAMES.iter().any(|f| text1.contains(f)));
        assert!(!text1.contains("Populating list"));
        assert!(!text1.contains("stale_prev_host.bin"));

        // Navigating/refreshing while connected also renders spinner only after 250ms, never "(This folder is empty)"
        tui.client_connected = true;
        tui.set_client_loading(false);
        tui.set_client_loading(true);
        tui.client_current_path = "Docs".to_string();
        tui.client_file_list.clear();
        let mut buf2_fast = ScreenBuffer::new(120, 30);
        tui.render(&mut buf2_fast);
        let text2_fast = buf2_fast.to_plain_text();
        assert!(!text2_fast.contains("(This folder is empty)"));
        assert!(!TUI_SPINNER_FRAMES.iter().any(|f| text2_fast.contains(f)));

        tui.client_loading_started_at =
            Some(Instant::now() - crate::core::LOADING_SPINNER_DELAY - Duration::from_millis(50));
        let mut buf2 = ScreenBuffer::new(120, 30);
        tui.render(&mut buf2);
        let text2 = buf2.to_plain_text();
        assert!(TUI_SPINNER_FRAMES.iter().any(|f| text2.contains(f)));
        assert!(!text2.contains("Populating list"));
        assert!(!text2.contains("(This folder is empty)"));
        drop(listener);
    }

    #[test]
    fn test_tui_host_uploads_section_collapsed_by_default_and_toggles() {
        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.secret_confirmed = true;
        tui.current_tab = TuiTab::Host;

        // Default: Folders expanded; Uploads & Logs collapsed at bottom
        let mut buf = ScreenBuffer::new(120, 30);
        tui.render(&mut buf);
        let plain = buf.to_plain_text();
        assert!(plain.contains("▼ Folders to Share on LAN"), "{}", plain);
        assert!(
            plain.contains("▶ [u] Uploads: (No active uploads)"),
            "{}",
            plain
        );
        assert!(!plain.contains("No active uploads."), "{}", plain);

        // Press 'u' to expand Uploads
        tui.handle_key(KeyEvent::Char('u'));
        assert_eq!(tui.host_section, HostSection::Uploads);
        let mut buf_open = ScreenBuffer::new(120, 30);
        tui.render(&mut buf_open);
        let open_plain = buf_open.to_plain_text();
        assert!(
            open_plain.contains("▼ Uploads — Active: 0"),
            "{}",
            open_plain
        );
        assert!(open_plain.contains("No active uploads."), "{}", open_plain);

        // Press Esc or click collapsed Folders bar to collapse back to Folders
        tui.handle_key(KeyEvent::Esc);
        assert_eq!(tui.host_section, HostSection::Folders);

        // Mouse click on collapsed Uploads bar expands Uploads
        let (up_start, _) = tui
            .last_host_uploads_header_range
            .expect("Host uploads header range must be recorded");
        tui.handle_key(KeyEvent::MouseClick {
            col: 5,
            row: up_start,
        });
        assert_eq!(tui.host_section, HostSection::Uploads);
    }

    #[test]
    fn test_tui_add_file_shares_after_folders_and_shows_sizes() {
        let base = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target")
            .join(format!("lanshare_tui_share_file_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let share_dir = base.join("alpha_folder");
        std::fs::create_dir_all(&share_dir).unwrap();
        std::fs::write(share_dir.join("sub.bin"), vec![1u8; 4096]).unwrap();
        let share_file = base.join("single_doc.bin");
        std::fs::write(&share_file, vec![2u8; 2048]).unwrap();

        let mut tui = LanShareTui::new(true, Some("party-ring-42".to_string()), Vec::new(), false);
        tui.secret_confirmed = true;
        tui.current_tab = TuiTab::Host;

        // 1. Add individual file first via 'F'
        tui.handle_key(KeyEvent::Char('F'));
        assert_eq!(
            tui.active_prompt.as_ref().map(|p| p.kind),
            Some(InputPromptKind::AddHostFile)
        );
        for c in share_file.to_string_lossy().chars() {
            tui.handle_key(KeyEvent::Char(c));
        }
        tui.handle_key(KeyEvent::Enter);
        assert!(tui.active_prompt.is_none());
        assert_eq!(tui.host_folders.len(), 1);

        // 2. Add folder next via 'a' -> folder must sort ahead of file
        tui.handle_key(KeyEvent::Char('a'));
        assert_eq!(
            tui.active_prompt.as_ref().map(|p| p.kind),
            Some(InputPromptKind::AddHostFolder)
        );
        for c in share_dir.to_string_lossy().chars() {
            tui.handle_key(KeyEvent::Char(c));
        }
        tui.handle_key(KeyEvent::Enter);
        assert!(tui.active_prompt.is_none());
        assert_eq!(tui.host_folders.len(), 2);
        assert!(tui.host_folders[0].is_dir(), "Folders must precede files");
        assert!(tui.host_folders[1].is_file(), "Files must follow folders");

        let mut buf = ScreenBuffer::new(140, 30);
        tui.render(&mut buf);
        let plain = buf.to_plain_text();
        let dir_pos = plain.find("[DIR]").expect("Missing [DIR] tag");
        let file_pos = plain.find("[FILE]").expect("Missing [FILE] tag");
        assert!(dir_pos < file_pos, "Shared folder must render before file");
        assert!(
            plain.contains("(4 KB)"),
            "Expected folder size (4 KB) in TUI shares list: {}",
            plain
        );
        assert!(
            plain.contains("(2 KB)"),
            "Expected file size (2 KB) in TUI shares list: {}",
            plain
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
