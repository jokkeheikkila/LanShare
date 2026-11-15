use crate::client::{self, ClientTlsStream, ConnectionContext, TransferProgress};
use crate::core::{
    complete_queued_download, default_mock_peers, dirs_fallback, estimate_folder_remaining_seconds,
    estimate_remaining_seconds, format_completed_timestamp, format_file_size,
    format_remaining_time, format_secret_display, generate_random_password,
    has_active_client_downloads as core_has_active_client_downloads, mock_directory_entries,
    open_file_in_default_app, open_folder_in_explorer, open_url, queue_status_sort_rank,
    sort_peers_alphabetically, spawn_next_queued_download, test_downloads_dir, ClientActionResult,
    EtaStabilizer, QueueItemStatus, QueuedDownloadItem, GITHUB_RELEASES_URL, GITHUB_REPO_URL,
};
use crate::protocol::{
    DiscoveredPeer, FileEntry, HandshakeResponse, DEFAULT_TCP_PORT, MIN_SECRET_LEN,
};
use crate::security::{clean_display_path, validate_shared_folder};
use crate::server::{self, ServerHandle, ServerLogEvent};
use arboard::Clipboard;
use chrono::{Local, TimeZone};
use eframe::egui::{
    self, Color32, CornerRadius, FontId, RichText, ScrollArea, Stroke, TextStyle, Vec2,
};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum AppTab {
    Client,
    Host,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub enum ThemePreference {
    #[default]
    Auto,
    Dark,
    Light,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppPalette {
    pub is_dark: bool,
    pub panel_bg: Color32,
    pub card_bg: Color32,
    pub card_secondary_bg: Color32,
    pub border: Color32,
    pub text_primary: Color32,
    pub text_muted: Color32,
    pub text_subtle: Color32,
    pub tab_active_bg: Color32,
    pub tab_active_text: Color32,
    pub tab_inactive_bg: Color32,
    pub tab_inactive_text: Color32,
    pub btn_primary_bg: Color32,
    pub btn_primary_text: Color32,
    pub btn_disabled_bg: Color32,
    pub btn_disabled_text: Color32,
    pub btn_secondary_bg: Color32,
    pub btn_secondary_text: Color32,
    pub accent_green: Color32,
    pub accent_blue: Color32,
    pub accent_amber: Color32,
    pub accent_red: Color32,
    pub browse_row_stripe_bg: Color32,
    pub browse_row_hover_bg: Color32,
}

impl AppPalette {
    pub fn new(is_dark: bool) -> Self {
        if is_dark {
            Self {
                is_dark: true,
                panel_bg: Color32::from_rgb(15, 20, 28),
                card_bg: Color32::from_rgb(26, 34, 48),
                card_secondary_bg: Color32::from_rgb(21, 28, 40),
                border: Color32::from_rgb(51, 65, 85),
                text_primary: Color32::from_rgb(241, 245, 249),
                text_muted: Color32::from_rgb(148, 163, 184),
                text_subtle: Color32::from_rgb(100, 116, 139),
                tab_active_bg: Color32::from_rgb(37, 99, 235),
                tab_active_text: Color32::WHITE,
                tab_inactive_bg: Color32::from_rgb(26, 34, 48),
                tab_inactive_text: Color32::from_rgb(203, 213, 225),
                btn_primary_bg: Color32::from_rgb(37, 99, 235),
                btn_primary_text: Color32::WHITE,
                btn_disabled_bg: Color32::from_rgb(38, 48, 64),
                btn_disabled_text: Color32::from_rgb(100, 116, 139),
                btn_secondary_bg: Color32::from_rgb(30, 41, 59),
                btn_secondary_text: Color32::from_rgb(226, 232, 240),
                accent_green: Color32::from_rgb(52, 211, 153),
                accent_blue: Color32::from_rgb(96, 165, 250),
                accent_amber: Color32::from_rgb(251, 191, 36),
                accent_red: Color32::from_rgb(248, 113, 113),
                browse_row_stripe_bg: Color32::from_rgb(21, 28, 40),
                browse_row_hover_bg: Color32::from_rgba_unmultiplied(37, 99, 235, 28),
            }
        } else {
            Self {
                is_dark: false,
                panel_bg: Color32::from_rgb(243, 244, 246),
                card_bg: Color32::WHITE,
                card_secondary_bg: Color32::from_rgb(247, 248, 250),
                border: Color32::from_rgb(226, 230, 235),
                text_primary: Color32::from_rgb(15, 23, 42),
                text_muted: Color32::from_rgb(100, 116, 139),
                text_subtle: Color32::from_rgb(148, 163, 184),
                tab_active_bg: Color32::from_rgb(15, 23, 42),
                tab_active_text: Color32::WHITE,
                tab_inactive_bg: Color32::WHITE,
                tab_inactive_text: Color32::from_rgb(15, 23, 42),
                btn_primary_bg: Color32::from_rgb(15, 23, 42),
                btn_primary_text: Color32::WHITE,
                btn_disabled_bg: Color32::from_rgb(226, 230, 235),
                btn_disabled_text: Color32::from_rgb(148, 163, 184),
                btn_secondary_bg: Color32::from_rgb(243, 244, 246),
                btn_secondary_text: Color32::from_rgb(51, 65, 85),
                accent_green: Color32::from_rgb(16, 185, 129),
                accent_blue: Color32::from_rgb(37, 99, 235),
                accent_amber: Color32::from_rgb(217, 119, 6),
                accent_red: Color32::from_rgb(220, 38, 38),
                browse_row_stripe_bg: Color32::from_rgb(226, 232, 240),
                browse_row_hover_bg: Color32::from_rgb(203, 224, 253),
            }
        }
    }
}

pub const BROWSE_COL_SIZE_W: f32 = 85.0;
pub const BROWSE_COL_DATE_W: f32 = 135.0;
pub const BROWSE_COL_ACTION_W: f32 = 76.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSourceFilter {
    All,
    Client,
    Server,
}

pub struct LanShareApp {
    tokio_rt: Runtime,

    // Theme (Auto reflects OS mode)
    theme_preference: ThemePreference,
    last_applied_dark: Option<bool>,

    // Two-Stage Startup Flow
    secret_confirmed: bool,

    // Single-User Test / Mock Mode
    test_mode: bool,
    mock_session: bool,

    // Active Tab (Browse LAN on left, Share Folders on right)
    current_tab: AppTab,

    // About Modal
    show_about: bool,
    focus_about_window: bool,

    // Shared LAN Secret (used for both discovering computers and sharing folders)
    ring_secret: String,
    show_secret_plain: bool,
    local_ips: Vec<String>,

    // --- Host State ---
    host_folders: Vec<PathBuf>,
    host_error: Option<String>,
    server_handle: Option<ServerHandle>,
    server_logs: VecDeque<ServerLogEvent>,
    server_log_rx: Receiver<ServerLogEvent>,
    server_log_tx: tokio::sync::mpsc::UnboundedSender<ServerLogEvent>,

    // --- Client State ---
    client_ip: String,
    client_port: u16,
    direct_ip_input: String,
    selected_peer_name: String,
    client_dest_folder: PathBuf,
    client_error: Option<String>,
    discovered_peers: Vec<DiscoveredPeer>,
    is_scanning: bool,
    scan_rx: Option<Receiver<Vec<DiscoveredPeer>>>,

    // Connected Client Browsing Session
    client_connected: bool,
    client_connection_lost: bool,
    connected_via_direct_ip: bool,
    client_handshake: Option<HandshakeResponse>,
    client_stream: Option<ClientTlsStream>,
    client_current_path: String,
    client_file_list: Vec<FileEntry>,
    client_loading: bool,

    // Async Channel for Client actions
    client_action_rx: Receiver<ClientActionResult>,
    client_action_tx: Sender<ClientActionResult>,

    // Multi-Item Download Queue & Active Transfer Progress
    next_queue_id: u64,
    download_queue: VecDeque<QueuedDownloadItem>,
    keep_downloads_panel_visible: bool,
    active_queue_id: Option<u64>,
    active_progress: Option<TransferProgress>,
    progress_finished_at: Option<Instant>,
    active_eta_stabilizer: EtaStabilizer,
    total_eta_stabilizer: EtaStabilizer,
    progress_rx: Receiver<TransferProgress>,
    progress_tx: tokio::sync::mpsc::UnboundedSender<TransferProgress>,
    transfer_cancel_tx: Option<tokio::sync::watch::Sender<bool>>,

    // Client Activity Log
    client_logs: VecDeque<String>,

    // Dedicated Activity Log Window
    show_log_window: bool,
    focus_log_window: bool,
    log_auto_scroll: bool,
    log_source_filter: LogSourceFilter,

    // Clipboard Handle & Status Flash
    clipboard: Option<Clipboard>,
    clipboard_flash: Option<(String, Instant)>,

    // Window Close Confirmation State
    show_close_confirm_dialog: bool,
    close_confirmed: bool,

    // Server Stop Confirmation State
    show_stop_server_confirm_dialog: bool,
    pending_remove_host_folder_idx: Option<usize>,

    // Adjustable Download Queue Section Height
    download_section_height: f32,

    // Resizable Browse Table Name Column Width
    browse_col_name_w: f32,

    // Interactive Hover Link & Directory Highlight State
    hovered_browse_download_idx: Option<usize>,
    hovered_host_remove_idx: Option<usize>,
}

fn load_clean_system_font(ctx: &egui::Context) {
    let sans_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "/System/Library/Fonts/SFPro.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ];

    let mono_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "C:\\Windows\\Fonts\\consola.ttf",
        "C:\\Windows\\Fonts\\cour.ttf",
        "/System/Library/Fonts/Monaco.ttf",
    ];

    let mut fonts = egui::FontDefinitions::default();
    let mut updated = false;

    for path in sans_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(
                "system_sans".to_string(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.insert(0, "system_sans".to_string());
            }
            updated = true;
            break;
        }
    }

    for path in mono_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(
                "system_mono".to_string(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                family.insert(0, "system_mono".to_string());
            }
            updated = true;
            break;
        }
    }

    let symbol_candidates = [
        "C:\\Windows\\Fonts\\seguisym.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
    ];

    for path in symbol_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(
                "system_symbols".to_string(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.push("system_symbols".to_string());
            }
            updated = true;
            break;
        }
    }

    if updated {
        ctx.set_fonts(fonts);
    }
}

/// Returns the embedded application icon (256x256 RGBA) wrapped in an Arc for zero-copy reuse.
pub fn app_icon() -> Option<std::sync::Arc<egui::IconData>> {
    static ICON: std::sync::OnceLock<Option<std::sync::Arc<egui::IconData>>> =
        std::sync::OnceLock::new();
    ICON.get_or_init(|| {
        eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
            .ok()
            .map(std::sync::Arc::new)
    })
    .clone()
}

fn configure_readable_style(ctx: &egui::Context, is_dark: bool) {
    load_clean_system_font(ctx);

    let mut style = (*ctx.global_style()).clone();
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(18.0));
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(13.0));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(12.0));

    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.button_padding = Vec2::new(10.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(10);

    let p = AppPalette::new(is_dark);

    let mut visuals = if is_dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.dark_mode = is_dark;
    visuals.override_text_color = Some(p.text_primary);

    // Background fills
    visuals.panel_fill = p.panel_bg;
    visuals.window_fill = p.card_bg;
    visuals.extreme_bg_color = if is_dark {
        Color32::from_rgb(18, 24, 34)
    } else {
        Color32::from_rgb(228, 232, 238)
    };
    visuals.faint_bg_color = p.card_secondary_bg;

    // Widget CornerRadius & Borders
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(8);
    visuals.widgets.noninteractive.bg_fill = p.card_bg;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.text_primary);

    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
    visuals.widgets.inactive.bg_fill = p.card_bg;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.text_muted);

    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
    visuals.widgets.hovered.bg_fill = if is_dark {
        Color32::from_rgb(45, 55, 72)
    } else {
        Color32::from_rgb(226, 232, 240)
    };
    visuals.widgets.hovered.bg_stroke = Stroke::new(
        1.0_f32,
        if is_dark {
            p.accent_blue
        } else {
            Color32::from_rgb(147, 175, 224)
        },
    );
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, p.text_primary);

    visuals.widgets.active.corner_radius = CornerRadius::same(6);
    visuals.widgets.active.bg_fill = if is_dark {
        Color32::from_rgb(55, 65, 81)
    } else {
        Color32::from_rgb(214, 222, 234)
    };
    visuals.widgets.active.bg_stroke = Stroke::new(1.2_f32, p.accent_blue);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, p.text_primary);

    visuals.selection.bg_fill = if is_dark {
        Color32::from_rgb(30, 58, 138)
    } else {
        Color32::from_rgb(191, 219, 254)
    };
    visuals.selection.stroke = Stroke::new(1.0_f32, p.text_primary);

    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.window_stroke = Stroke::new(1.0_f32, p.border);

    style.visuals = visuals;
    ctx.set_global_style(style);
}

impl LanShareApp {
    pub fn new(cc: &eframe::CreationContext<'_>, test_mode: bool) -> Self {
        Self::with_secret(cc, test_mode, None)
    }

    pub fn with_secret(
        cc: &eframe::CreationContext<'_>,
        test_mode: bool,
        cli_secret: Option<String>,
    ) -> Self {
        let is_initial_dark = match cc.egui_ctx.system_theme() {
            Some(egui::Theme::Dark) => true,
            Some(egui::Theme::Light) => false,
            None => cc.egui_ctx.theme() == egui::Theme::Dark,
        };
        configure_readable_style(&cc.egui_ctx, is_initial_dark);

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

        let (ring_secret, secret_confirmed) = match cli_secret {
            Some(s) if s.trim().len() >= MIN_SECRET_LEN => (s.trim().to_string(), true),
            Some(s) => (s, false),
            None => (String::new(), false),
        };
        let local_ips = crate::network::get_all_local_lan_ips();
        let mut client_logs = VecDeque::new();
        let mut discovered_peers = Vec::new();

        if test_mode {
            discovered_peers = default_mock_peers();
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let entry = format!("[{}] Test Mode active with 2 simulated LAN computers.", ts);
            crate::core::spool_log_entry(&format!("[Client] {}", entry));
            client_logs.push_back(entry);
        }

        crate::core::spool_log_session_start("GUI");

        let mut app = Self {
            tokio_rt,
            theme_preference: ThemePreference::Auto,
            last_applied_dark: Some(is_initial_dark),
            secret_confirmed,
            test_mode,
            mock_session: false,
            current_tab: AppTab::Client,
            show_about: false,
            focus_about_window: false,

            ring_secret,
            show_secret_plain: false,
            local_ips,

            host_folders: Vec::new(),
            host_error: None,
            server_handle: None,
            server_logs: VecDeque::new(),
            server_log_rx: server_log_std_rx,
            server_log_tx: server_log_tokio_tx,

            client_ip: String::new(),
            client_port: DEFAULT_TCP_PORT,
            direct_ip_input: String::new(),
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
            client_loading: false,

            client_action_rx,
            client_action_tx,

            next_queue_id: 1,
            download_queue: VecDeque::new(),
            keep_downloads_panel_visible: false,
            active_queue_id: None,
            active_progress: None,
            progress_finished_at: None,
            active_eta_stabilizer: EtaStabilizer::new(),
            total_eta_stabilizer: EtaStabilizer::new(),
            progress_rx: prog_std_rx,
            progress_tx: prog_tokio_tx,
            transfer_cancel_tx: None,

            client_logs,
            show_log_window: false,
            focus_log_window: false,
            log_auto_scroll: true,
            log_source_filter: LogSourceFilter::All,

            clipboard: None,
            clipboard_flash: None,

            show_close_confirm_dialog: false,
            close_confirmed: false,
            show_stop_server_confirm_dialog: false,
            pending_remove_host_folder_idx: None,

            download_section_height: 220.0,

            browse_col_name_w: 260.0,

            hovered_browse_download_idx: None,
            hovered_host_remove_idx: None,
        };
        if app.secret_confirmed {
            app.trigger_ring_scan();
        }
        app
    }

    pub fn set_status_flash(&mut self, msg: impl Into<String>) {
        self.clipboard_flash = Some((msg.into(), Instant::now()));
    }

    pub fn clear_errors(&mut self) {
        self.host_error = None;
        self.client_error = None;
    }

    fn switch_tab(&mut self, tab: AppTab) {
        self.current_tab = tab;
        self.clear_errors();
    }

    fn copy_to_clipboard(&mut self, ctx: &egui::Context, text: &str, label: &str) {
        ctx.copy_text(text.to_string());
        if !cfg!(test) {
            // Keep the arboard Clipboard handle alive on the app struct so X11/Wayland
            // selection ownership is not dropped right after copying.
            if self.clipboard.is_none() {
                self.clipboard = Clipboard::new().ok();
            }
            if let Some(ref mut cb) = self.clipboard {
                let _ = cb.set_text(text.to_string());
            }
        }
        self.set_status_flash(format!("Copied {}!", label));
    }

    pub fn effective_dark_mode(&self, ctx: &egui::Context) -> bool {
        match self.theme_preference {
            ThemePreference::Dark => true,
            ThemePreference::Light => false,
            ThemePreference::Auto => match ctx.system_theme() {
                Some(egui::Theme::Dark) => true,
                Some(egui::Theme::Light) => false,
                None => ctx.theme() == egui::Theme::Dark,
            },
        }
    }

    pub fn palette(&self, ctx: &egui::Context) -> AppPalette {
        AppPalette::new(self.effective_dark_mode(ctx))
    }

    fn cycle_theme(&mut self, ctx: &egui::Context) {
        self.theme_preference = match self.theme_preference {
            ThemePreference::Auto => ThemePreference::Dark,
            ThemePreference::Dark => ThemePreference::Light,
            ThemePreference::Light => ThemePreference::Auto,
        };
        let is_dark = self.effective_dark_mode(ctx);
        configure_readable_style(ctx, is_dark);
        self.last_applied_dark = Some(is_dark);
    }

    pub fn current_status_message(&self, p: &AppPalette) -> (String, Color32) {
        if let Some((ref msg, time)) = self.clipboard_flash {
            if time.elapsed() < Duration::from_millis(2500) {
                if msg.starts_with("Copied ") {
                    let target = msg.trim_start_matches("Copied ").trim_end_matches('!');
                    return (format!("✓ Copied {} to clipboard", target), p.accent_green);
                } else if msg.contains("already in") {
                    return (format!("ℹ {}", msg), p.accent_amber);
                } else {
                    return (format!("✓ {}", msg), p.accent_green);
                }
            }
        }

        if !self.secret_confirmed {
            let secret_len = self.ring_secret.trim().len();
            if secret_len == 0 {
                (
                    "Enter Share-Ring secret to begin".to_string(),
                    p.text_subtle,
                )
            } else if secret_len < MIN_SECRET_LEN {
                (
                    format!(
                        "Secret must be at least {} characters ({} / {} required)",
                        MIN_SECRET_LEN, secret_len, MIN_SECRET_LEN
                    ),
                    p.accent_amber,
                )
            } else {
                (String::new(), p.text_subtle)
            }
        } else if let Some(ref err) = self.client_error {
            (format!("Error: {}", err), p.accent_red)
        } else if let Some(ref err) = self.host_error {
            (format!("Error: {}", err), p.accent_red)
        } else if let Some(ref prog) = self.active_progress {
            let pct = if prog.bytes_total > 0 {
                ((prog.bytes_done as f64 / prog.bytes_total as f64) * 100.0).clamp(0.0, 100.0)
                    as u32
            } else {
                0
            };
            if crate::core::is_transfer_waiting_status(&prog.file_name) {
                (
                    format!("{} ({}%): {}", prog.selected_target, pct, prog.file_name),
                    p.accent_amber,
                )
            } else {
                (
                    format!(
                        "↓ Downloading {}: {}% ({})",
                        prog.file_name,
                        pct,
                        format_file_size(prog.bytes_done)
                    ),
                    p.accent_blue,
                )
            }
        } else if self.is_scanning {
            (
                "Scanning local network for computers...".to_string(),
                p.accent_blue,
            )
        } else if self.client_loading {
            ("Loading folder contents...".to_string(), p.accent_blue)
        } else if self.server_handle.is_some() {
            let count = self.host_folders.len();
            let folder_word = if count == 1 { "folder" } else { "folders" };
            (
                format!("● Hosting active (sharing {} {})", count, folder_word),
                p.accent_green,
            )
        } else {
            (String::new(), p.text_subtle)
        }
    }

    fn render_status_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let p = self.palette(&ctx);
        let border_color = p.border;

        egui::Panel::bottom("app_status_bar")
            .resizable(false)
            .show_separator_line(false)
            .frame(
                egui::Frame::NONE
                    .fill(p.card_secondary_bg)
                    .stroke(Stroke::new(1.0_f32, border_color))
                    .inner_margin(egui::Margin {
                        left: 14,
                        right: 14,
                        top: 5,
                        bottom: 5,
                    }),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Right side: Theme toggle and About link (Theme on left, About on right)
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let about_link = ui.add(
                            egui::Label::new(
                                RichText::new("About")
                                    .size(12.0)
                                    .underline()
                                    .color(p.text_muted),
                            )
                            .sense(egui::Sense::click()),
                        );
                        if about_link.hovered() {
                            ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        if about_link.clicked() {
                            self.show_about = true;
                            self.focus_about_window = true;
                            let id = egui::ViewportId::from_hash_of("about_viewport");
                            ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Minimized(false));
                            ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Focus);
                        }
                        let _ = about_link.on_hover_text("About LanShare");

                        ui.add_space(6.0);
                        ui.label(RichText::new("•").size(11.0).color(p.text_subtle));
                        ui.add_space(6.0);

                        let theme_label = match self.theme_preference {
                            ThemePreference::Auto => {
                                if p.is_dark {
                                    "Theme: Auto (Dark)"
                                } else {
                                    "Theme: Auto (Light)"
                                }
                            }
                            ThemePreference::Dark => "Theme: Dark",
                            ThemePreference::Light => "Theme: Light",
                        };
                        let theme_link = ui.add(
                            egui::Label::new(
                                RichText::new(theme_label)
                                    .size(12.0)
                                    .underline()
                                    .color(p.text_muted),
                            )
                            .sense(egui::Sense::click()),
                        );
                        if theme_link.hovered() {
                            ctx.set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                        if theme_link.clicked() {
                            self.cycle_theme(&ctx);
                        }
                        let _ = theme_link.on_hover_text("Switch theme (Auto reflects OS mode)");

                        ui.add_space(10.0);

                        // Left side: Status indicators, secret copy confirmation, and general status
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            let (status_text, status_color) = self.current_status_message(&p);
                            if !status_text.is_empty() {
                                let is_strong = status_text.starts_with('✓')
                                    || status_text.starts_with("Error:");
                                let text =
                                    RichText::new(status_text).size(12.0).color(status_color);
                                let text = if is_strong { text.strong() } else { text };
                                ui.add(egui::Label::new(text).truncate());
                            }
                        });
                    });
                });
            });
    }

    fn is_local_peer(&self, peer: &DiscoveredPeer) -> bool {
        if peer.ip == "127.0.0.1" || self.local_ips.contains(&peer.ip) {
            return true;
        }
        if let Some(ref handle) = self.server_handle {
            if handle.local_ip == peer.ip || handle.all_ips.contains(&peer.ip) {
                return true;
            }
        }
        false
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

    pub fn is_hosting_active(&self) -> bool {
        self.server_handle
            .as_ref()
            .map(|h| h.is_running.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false)
    }

    pub fn has_active_client_downloads(&self) -> bool {
        core_has_active_client_downloads(
            self.active_progress.as_ref(),
            self.active_queue_id,
            &self.download_queue,
        )
    }

    pub fn can_change_secret(&self) -> bool {
        !self.is_hosting_active() && !self.has_active_client_downloads()
    }

    pub fn needs_close_confirmation(&self) -> bool {
        self.is_hosting_active()
            || self.active_server_downloads() > 0
            || self.has_active_client_downloads()
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

    fn poll_scan_results(&mut self) {
        if let Some(ref rx) = self.scan_rx {
            if let Ok(mut peers) = rx.try_recv() {
                // Ensure local server is present if hosting (Fixes Issue 2)
                if let Some(ref handle) = self.server_handle {
                    let my_name = crate::network::get_computer_name();
                    if !peers.iter().any(|p| self.is_local_peer(p)) {
                        peers.push(DiscoveredPeer {
                            host_name: my_name,
                            ip: handle.local_ip.clone(),
                            port: handle.port,
                            last_seen: Instant::now(),
                        });
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
    }

    fn poll_client_action_results(&mut self) {
        while let Ok(action) = self.client_action_rx.try_recv() {
            match action {
                ClientActionResult::Connected(stream, resp, ip) => {
                    self.client_loading = false;
                    self.client_connected = true;
                    self.client_connection_lost = false;
                    self.mock_session = false;
                    self.client_ip = ip.clone();
                    self.selected_peer_name = resp.server_name.clone();
                    if !self.discovered_peers.iter().any(|p| p.ip == ip) {
                        self.discovered_peers.push(DiscoveredPeer {
                            host_name: resp.server_name.clone(),
                            ip: ip.clone(),
                            port: DEFAULT_TCP_PORT,
                            last_seen: Instant::now(),
                        });
                        sort_peers_alphabetically(&mut self.discovered_peers);
                    }
                    self.client_handshake = Some(resp);
                    self.client_stream = Some(stream);
                    self.client_error = None;
                    self.client_current_path.clear();
                    self.refresh_client_listing();
                }
                ClientActionResult::ConnectFailed(err) => {
                    self.client_loading = false;
                    self.mock_session = false;
                    self.client_stream = None;
                    if self.client_connected || !self.client_file_list.is_empty() {
                        // Preserve existing file list and downloads in read-only unavailable state
                        self.client_connection_lost = true;
                    } else {
                        self.client_connected = false;
                        self.client_connection_lost = false;
                    }
                    self.client_error = Some(err);
                }
                ClientActionResult::ListingLoaded(stream, loaded_path, entries) => {
                    self.client_loading = false;
                    self.client_connection_lost = false;
                    self.client_stream = Some(stream);
                    self.client_current_path = loaded_path;
                    self.client_file_list = entries;
                    self.client_error = None;
                }
                ClientActionResult::ListingFailed(stream, err) => {
                    self.client_loading = false;
                    let is_transport_loss = stream.is_none();
                    self.client_stream = stream;
                    if is_transport_loss {
                        self.client_connection_lost = true;
                    }
                    self.client_error = Some(err);
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
                    if let Some(err) = outcome.error {
                        self.client_error = Some(err);
                    }
                    self.start_next_queued_download();
                }
            }
        }
    }
}

impl eframe::App for LanShareApp {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Intercept window close request when shares or transfers are active
        if ctx.input(|i| i.viewport().close_requested())
            && !self.close_confirmed
            && self.needs_close_confirmation()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.show_close_confirm_dialog = true;
        }

        let is_dark = self.effective_dark_mode(&ctx);
        if self.last_applied_dark != Some(is_dark) {
            configure_readable_style(&ctx, is_dark);
            self.last_applied_dark = Some(is_dark);
        }

        if self.active_progress.is_some()
            || self.active_queue_id.is_some()
            || self.client_loading
            || self.clipboard_flash.is_some()
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        } else if self.is_scanning {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        // Drain server logs (capped at 500 entries in memory, spooled to disk)
        while let Ok(evt) = self.server_log_rx.try_recv() {
            self.push_server_log(evt);
        }

        // Check if server auto-stopped
        if let Some(ref handle) = self.server_handle {
            if !handle.is_running.load(std::sync::atomic::Ordering::Relaxed) {
                let local_ips = self.local_ips.clone();
                let s_ip = handle.local_ip.clone();
                self.server_handle = None;
                self.discovered_peers
                    .retain(|p| !local_ips.contains(&p.ip) && p.ip != s_ip && p.ip != "127.0.0.1");
            }
        }

        // Note: Automatic periodic refresh is intentionally disabled.
        // LAN scanning runs only when the user clicks "Scan LAN".

        // Drain manual LAN scan results
        self.poll_scan_results();

        // Drain transfer progress
        while let Ok(p) = self.progress_rx.try_recv() {
            if let Some(ref msg) = p.log_message {
                let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                self.push_client_log(format!("[{}] {}", ts, msg));
            }

            if let Some(active_id) = self.active_queue_id {
                if let Some(item) = self.download_queue.iter_mut().find(|i| i.id == active_id) {
                    if p.bytes_total > 0 {
                        item.total_bytes = Some(p.bytes_total);
                    } else if p.bytes_done > 0 {
                        item.total_bytes = Some(p.bytes_done);
                    }
                }
            }

            if p.is_finished {
                self.active_progress = Some(p);
                self.progress_finished_at = Some(Instant::now());
            } else {
                self.active_progress = Some(p);
                self.progress_finished_at = None;
            }
        }

        // Drain client action results
        self.poll_client_action_results();

        if self.active_queue_id.is_none() {
            self.start_next_queued_download();
        }

        if self.active_queue_id.is_none() {
            if let Some(t) = self.progress_finished_at {
                if t.elapsed() >= Duration::from_millis(3500) {
                    self.active_progress = None;
                    self.active_eta_stabilizer.reset();
                    self.progress_finished_at = None;
                }
            }
        }

        // Drag & Drop handling on Share Folders tab
        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            let mut added_any = false;
            if self.current_tab == AppTab::Host {
                self.clear_errors();
            }
            for file in dropped {
                let path = file.path();
                if self.current_tab == AppTab::Host && path.is_dir() {
                    match validate_shared_folder(path) {
                        Ok(safe) => {
                            if !self.host_folders.contains(&safe) {
                                self.host_folders.push(safe);
                                added_any = true;
                            }
                        }
                        Err(e) => self.host_error = Some(e),
                    }
                }
            }
            if added_any {
                if let Some(ref handle) = self.server_handle {
                    if let Err(e) = handle.update_shared_folders(self.host_folders.clone()) {
                        self.host_error = Some(e);
                    }
                } else if self.ring_secret.trim().len() >= MIN_SECRET_LEN {
                    self.start_hosting_server();
                }
            }
        }

        self.render_about_modal(&ctx);
        self.render_log_window(&ctx);
        self.render_close_confirm_modal(&ctx);
        self.render_stop_server_confirm_modal(&ctx);

        // Unified Status Bar rendered across bottom of entire window (consistent across login and main views)
        self.render_status_bar(ui);

        if let Some((_, time)) = self.clipboard_flash {
            if time.elapsed() >= Duration::from_millis(2500) {
                self.clipboard_flash = None;
            }
        }

        if !self.secret_confirmed {
            let p = self.palette(&ctx);
            let panel_bg = p.panel_bg;

            egui::CentralPanel::default()
                .frame(egui::Frame::central_panel(&ctx.global_style()).fill(panel_bg))
                .show(ui, |ui| {
                    self.render_initial_secret_dialog(ui);
                });
            return;
        }

        self.render_main_left_rail(ui);

        match self.current_tab {
            AppTab::Client => self.render_client_view(ui),
            AppTab::Host => {
                let p = self.palette(&ctx);
                let panel_bg = p.panel_bg;
                egui::CentralPanel::default()
                    .frame(egui::Frame::central_panel(&ctx.global_style()).fill(panel_bg))
                    .show(ui, |ui| {
                        ScrollArea::vertical()
                            .id_salt("host_central_scroll")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                self.render_host_tab(ui);
                            });
                    });
            }
        }
    }
}

impl LanShareApp {
    fn render_initial_secret_dialog(&mut self, ui: &mut egui::Ui) {
        let p = self.palette(ui.ctx());
        let avail_size = ui.available_size();

        ui.vertical_centered(|ui| {
            let top_pad = (avail_size.y - 180.0).max(40.0) / 2.0;
            ui.add_space(top_pad);

            let card_frame = egui::Frame {
                inner_margin: egui::Margin::symmetric(28, 24),
                outer_margin: egui::Margin::same(0),
                corner_radius: CornerRadius::same(10),
                shadow: egui::epaint::Shadow::NONE,
                fill: p.card_bg,
                stroke: Stroke::new(1.0_f32, p.border),
            };

            card_frame.show(ui, |ui| {
                ui.set_width(430.0);

                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("LanShare")
                            .size(24.0)
                            .strong()
                            .color(p.text_primary),
                    );
                    ui.label(
                        RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .size(12.0)
                            .color(p.text_muted),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Enter Share-Ring Secret")
                            .size(13.5)
                            .strong()
                            .color(p.text_primary),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(
                            "Join an existing ring by entering a secret others shared with you,",
                        )
                        .size(12.5)
                        .color(p.text_muted),
                    );
                    ui.label(
                        RichText::new("or create a new ring by typing or generating one.")
                            .size(12.5)
                            .color(p.text_muted),
                    );
                });

                ui.add_space(16.0);

                let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 3.0;
                    let input_width = (ui.available_width() - 120.0).max(160.0);
                    let text_edit = egui::TextEdit::singleline(&mut self.ring_secret)
                        .desired_width(input_width)
                        .font(FontId::monospace(14.0))
                        .hint_text(format!("Secret ({}+ chars)...", MIN_SECRET_LEN));
                    let _ = ui.add(text_edit);

                    let has_secret = !self.ring_secret.is_empty();
                    ui.add_enabled_ui(has_secret, |ui| {
                        let copy_resp = Self::draw_icon_button(
                            ui,
                            "Copy secret to clipboard",
                            |ui, rect, color| {
                                Self::draw_mini_copy_icon_in_rect(ui, rect, color);
                            },
                        );
                        copy_resp.surrender_focus();
                        if copy_resp.clicked() {
                            let sec_clone = self.ring_secret.clone();
                            self.copy_to_clipboard(ui.ctx(), &sec_clone, "LAN Secret");
                        }
                    });

                    ui.add_space(6.0);
                    let random_btn = egui::Button::new(RichText::new("Random").size(13.5))
                        .min_size(Vec2::new(80.0, 28.0));
                    let random_resp = ui.add(random_btn).on_hover_text("Generate random secret");
                    random_resp.surrender_focus();
                    if random_resp.clicked() {
                        self.ring_secret = generate_random_password();
                    }
                });

                let is_valid = self.ring_secret.trim().len() >= MIN_SECRET_LEN;
                ui.add_space(14.0);

                let btn_fill = if is_valid {
                    p.btn_primary_bg
                } else {
                    p.btn_disabled_bg
                };
                let btn_text_color = if is_valid {
                    p.btn_primary_text
                } else {
                    p.btn_disabled_text
                };
                let enter_btn = egui::Button::new(
                    RichText::new("Join Ring")
                        .size(15.0)
                        .strong()
                        .color(btn_text_color),
                )
                .fill(btn_fill)
                .stroke(Stroke::NONE)
                .min_size(Vec2::new(ui.available_width(), 38.0));

                let clicked = ui.add_enabled(is_valid, enter_btn).clicked();
                if (clicked || (enter_pressed && is_valid)) && is_valid {
                    self.disconnect_client_session();
                    self.secret_confirmed = true;
                    self.show_secret_plain = false;
                    self.trigger_ring_scan();
                }
            });
        });
    }

    fn render_main_left_rail(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let is_hosting = self.server_handle.is_some();
        let p = self.palette(&ctx);
        let border_color = p.border;
        let text_dark = p.text_primary;
        let text_muted = p.text_muted;

        let rail_frame = egui::Frame {
            inner_margin: egui::Margin {
                left: 10,
                right: 10,
                top: 14,
                bottom: 4,
            },
            outer_margin: egui::Margin::ZERO,
            corner_radius: CornerRadius::ZERO,
            shadow: egui::epaint::Shadow::NONE,
            fill: p.card_secondary_bg,
            stroke: Stroke::new(1.0_f32, border_color),
        };

        egui::Panel::left("main_navigation_rail")
            .frame(rail_frame)
            .resizable(false)
            .exact_size(236.0)
            .show_separator_line(false)
            .show(ui, |ui| {
                ui.add_space(4.0);

                // App Brand
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("LanShare")
                            .size(20.0)
                            .strong()
                            .color(text_dark),
                    );
                    ui.label(
                        RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .size(11.5)
                            .color(text_muted),
                    );
                });

                // Status chip
                let (status_text, status_color) = if is_hosting {
                    ("● HOSTING ACTIVE", p.accent_green)
                } else {
                    ("● RING CONNECTED", p.accent_blue)
                };
                ui.label(
                    RichText::new(status_text)
                        .size(11.0)
                        .monospace()
                        .strong()
                        .color(status_color),
                );

                if self.test_mode {
                    ui.label(
                        RichText::new("[ TEST MODE ]")
                            .size(10.5)
                            .monospace()
                            .strong()
                            .color(p.accent_amber),
                    );
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(10.0);

                // Navigation Selection 1: Browse LAN
                let is_client = self.current_tab == AppTab::Client;
                let client_fill = if is_client {
                    p.tab_active_bg
                } else {
                    p.tab_inactive_bg
                };
                let client_stroke = if is_client {
                    Stroke::NONE
                } else {
                    Stroke::new(1.0_f32, border_color)
                };
                let client_text_color = if is_client {
                    p.tab_active_text
                } else {
                    p.tab_inactive_text
                };

                let client_btn = egui::Button::new(
                    RichText::new("Browse LAN")
                        .size(14.5)
                        .strong()
                        .color(client_text_color),
                )
                .fill(client_fill)
                .stroke(client_stroke)
                .corner_radius(CornerRadius::same(8))
                .min_size(Vec2::new(ui.available_width(), 42.0));

                if ui.add(client_btn).clicked() {
                    self.switch_tab(AppTab::Client);
                }

                ui.add_space(8.0);

                // Navigation Selection 2: Share Folders
                let is_host = self.current_tab == AppTab::Host;
                let host_fill = if is_host {
                    p.tab_active_bg
                } else {
                    p.tab_inactive_bg
                };
                let host_stroke = if is_host {
                    Stroke::NONE
                } else {
                    Stroke::new(1.0_f32, border_color)
                };
                let host_text_color = if is_host {
                    p.tab_active_text
                } else {
                    p.tab_inactive_text
                };
                let host_label = if is_hosting {
                    "Share Folders  ●"
                } else {
                    "Share Folders"
                };

                let host_btn = egui::Button::new(
                    RichText::new(host_label)
                        .size(14.5)
                        .strong()
                        .color(host_text_color),
                )
                .fill(host_fill)
                .stroke(host_stroke)
                .corner_radius(CornerRadius::same(8))
                .min_size(Vec2::new(ui.available_width(), 42.0));

                if ui.add(host_btn).clicked() {
                    self.switch_tab(AppTab::Host);
                }

                ui.add_space(8.0);

                // Navigation Selection 3: Activity Logs (below Share Folders)
                let total_logs = self.client_logs.len() + self.server_logs.len();
                let log_label = if total_logs > 0 {
                    format!("Logs ({})", total_logs)
                } else {
                    "Logs".to_string()
                };

                let btn_size = Vec2::new(ui.available_width(), 42.0);
                let (rect, resp) = ui.allocate_exact_size(btn_size, egui::Sense::click());

                if resp.clicked() {
                    self.clear_errors();
                    self.show_log_window = true;
                    self.focus_log_window = true;
                    let id = egui::ViewportId::from_hash_of("activity_logs_viewport");
                    ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd_to(id, egui::ViewportCommand::Focus);
                }

                let bg_color = if resp.is_pointer_button_down_on() {
                    p.card_secondary_bg
                } else if resp.hovered() {
                    p.card_bg
                } else {
                    p.btn_secondary_bg
                };
                let content_color = if resp.hovered() {
                    p.text_primary
                } else {
                    p.btn_secondary_text
                };

                ui.painter().rect(
                    rect,
                    CornerRadius::same(8),
                    bg_color,
                    Stroke::new(1.0_f32, border_color),
                    egui::StrokeKind::Inside,
                );

                // Left-aligned text matching Browse LAN and Share Folders buttons, with open-window icon next to text
                let text_galley = egui::WidgetText::from(
                    RichText::new(&log_label)
                        .size(14.5)
                        .strong()
                        .color(content_color),
                )
                .into_galley(ui, None, ui.available_width(), TextStyle::Button);

                let text_w = text_galley.size().x;
                let text_h = text_galley.size().y;
                let icon_size = 12.0;
                let gap = 8.0;
                let start_x = rect.min.x + ui.spacing().button_padding.x;

                let text_pos = egui::pos2(start_x, rect.center().y - (text_h / 2.0));
                ui.painter().galley(text_pos, text_galley, Color32::PLACEHOLDER);

                let icon_rect = egui::Rect::from_min_size(
                    egui::pos2(start_x + text_w + gap, rect.center().y - (icon_size / 2.0)),
                    egui::vec2(icon_size, icon_size),
                );
                Self::draw_mini_open_window_icon_in_rect(ui, icon_rect, content_color);

                // Bottom Telemetry & Secret Control Box
                let bottom_frame = egui::Frame {
                    inner_margin: egui::Margin::symmetric(10, 10),
                    outer_margin: egui::Margin::same(0),
                    corner_radius: CornerRadius::same(8),
                    shadow: egui::epaint::Shadow::NONE,
                    fill: p.card_bg,
                    stroke: Stroke::new(1.0_f32, border_color),
                };

                // Bottom section sized exactly to its content: Ring Secret card
                egui::Panel::bottom("left_rail_bottom_section")
                    .resizable(false)
                    .show_separator_line(false)
                    .frame(
                        egui::Frame::NONE.inner_margin(egui::Margin {
                            left: 2,
                            right: 2,
                            top: 6,
                            bottom: 2,
                        }),
                    )
                    .show(ui, |ui| {
                        // Ring Secret Frame
                        bottom_frame.show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 5.0;
                                    Self::draw_mini_lock_icon(ui, text_muted);
                                    ui.label(
                                        RichText::new("RING SECRET")
                                            .size(11.0)
                                            .strong()
                                            .monospace()
                                            .color(text_muted),
                                    );
                                });

                                ui.add_space(3.0);

                                let secret_display = format_secret_display(&self.ring_secret, self.show_secret_plain, 20);
                                let secret_label = egui::Label::new(
                                    RichText::new(&secret_display)
                                        .monospace()
                                        .size(13.0)
                                        .strong()
                                        .color(text_dark),
                                )
                                .wrap();
                                let secret_resp = ui.add(secret_label);
                                if !self.show_secret_plain {
                                    secret_resp.on_hover_text(
                                        "Hidden secret (click eye icon below to reveal)",
                                    );
                                }

                                ui.add_space(4.0);

                                ui.horizontal(|ui| {
                                    let gap = 6.0;
                                    ui.spacing_mut().item_spacing.x = gap;

                                    let is_plain = self.show_secret_plain;
                                    let eye_tooltip = if is_plain { "Hide secret" } else { "Show secret" };
                                    let eye_resp = Self::draw_icon_button(ui, eye_tooltip, |ui, rect, color| {
                                        Self::draw_mini_eye_icon_in_rect(ui, rect, color, is_plain);
                                    });
                                    if eye_resp.clicked() {
                                        self.clear_errors();
                                        self.show_secret_plain = !self.show_secret_plain;
                                    }

                                    let sec_clone = self.ring_secret.clone();
                                    let copy_resp = Self::draw_icon_button(ui, "Copy secret to clipboard", |ui, rect, color| {
                                        Self::draw_mini_copy_icon_in_rect(ui, rect, color);
                                    });
                                    if copy_resp.clicked() {
                                        self.clear_errors();
                                        self.copy_to_clipboard(&ctx, &sec_clone, "LAN Secret");
                                    }

                                    let is_downloading = self.has_active_client_downloads();
                                    let can_change_secret = !is_hosting && !is_downloading;

                                    ui.add_enabled_ui(can_change_secret, |ui| {
                                        let pencil_resp = Self::draw_icon_button(ui, "Change secret", |ui, rect, color| {
                                            Self::draw_mini_pencil_icon_in_rect(ui, rect, color);
                                        });
                                        if is_hosting && is_downloading {
                                            pencil_resp.on_hover_text("Stop sharing and wait for downloads to finish before changing secret");
                                        } else if is_hosting {
                                            pencil_resp.on_hover_text("Stop sharing before changing secret");
                                        } else if is_downloading {
                                            pencil_resp.on_hover_text("Wait for downloads to finish before changing secret");
                                        } else if pencil_resp.clicked() {
                                            self.clear_errors();
                                            self.disconnect_client_session();
                                            self.secret_confirmed = false;
                                        }
                                    });
                                });
                            }
                        });
                    });
            });
    }

    fn render_about_link(
        ui: &mut egui::Ui,
        p: &AppPalette,
        label: &str,
        url: &str,
    ) -> egui::Response {
        let link = egui::Label::new(RichText::new(label).size(12.5).color(p.accent_blue))
            .sense(egui::Sense::click());
        let (galley_pos, galley, resp) = link.layout_in_ui(ui);
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
        }
        if ui.is_rect_visible(resp.rect) {
            let underline = if resp.hovered() {
                Stroke::new(1.0_f32, p.accent_blue)
            } else {
                Stroke::NONE
            };
            ui.painter().add(
                egui::epaint::TextShape::new(galley_pos, galley, p.accent_blue)
                    .with_underline(underline),
            );
        }
        if resp.clicked() {
            let _ = open_url(url);
        }
        resp
    }

    fn render_about_modal(&mut self, ctx: &egui::Context) {
        if !self.show_about {
            return;
        }

        let should_focus = self.focus_about_window;
        self.focus_about_window = false;

        let mut close_requested = false;
        let mut builder = egui::ViewportBuilder::default()
            .with_title("About LanShare")
            .with_inner_size([540.0, 535.0])
            .with_min_inner_size([460.0, 360.0])
            .with_active(true)
            .with_resizable(true);

        if let Some(icon) = app_icon() {
            builder = builder.with_icon(icon);
        }

        let is_dark = self.effective_dark_mode(ctx);
        let p = self.palette(ctx);

        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("about_viewport"),
            builder,
            |ui, _class| {
                let ctx = ui.ctx().clone();
                if should_focus {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                if ctx.global_style().visuals.dark_mode != is_dark {
                    configure_readable_style(&ctx, is_dark);
                }
                if ctx.input(|i| i.viewport().close_requested()) {
                    close_requested = true;
                }

                let panel_bg = p.panel_bg;
                egui::CentralPanel::default()
                    .frame(egui::Frame::central_panel(&ctx.global_style()).fill(panel_bg))
                    .show(ui, |ui| {
                    ScrollArea::vertical()
                        .id_salt("about_scroll_area")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.add_space(8.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    RichText::new(format!("LanShare v{}", env!("CARGO_PKG_VERSION")))
                                        .strong()
                                        .size(20.0)
                                        .color(p.text_primary),
                                );
                                ui.add_space(2.0);
                                ui.label(
                                    RichText::new("Author: Jokke Heikkilä")
                                        .size(13.0)
                                        .color(p.text_muted),
                                );
                                ui.add_space(4.0);
                                Self::render_about_link(
                                    ui,
                                    &p,
                                    GITHUB_REPO_URL,
                                    GITHUB_REPO_URL,
                                );
                                ui.add_space(2.0);
                                Self::render_about_link(
                                    ui,
                                    &p,
                                    "Check for updates (GitHub Releases)",
                                    GITHUB_RELEASES_URL,
                                );
                            });

                            ui.add_space(12.0);
                            ui.separator();
                            ui.add_space(10.0);

                            ui.label("Encrypted peer-to-peer LAN folder sharing powered by Share-Ring.");
                            ui.add_space(6.0);
                            ui.label("1. Enter your Share-Ring Secret to discover computers or share folders.");
                            ui.add_space(3.0);
                            ui.label("2. In 'Browse LAN', click 'Scan' to list peers, or connect directly by IP.");
                            ui.add_space(3.0);
                            ui.label("3. In 'Share Folders', add folders and click 'Start Sharing' to share them read-only.");

                            ui.add_space(12.0);
                            ui.label(
                                RichText::new("Security Guarantees:")
                                    .strong()
                                    .color(p.accent_green),
                            );
                            ui.label("• Zero-Trust mutual TLS authentication (mTLS) with ephemeral in-memory certificates.");
                            ui.label("• 100% Read-Only: Guests cannot write, upload, modify, or delete any files.");
                            ui.label("• Zero Cloud: Direct peer-to-peer transfers over local Wi-Fi / Ethernet at max NIC speed.");

                            ui.add_space(16.0);
                            ui.vertical_centered(|ui| {
                                let close_btn = egui::Button::new(
                                    RichText::new("Close")
                                        .color(p.btn_primary_text)
                                        .strong(),
                                )
                                .fill(p.btn_primary_bg)
                                .min_size(Vec2::new(120.0, 34.0));
                                if ui.add(close_btn).clicked() {
                                    close_requested = true;
                                }
                            });
                            ui.add_space(8.0);
                        });
                });
            },
        );

        if close_requested {
            self.show_about = false;
        }
    }

    fn render_log_window(&mut self, ctx: &egui::Context) {
        if !self.show_log_window {
            return;
        }

        let should_focus = self.focus_log_window;
        self.focus_log_window = false;

        let mut close_requested = false;
        let mut clear_logs = false;

        let client_count = self.client_logs.len();
        let server_count = self.server_logs.len();
        let mut log_auto_scroll = self.log_auto_scroll;
        let mut log_source_filter = self.log_source_filter;
        let client_logs_clone = self.client_logs.clone();
        let server_logs_clone = self.server_logs.clone();

        let mut builder = egui::ViewportBuilder::default()
            .with_title("Activity & Transfer Logs")
            .with_inner_size([960.0, 520.0])
            .with_min_inner_size([900.0, 340.0])
            .with_active(true)
            .with_resizable(true);

        if let Some(icon) = app_icon() {
            builder = builder.with_icon(icon);
        }

        let is_dark = self.effective_dark_mode(ctx);
        let p = self.palette(ctx);

        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("activity_logs_viewport"),
            builder,
            |ui, _class| {
                let ctx = ui.ctx().clone();
                if should_focus {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                if ctx.global_style().visuals.dark_mode != is_dark {
                    configure_readable_style(&ctx, is_dark);
                }
                if ctx.input(|i| i.viewport().close_requested()) {
                    close_requested = true;
                }

                let panel_bg = p.panel_bg;
                egui::CentralPanel::default()
                    .frame(egui::Frame::central_panel(&ctx.global_style()).fill(panel_bg))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Right side controls rendered right-to-left first so they occupy their needed space on the right
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .button("Clear")
                                        .on_hover_text(
                                            "Clear window display (log file on disk is preserved)",
                                        )
                                        .clicked()
                                    {
                                        clear_logs = true;
                                    }

                                    ui.checkbox(&mut log_auto_scroll, "Auto-scroll");

                                    // Left side controls in remaining horizontal space (will never overlap right side)
                                    ui.with_layout(
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                RichText::new("Filter:")
                                                    .size(13.0)
                                                    .strong()
                                                    .color(p.text_muted),
                                            );
                                            ui.selectable_value(
                                                &mut log_source_filter,
                                                LogSourceFilter::All,
                                                format!("All ({})", client_count + server_count),
                                            );
                                            ui.selectable_value(
                                                &mut log_source_filter,
                                                LogSourceFilter::Client,
                                                format!("Client ({})", client_count),
                                            );
                                            ui.selectable_value(
                                                &mut log_source_filter,
                                                LogSourceFilter::Server,
                                                format!("Server ({})", server_count),
                                            );

                                            ui.add_space(8.0);

                                            let log_path = crate::core::get_log_file_path();
                                            let log_file_name = log_path
                                                .file_name()
                                                .map(|s| s.to_string_lossy().to_string())
                                                .unwrap_or_else(|| "lanshare.log".to_string());

                                            let spool_spacing_x = 6.0_f32;
                                            let prompt_galley = egui::WidgetText::from(
                                                RichText::new("Spooling to:")
                                                    .size(13.5)
                                                    .color(p.text_muted),
                                            )
                                            .into_galley(
                                                ui,
                                                Some(egui::TextWrapMode::Extend),
                                                f32::INFINITY,
                                                egui::TextStyle::Body,
                                            );
                                            let max_link_w = (ui.available_width()
                                                - prompt_galley.size().x
                                                - spool_spacing_x)
                                                .max(40.0);
                                            let link_galley = egui::WidgetText::from(
                                                RichText::new(&log_file_name)
                                                    .size(13.5)
                                                    .strong()
                                                    .color(p.accent_blue),
                                            )
                                            .into_galley(
                                                ui,
                                                Some(egui::TextWrapMode::Truncate),
                                                max_link_w,
                                                egui::TextStyle::Body,
                                            );

                                            let row_height =
                                                prompt_galley.size().y.max(link_galley.size().y);
                                            let link_size = link_galley.size();
                                            let total_w = prompt_galley.size().x
                                                + spool_spacing_x
                                                + link_size.x;
                                            let (_row_id, row_rect) =
                                                ui.allocate_space(egui::vec2(total_w, row_height));

                                            let (prompt_pos, link_pos, _) =
                                                Self::compute_download_header_layout(
                                                    row_rect,
                                                    &prompt_galley,
                                                    &link_galley,
                                                    spool_spacing_x,
                                                    Vec2::ZERO,
                                                );
                                            let link_rect =
                                                egui::Rect::from_min_size(link_pos, link_size);
                                            let resp = ui.interact(
                                                link_rect,
                                                ui.make_persistent_id("activity_log_spool_link"),
                                                egui::Sense::click(),
                                            );
                                            if resp.hovered() {
                                                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                                            }
                                            if ui.is_rect_visible(row_rect) {
                                                ui.painter().galley(
                                                    prompt_pos,
                                                    prompt_galley,
                                                    p.text_muted,
                                                );
                                                let underline = if resp.hovered() {
                                                    Stroke::new(1.0_f32, p.accent_blue)
                                                } else {
                                                    Stroke::NONE
                                                };
                                                ui.painter().add(
                                                    egui::epaint::TextShape::new(
                                                        link_pos,
                                                        link_galley,
                                                        p.accent_blue,
                                                    )
                                                    .with_underline(underline),
                                                );
                                            }
                                            // Open log file directly on click (no hover tooltip)
                                            if resp.clicked() {
                                                let _ = open_file_in_default_app(&log_path);
                                            }
                                        },
                                    );
                                },
                            );
                        });

                        let show_client = matches!(
                            log_source_filter,
                            LogSourceFilter::All | LogSourceFilter::Client
                        );
                        let show_server = matches!(
                            log_source_filter,
                            LogSourceFilter::All | LogSourceFilter::Server
                        );
                        let has_entries = (show_client && !client_logs_clone.is_empty())
                            || (show_server && !server_logs_clone.is_empty());
                        let log_scroll_visibility = if has_entries {
                            egui::scroll_area::ScrollBarVisibility::AlwaysVisible
                        } else {
                            egui::scroll_area::ScrollBarVisibility::AlwaysHidden
                        };

                        ui.separator();
                        ui.spacing_mut().scroll = Self::visible_scroll_style();

                        ScrollArea::vertical()
                            .id_salt("dedicated_activity_log_scroll")
                            .stick_to_bottom(log_auto_scroll)
                            .auto_shrink([false, false])
                            .scroll_bar_visibility(log_scroll_visibility)
                            .show(ui, |ui| {
                                if !has_entries {
                                    ui.vertical_centered(|ui| {
                                        ui.add_space(40.0);
                                        let msg = match log_source_filter {
                                            LogSourceFilter::All => "No activity logged yet.",
                                            LogSourceFilter::Client => {
                                                "No client activity logged yet."
                                            }
                                            LogSourceFilter::Server => {
                                                "No server activity logged yet."
                                            }
                                        };
                                        ui.label(RichText::new(msg).color(p.text_muted));
                                    });
                                } else {
                                    if show_client {
                                        for log in &client_logs_clone {
                                            let color = if log.contains("Skipped") {
                                                p.accent_amber
                                            } else if log.contains("Downloaded")
                                                || log.contains("Finished")
                                            {
                                                p.accent_green
                                            } else if log.contains("interrupted")
                                                || log.contains("dropped")
                                                || log.contains("lost")
                                                || log.contains("failed")
                                            {
                                                p.accent_red
                                            } else if p.is_dark {
                                                p.text_primary
                                            } else {
                                                Color32::from_rgb(51, 65, 85)
                                            };
                                            ui.label(
                                                RichText::new(format!("[Client] {}", log))
                                                    .font(FontId::monospace(12.5))
                                                    .color(color),
                                            );
                                        }
                                    }

                                    if show_server {
                                        for log in &server_logs_clone {
                                            let color = if log.is_error {
                                                p.accent_red
                                            } else {
                                                p.accent_blue
                                            };
                                            ui.label(
                                                RichText::new(format!(
                                                    "[Server] [{}] {}",
                                                    log.timestamp, log.message
                                                ))
                                                .font(FontId::monospace(12.5))
                                                .color(color),
                                            );
                                        }
                                    }
                                }
                            });
                    });
            },
        );

        self.log_auto_scroll = log_auto_scroll;
        self.log_source_filter = log_source_filter;

        if clear_logs {
            self.client_logs.clear();
            self.server_logs.clear();
        }

        if close_requested {
            self.show_log_window = false;
        }
    }

    fn render_close_confirm_modal(&mut self, ctx: &egui::Context) {
        if !self.show_close_confirm_dialog {
            return;
        }

        let p = self.palette(ctx);
        let screen_rect = ctx.content_rect();
        let active_server_dl = self.active_server_downloads();
        let is_hosting = self.is_hosting_active();
        let active_client_dl = self.has_active_client_downloads();

        // 1. Semi-transparent backdrop overlay to dim background and capture outside clicks
        let backdrop_area = egui::Area::new(egui::Id::unique("close_confirm_backdrop"))
            .order(egui::Order::Middle)
            .fixed_pos(screen_rect.min)
            .interactable(true)
            .show(ctx, |ui| {
                let (rect, resp) = ui.allocate_exact_size(screen_rect.size(), egui::Sense::click());
                ui.painter()
                    .rect_filled(rect, 0.0, Color32::from_black_alpha(160));
                resp
            });

        let mut stay_open = true;
        let mut confirmed_exit = false;

        if backdrop_area.inner.clicked() {
            stay_open = false;
        }

        // 2. Centered modal dialog window
        let border_stroke = if active_server_dl > 0 {
            Stroke::new(2.0_f32, p.accent_red)
        } else {
            Stroke::new(1.0_f32, p.border)
        };

        let card_frame = egui::Frame {
            inner_margin: egui::Margin::symmetric(24, 20),
            outer_margin: egui::Margin::ZERO,
            corner_radius: CornerRadius::same(12),
            shadow: egui::epaint::Shadow::NONE,
            fill: p.card_bg,
            stroke: border_stroke,
        };

        egui::Window::new("close_confirm_modal")
            .id(egui::Id::unique("close_confirm_modal_window"))
            .order(egui::Order::Foreground)
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .fixed_size(egui::vec2(440.0, 0.0))
            .frame(card_frame)
            .show(ctx, |ui| {
                ui.set_width(440.0);

                // Title row
                ui.horizontal(|ui| {
                    if active_server_dl > 0 {
                        ui.label(
                            RichText::new("Active Peer Download")
                                .size(17.0)
                                .strong()
                                .color(p.accent_red),
                        );
                    } else if active_client_dl && !is_hosting {
                        ui.label(
                            RichText::new("Active Downloads in Progress")
                                .size(17.0)
                                .strong()
                                .color(p.accent_amber),
                        );
                    } else if active_client_dl && is_hosting {
                        ui.label(
                            RichText::new("Stop Sharing & Downloads?")
                                .size(17.0)
                                .strong()
                                .color(p.accent_amber),
                        );
                    } else {
                        ui.label(
                            RichText::new("Stop Sharing & Exit?")
                                .size(17.0)
                                .strong()
                                .color(p.accent_amber),
                        );
                    }
                });

                ui.add_space(10.0);

                if active_server_dl > 0 {
                    // High-visibility RED warning banner
                    let alert_bg = if p.is_dark {
                        Color32::from_rgba_premultiplied(90, 15, 15, 200)
                    } else {
                        Color32::from_rgb(254, 242, 242)
                    };
                    let alert_frame = egui::Frame {
                        inner_margin: egui::Margin::symmetric(14, 12),
                        outer_margin: egui::Margin::ZERO,
                        corner_radius: CornerRadius::same(8),
                        shadow: egui::epaint::Shadow::NONE,
                        fill: alert_bg,
                        stroke: Stroke::new(1.5_f32, p.accent_red),
                    };

                    alert_frame.show(ui, |ui| {
                        ui.label(
                            RichText::new(format!(
                                "ALERT: Someone is currently downloading from you!\n({} active transfer{} in progress)",
                                active_server_dl,
                                if active_server_dl == 1 { "" } else { "s" }
                            ))
                            .size(13.5)
                            .strong()
                            .color(p.accent_red),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new("If you close LanShare now, their file download will be immediately aborted and left incomplete on their device.")
                                .size(12.5)
                                .color(p.text_primary),
                        );
                    });

                    if active_client_dl {
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("• You also have downloads in progress from peers that will be stopped.")
                                .size(12.0)
                                .color(p.accent_amber),
                        );
                    }
                } else {
                    // Standard AMBER warning banner
                    let alert_bg = if p.is_dark {
                        Color32::from_rgba_premultiplied(75, 45, 10, 180)
                    } else {
                        Color32::from_rgb(254, 252, 232)
                    };
                    let alert_frame = egui::Frame {
                        inner_margin: egui::Margin::symmetric(14, 12),
                        outer_margin: egui::Margin::ZERO,
                        corner_radius: CornerRadius::same(8),
                        shadow: egui::epaint::Shadow::NONE,
                        fill: alert_bg,
                        stroke: Stroke::new(1.0_f32, p.accent_amber),
                    };

                    if active_client_dl && !is_hosting {
                        alert_frame.show(ui, |ui| {
                            ui.label(
                                RichText::new("File downloads are currently in progress from peers.")
                                    .size(13.0)
                                    .strong()
                                    .color(p.accent_amber),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new("If you close LanShare now, your active file transfers will be cancelled and incomplete.")
                                    .size(12.0)
                                    .color(p.text_primary),
                            );
                        });
                    } else if active_client_dl && is_hosting {
                        alert_frame.show(ui, |ui| {
                            ui.label(
                                RichText::new("Folder sharing and downloads are currently active.")
                                    .size(13.0)
                                    .strong()
                                    .color(p.accent_amber),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new("Closing LanShare will shut down your shared folders (remote peers can no longer access them) and abort all in-progress downloads.")
                                    .size(12.0)
                                    .color(p.text_primary),
                            );
                        });
                    } else if is_hosting {
                        alert_frame.show(ui, |ui| {
                            ui.label(
                                RichText::new("Folder sharing is currently active on your local network.")
                                    .size(13.0)
                                    .strong()
                                    .color(p.accent_amber),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new("Closing LanShare will shut down the server and other computers on your LAN will no longer be able to browse or download your shared folders.")
                                    .size(12.0)
                                    .color(p.text_primary),
                            );
                        });
                    }
                }

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(12.0);

                // Action buttons
                ui.horizontal(|ui| {
                    let cancel_btn = egui::Button::new(
                        RichText::new("Cancel (Keep Running)")
                            .size(13.5)
                            .color(p.btn_secondary_text),
                    )
                    .fill(p.btn_secondary_bg)
                    .min_size(Vec2::new(175.0, 34.0));

                    if ui.add(cancel_btn).clicked() {
                        stay_open = false;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let btn_text = if active_server_dl > 0 {
                            "Abort Transfer & Exit"
                        } else if active_client_dl && !is_hosting {
                            "Abort Downloads & Exit"
                        } else if active_client_dl && is_hosting {
                            "Stop All & Exit"
                        } else {
                            "Stop Sharing & Exit"
                        };
                        let exit_btn = egui::Button::new(
                            RichText::new(btn_text)
                                .size(13.5)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(p.accent_red)
                        .min_size(Vec2::new(185.0, 34.0));

                        if ui.add(exit_btn).clicked() {
                            confirmed_exit = true;
                        }
                    });
                });

                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    stay_open = false;
                }
            });

        if !stay_open {
            self.show_close_confirm_dialog = false;
        }

        if confirmed_exit {
            self.close_confirmed = true;
            self.show_close_confirm_dialog = false;
            if let Some(handle) = self.server_handle.take() {
                let _ = handle.stop_sender.send(());
            }
            if let Some(cancel_tx) = self.transfer_cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn start_hosting_server(&mut self) {
        self.clear_errors();
        if self.server_handle.is_some()
            || self.host_folders.is_empty()
            || self.ring_secret.trim().len() < MIN_SECRET_LEN
        {
            return;
        }
        let folders_clone = self.host_folders.clone();
        let pwd = self.ring_secret.trim().to_string();
        let log_tx = self.server_log_tx.clone();

        match self
            .tokio_rt
            .block_on(server::start_server(folders_clone, pwd, None, log_tx))
        {
            Ok(handle) => {
                if self.test_mode {
                    crate::core::spawn_mock_server_downloads(&self.tokio_rt, &handle);
                }
                let my_ip = handle.local_ip.clone();
                let my_port = handle.port;
                self.server_handle = Some(handle);
                self.host_error = None;
                let my_name = crate::network::get_computer_name();
                if !self.discovered_peers.iter().any(|p| self.is_local_peer(p)) {
                    self.discovered_peers.push(DiscoveredPeer {
                        host_name: my_name,
                        ip: my_ip,
                        port: my_port,
                        last_seen: Instant::now(),
                    });
                    sort_peers_alphabetically(&mut self.discovered_peers);
                }
            }
            Err(e) => {
                self.host_error = Some(format!("Failed to start server: {}", e));
            }
        }
    }

    fn remove_host_folder(&mut self, idx: usize) {
        self.clear_errors();
        if idx >= self.host_folders.len() {
            return;
        }
        let is_last = self.host_folders.len() <= 1;
        let is_running = self
            .server_handle
            .as_ref()
            .map(|h| h.is_running.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false);
        let active_for_folder = self
            .server_handle
            .as_ref()
            .map(|h| h.active_downloads_for_folder(&self.host_folders[idx]))
            .unwrap_or(0);

        if is_last && self.server_handle.is_some() {
            if is_running && (self.active_server_downloads() > 0 || active_for_folder > 0) {
                self.pending_remove_host_folder_idx = Some(idx);
                self.show_stop_server_confirm_dialog = true;
            } else {
                self.host_folders.remove(idx);
                self.host_error = None;
                self.stop_hosting_server();
            }
            return;
        }

        if is_running && active_for_folder > 0 {
            self.pending_remove_host_folder_idx = Some(idx);
            self.show_stop_server_confirm_dialog = true;
            return;
        }

        self.host_folders.remove(idx);
        self.host_error = None;
        if let Some(ref handle) = self.server_handle {
            if let Err(e) = handle.update_shared_folders(self.host_folders.clone()) {
                self.host_error = Some(e);
            }
        }
    }

    fn stop_hosting_server(&mut self) {
        self.clear_errors();
        let local_ips = self.local_ips.clone();
        let s_ip = self.server_handle.as_ref().map(|h| h.local_ip.clone());
        if let Some(handle) = self.server_handle.take() {
            let _ = handle.stop_sender.send(());
        }
        self.discovered_peers.retain(|p| {
            !local_ips.contains(&p.ip) && s_ip.as_deref() != Some(&p.ip) && p.ip != "127.0.0.1"
        });
    }

    fn render_stop_server_confirm_modal(&mut self, ctx: &egui::Context) {
        if !self.show_stop_server_confirm_dialog {
            return;
        }

        let p = self.palette(ctx);
        let screen_rect = ctx.content_rect();
        let active_server_dl = self.active_server_downloads();

        // 1. Semi-transparent backdrop overlay to dim background and capture outside clicks
        let backdrop_area = egui::Area::new(egui::Id::unique("stop_server_confirm_backdrop"))
            .order(egui::Order::Middle)
            .fixed_pos(screen_rect.min)
            .interactable(true)
            .show(ctx, |ui| {
                let (rect, resp) = ui.allocate_exact_size(screen_rect.size(), egui::Sense::click());
                ui.painter()
                    .rect_filled(rect, 0.0, Color32::from_black_alpha(160));
                resp
            });

        let mut stay_open = true;
        let mut confirmed_stop = false;

        if backdrop_area.inner.clicked() {
            stay_open = false;
        }

        // 2. Centered modal dialog window
        let card_frame = egui::Frame {
            inner_margin: egui::Margin::symmetric(24, 20),
            outer_margin: egui::Margin::ZERO,
            corner_radius: CornerRadius::same(12),
            shadow: egui::epaint::Shadow::NONE,
            fill: p.card_bg,
            stroke: Stroke::new(2.0_f32, p.accent_red),
        };

        egui::Window::new("stop_server_confirm_modal")
            .id(egui::Id::unique("stop_server_confirm_modal_window"))
            .order(egui::Order::Foreground)
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .fixed_size(egui::vec2(440.0, 0.0))
            .frame(card_frame)
            .show(ctx, |ui| {
                ui.set_width(440.0);

                // Title row
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Active Peer Download")
                            .size(17.0)
                            .strong()
                            .color(p.accent_red),
                    );
                });

                ui.add_space(10.0);

                // High-visibility RED warning banner
                let alert_bg = if p.is_dark {
                    Color32::from_rgba_premultiplied(90, 15, 15, 200)
                } else {
                    Color32::from_rgb(254, 242, 242)
                };
                let alert_frame = egui::Frame {
                    inner_margin: egui::Margin::symmetric(14, 12),
                    outer_margin: egui::Margin::ZERO,
                    corner_radius: CornerRadius::same(8),
                    shadow: egui::epaint::Shadow::NONE,
                    fill: alert_bg,
                    stroke: Stroke::new(1.5_f32, p.accent_red),
                };

                let pending_remove_folder = self
                    .pending_remove_host_folder_idx
                    .and_then(|idx| self.host_folders.get(idx))
                    .map(|p| clean_display_path(p));
                let removes_non_last_folder =
                    pending_remove_folder.is_some() && self.host_folders.len() > 1;
                let folder_active_dl = self
                    .pending_remove_host_folder_idx
                    .and_then(|idx| {
                        let folder = self.host_folders.get(idx)?;
                        self.server_handle
                            .as_ref()
                            .map(|h| h.active_downloads_for_folder(folder))
                    })
                    .unwrap_or(active_server_dl);

                alert_frame.show(ui, |ui| {
                    let (alert_title, alert_detail) = if let Some(ref folder_name) = pending_remove_folder {
                        if removes_non_last_folder {
                            (
                                format!(
                                    "ALERT: Someone is currently downloading from:\n{}\n({} active transfer{} in progress from this folder)",
                                    folder_name,
                                    folder_active_dl,
                                    if folder_active_dl == 1 { "" } else { "s" }
                                ),
                                "If you remove this folder from shares now, their file download will be immediately aborted and left incomplete on their device.",
                            )
                        } else {
                            (
                                format!(
                                    "ALERT: Someone is currently downloading from you!\n({} active transfer{} in progress)",
                                    active_server_dl,
                                    if active_server_dl == 1 { "" } else { "s" }
                                ),
                                "Removing the last shared folder will stop sharing and immediately abort their file download.",
                            )
                        }
                    } else {
                        (
                            format!(
                                "ALERT: Someone is currently downloading from you!\n({} active transfer{} in progress)",
                                active_server_dl,
                                if active_server_dl == 1 { "" } else { "s" }
                            ),
                            "If you stop sharing now, their file download will be immediately aborted and left incomplete on their device.",
                        )
                    };
                    ui.label(
                        RichText::new(alert_title)
                            .size(13.5)
                            .strong()
                            .color(p.accent_red),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(alert_detail)
                            .size(12.5)
                            .color(p.text_primary),
                    );
                });

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(12.0);

                // Action buttons
                ui.horizontal(|ui| {
                    let cancel_label = if removes_non_last_folder {
                        "Cancel (Keep Folder)"
                    } else {
                        "Cancel (Keep Sharing)"
                    };
                    let cancel_btn = egui::Button::new(
                        RichText::new(cancel_label)
                            .size(13.5)
                            .color(p.btn_secondary_text),
                    )
                    .fill(p.btn_secondary_bg)
                    .min_size(Vec2::new(175.0, 34.0));

                    if ui.add(cancel_btn).clicked() {
                        stay_open = false;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let confirm_label = if removes_non_last_folder {
                            "Abort Transfer & Remove"
                        } else {
                            "Abort Transfer & Stop"
                        };
                        let abort_btn = egui::Button::new(
                            RichText::new(confirm_label)
                                .size(13.5)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(p.accent_red)
                        .min_size(Vec2::new(185.0, 34.0));

                        if ui.add(abort_btn).clicked() {
                            confirmed_stop = true;
                        }
                    });
                });

                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    stay_open = false;
                }
            });

        if !stay_open {
            self.show_stop_server_confirm_dialog = false;
            self.pending_remove_host_folder_idx = None;
        }

        if confirmed_stop {
            self.show_stop_server_confirm_dialog = false;
            if let Some(idx) = self.pending_remove_host_folder_idx.take() {
                if idx < self.host_folders.len() {
                    self.host_folders.remove(idx);
                }
                self.host_error = None;
                if self.host_folders.is_empty() {
                    self.stop_hosting_server();
                } else if let Some(ref handle) = self.server_handle {
                    if let Err(e) = handle.update_shared_folders(self.host_folders.clone()) {
                        self.host_error = Some(e);
                    }
                }
            } else {
                self.stop_hosting_server();
            }
        }
    }

    fn render_client_view(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let p = self.palette(&ctx);
        let border_color = p.border;
        let text_dark = p.text_primary;
        let text_muted = p.text_muted;

        // Left Panel: Vertical List of Computers on LAN + Direct IP Connect
        let client_panel_frame = egui::Frame {
            inner_margin: egui::Margin::symmetric(10, 12),
            outer_margin: egui::Margin::ZERO,
            corner_radius: CornerRadius::ZERO,
            shadow: egui::epaint::Shadow::NONE,
            fill: p.panel_bg,
            stroke: Stroke::new(1.0_f32, border_color),
        };

        egui::Panel::left("computers_on_lan_panel")
            .frame(client_panel_frame)
            .resizable(true)
            .default_size(290.0)
            .size_range(250.0..=380.0)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Computers on LAN")
                            .size(14.0)
                            .strong()
                            .color(text_dark),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let can_scan =
                            !self.is_scanning && self.ring_secret.trim().len() >= MIN_SECRET_LEN;
                        ui.add_enabled_ui(can_scan, |ui| {
                            if ui.button("Scan").clicked() {
                                self.trigger_ring_scan();
                            }
                        });
                    });
                });

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                // Direct IP Connect: bottom section sized exactly to its content
                egui::Panel::bottom("direct_ip_bottom_section")
                    .resizable(false)
                    .show_separator_line(false)
                    .frame(egui::Frame::NONE.inner_margin(egui::Margin::symmetric(2, 0)))
                    .show(ui, |ui| {
                        ui.add_space(2.0);
                        ui.separator();
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Direct IP Connect")
                                    .size(13.0)
                                    .strong()
                                    .color(text_dark),
                            );

                            let tip_btn = egui::Button::new(
                                RichText::new("?")
                                    .size(11.0)
                                    .strong()
                                    .color(text_muted),
                            )
                            .min_size(Vec2::new(16.0, 16.0))
                            .corner_radius(CornerRadius::same(8))
                            .fill(p.card_bg)
                            .stroke(Stroke::new(1.0_f32, border_color));

                            let tip_resp = ui.add(tip_btn);
                            if tip_resp.hovered() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                            }
                            egui::Popup::from_toggle_button_response(&tip_resp)
                                .align(egui::RectAlign::TOP_START)
                                .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                                .width(440.0)
                                .show(|ui| {
                                    ui.label(
                                        RichText::new("When to use Direct IP Connect:")
                                            .strong()
                                            .color(text_dark),
                                    );
                                    ui.add_space(2.0);
                                    ui.label(
                                        RichText::new(
                                            "• UDP Broadcast Blocked: On some Wi-Fi routers, guest networks, or firewalls, UDP broadcast (port 22223) is blocked, preventing computers from appearing automatically in the scan list.\n\
                                             • Tailscale / VPN: Connecting computers over Tailscale, WireGuard, ZeroTier, or other mesh VPNs where broadcast packets are not bridged.\n\
                                             • Different Subnets: When computers are on separate subnets or VLANs.",
                                        )
                                        .size(12.0)
                                        .color(text_dark),
                                    );
                                    ui.add_space(6.0);
                                    ui.label(
                                        RichText::new("Which IP address to enter:")
                                            .strong()
                                            .color(text_dark),
                                    );
                                    ui.add_space(2.0);
                                    ui.label(
                                        RichText::new(
                                            "• Local LAN: Enter the host's private IP (e.g. 192.168.1.50 or 10.0.0.5).\n\
                                             • Tailscale / VPN: Enter the host's Tailscale IP (e.g. 100.x.y.z).\n\
                                             • Note: Both computers must use the same Share-Ring secret.",
                                        )
                                        .size(12.0)
                                        .color(text_muted),
                                    );
                                });
                        });
                        ui.horizontal(|ui| {
                            let field_height = 28.0;
                            let input_w = (ui.available_width() - 84.0).clamp(142.0, 260.0);
                            let resp = ui.add_sized(
                                [input_w, field_height],
                                egui::TextEdit::singleline(&mut self.direct_ip_input)
                                    .font(FontId::monospace(13.0))
                                    .margin(egui::Margin::symmetric(6, 5)),
                            );
                            if resp.changed() {
                                self.clear_errors();
                            }
                            let enter_pressed =
                                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                            let connect_btn = egui::Button::new(RichText::new("Connect").size(13.0))
                                .min_size(Vec2::new(0.0, field_height));

                            if (ui.add(connect_btn).clicked() || enter_pressed)
                                && !self.direct_ip_input.trim().is_empty()
                            {
                                self.client_ip = self.direct_ip_input.trim().to_string();
                                self.client_port = DEFAULT_TCP_PORT;
                                self.connected_via_direct_ip = true;
                                self.trigger_connect();
                            }
                        });
                        ui.add_space(10.0);
                    });

                // Vertical list of discovered computers fills remaining space above
                        ScrollArea::vertical()
                            .id_salt("lan_computers_vertical_list")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                if self.discovered_peers.is_empty() {
                                    ui.add_space(24.0);
                                    ui.vertical_centered(|ui| {
                                        if self.is_scanning {
                                            ui.spinner();
                                            ui.add_space(6.0);
                                            ui.label(
                                                RichText::new("Scanning LAN for peers...")
                                                    .size(12.5)
                                                    .color(text_muted),
                                            );
                                        } else {
                                            ui.label(
                                                RichText::new("No computers detected.\nClick 'Scan LAN' to discover.")
                                                    .size(12.5)
                                                    .color(text_muted),
                                            );
                                        }
                                    });
                                } else {
                                    let mut peers = self.discovered_peers.clone();
                                    sort_peers_alphabetically(&mut peers);
                                    for peer in peers {
                                        let is_selected = self.client_connected
                                            && !self.client_connection_lost
                                            && self.client_ip == peer.ip;
                                        let is_local = self.is_local_peer(&peer);

                                        let title = if is_local {
                                            format!("{} (This PC)", peer.host_name)
                                        } else {
                                            peer.host_name.clone()
                                        };
                                        let subtitle = if peer.ip.starts_with("mock://") {
                                            "Simulated Host".to_string()
                                        } else {
                                            peer.ip.clone()
                                        };

                                        let row_w = ui.available_width().max(120.0);
                                        let (card_rect, resp) = ui.allocate_exact_size(
                                            Vec2::new(row_w, 48.0),
                                            egui::Sense::click(),
                                        );
                                        if resp.hovered() {
                                            ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                                        }

                                        let (fill, stroke) = if is_selected {
                                            (p.tab_active_bg, Stroke::NONE)
                                        } else if resp.hovered() || resp.is_pointer_button_down_on()
                                        {
                                            let visuals = ui.style().interact(&resp);
                                            (visuals.bg_fill, visuals.bg_stroke)
                                        } else {
                                            (p.card_bg, Stroke::new(1.0_f32, border_color))
                                        };

                                        let title_color = if is_selected {
                                            p.tab_active_text
                                        } else {
                                            text_dark
                                        };
                                        let subtitle_color = if is_selected {
                                            p.tab_active_text.gamma_multiply(0.85)
                                        } else {
                                            text_muted
                                        };
                                        let icon_color = if is_selected {
                                            p.tab_active_text
                                        } else {
                                            text_dark
                                        };

                                        if ui.is_rect_visible(card_rect) {
                                            ui.painter().rect(
                                                card_rect,
                                                CornerRadius::same(8),
                                                fill,
                                                stroke,
                                                egui::StrokeKind::Inside,
                                            );

                                            let icon_rect = egui::Rect::from_center_size(
                                                egui::pos2(
                                                    card_rect.left() + 20.0,
                                                    card_rect.center().y,
                                                ),
                                                egui::vec2(20.0, 18.0),
                                            );
                                            Self::draw_mini_computer_icon_in_rect(
                                                ui, icon_rect, icon_color,
                                            );

                                            let text_left = icon_rect.right() + 10.0;
                                            let max_text_w =
                                                (card_rect.right() - 10.0 - text_left).max(40.0);
                                            let title_galley = egui::WidgetText::from(
                                                RichText::new(&title)
                                                    .size(13.5)
                                                    .strong()
                                                    .color(title_color),
                                            )
                                            .into_galley(
                                                ui,
                                                Some(egui::TextWrapMode::Truncate),
                                                max_text_w,
                                                egui::TextStyle::Body,
                                            );
                                            let subtitle_galley = egui::WidgetText::from(
                                                RichText::new(&subtitle)
                                                    .size(12.0)
                                                    .color(subtitle_color),
                                            )
                                            .into_galley(
                                                ui,
                                                Some(egui::TextWrapMode::Truncate),
                                                max_text_w,
                                                egui::TextStyle::Body,
                                            );

                                            let title_h = title_galley.size().y;
                                            let total_h =
                                                title_h + 2.0 + subtitle_galley.size().y;
                                            let top_y = card_rect.center().y - total_h * 0.5;
                                            ui.painter().galley(
                                                egui::pos2(text_left, top_y),
                                                title_galley,
                                                title_color,
                                            );
                                            ui.painter().galley(
                                                egui::pos2(text_left, top_y + title_h + 2.0),
                                                subtitle_galley,
                                                subtitle_color,
                                            );
                                        }

                                        if resp.clicked() {
                                            self.select_and_connect_peer(&peer);
                                        }
                                        ui.add_space(4.0);
                                    }
                                }
                            });
            });

        // Main Area: File Browser, Queue, and Activity Log
        let central_frame = egui::Frame {
            inner_margin: egui::Margin::same(12),
            outer_margin: egui::Margin::ZERO,
            corner_radius: CornerRadius::ZERO,
            shadow: egui::epaint::Shadow::NONE,
            fill: p.panel_bg,
            stroke: Stroke::NONE,
        };
        egui::CentralPanel::default()
            .frame(central_frame)
            .show(ui, |ui| {
                self.render_client_browser_panel(ui);
            });
    }

    fn draw_mini_folder_icon(ui: &mut egui::Ui, color: Color32) -> egui::Response {
        let size = egui::vec2(15.0, 12.0);
        let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
        }
        if ui.is_rect_visible(rect) {
            let painter = ui.painter();
            let stroke = Stroke::new(1.2_f32, color);
            let tab_w = 6.0;
            let tab_h = 3.0;

            // Folder back tab
            painter.rect(
                egui::Rect::from_min_max(
                    rect.min,
                    egui::pos2(rect.min.x + tab_w, rect.min.y + tab_h + 1.0),
                ),
                CornerRadius {
                    nw: 2,
                    ne: 2,
                    sw: 0,
                    se: 0,
                },
                color.gamma_multiply(0.25),
                stroke,
                egui::StrokeKind::Inside,
            );

            // Folder front body
            painter.rect(
                egui::Rect::from_min_max(egui::pos2(rect.min.x, rect.min.y + tab_h), rect.max),
                CornerRadius {
                    nw: 0,
                    ne: 2,
                    sw: 2,
                    se: 2,
                },
                color.gamma_multiply(0.15),
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        resp
    }

    fn draw_mini_lock_icon(ui: &mut egui::Ui, color: Color32) {
        let size = egui::vec2(12.0, 13.0);
        let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        if ui.is_rect_visible(rect) {
            let painter = ui.painter();
            let stroke = Stroke::new(1.2_f32, color);
            let cx = rect.center().x;
            // Lock body (bottom)
            let body_rect = egui::Rect::from_min_max(
                egui::pos2(rect.min.x + 1.0, rect.min.y + 5.0),
                egui::pos2(rect.max.x - 1.0, rect.max.y),
            );
            painter.rect(
                body_rect,
                CornerRadius::same(2),
                Color32::TRANSPARENT,
                stroke,
                egui::StrokeKind::Inside,
            );
            // Shackle (arch on top)
            let shackle_pts = vec![
                egui::pos2(cx - 3.0, rect.min.y + 5.0),
                egui::pos2(cx - 3.0, rect.min.y + 2.0),
                egui::pos2(cx - 1.5, rect.min.y + 0.8),
                egui::pos2(cx + 1.5, rect.min.y + 0.8),
                egui::pos2(cx + 3.0, rect.min.y + 2.0),
                egui::pos2(cx + 3.0, rect.min.y + 5.0),
            ];
            painter.add(egui::epaint::PathShape::line(shackle_pts, stroke));
            // Small keyhole dot
            painter.circle_filled(egui::pos2(cx, rect.min.y + 8.5), 1.0, color);
        }
    }

    fn draw_mini_eye_icon_in_rect(ui: &egui::Ui, rect: egui::Rect, color: Color32, is_plain: bool) {
        let painter = ui.painter();
        let stroke = Stroke::new(1.45_f32, color);
        let c = rect.center();
        // Upper eyelid arc
        let upper = vec![
            egui::pos2(c.x - 8.5, c.y),
            egui::pos2(c.x - 4.0, c.y - 4.5),
            egui::pos2(c.x, c.y - 5.2),
            egui::pos2(c.x + 4.0, c.y - 4.5),
            egui::pos2(c.x + 8.5, c.y),
        ];
        painter.add(egui::epaint::PathShape::line(upper, stroke));
        // Lower eyelid arc
        let lower = vec![
            egui::pos2(c.x - 8.5, c.y),
            egui::pos2(c.x - 4.0, c.y + 4.5),
            egui::pos2(c.x, c.y + 5.2),
            egui::pos2(c.x + 4.0, c.y + 4.5),
            egui::pos2(c.x + 8.5, c.y),
        ];
        painter.add(egui::epaint::PathShape::line(lower, stroke));
        // Center pupil
        painter.circle_filled(c, 2.3, color);

        // If password is hidden, draw a slash across the eye
        if !is_plain {
            let slash_stroke = Stroke::new(1.5_f32, color);
            painter.line_segment(
                [
                    egui::pos2(c.x - 7.5, c.y + 6.2),
                    egui::pos2(c.x + 7.5, c.y - 6.2),
                ],
                slash_stroke,
            );
        }
    }

    fn draw_mini_copy_icon_in_rect(ui: &egui::Ui, rect: egui::Rect, color: Color32) {
        let painter = ui.painter();
        let stroke = Stroke::new(1.4_f32, color);
        let c = rect.center();
        // Back document
        let back_rect = egui::Rect::from_min_max(
            egui::pos2(c.x - 2.5, c.y - 7.0),
            egui::pos2(c.x + 7.0, c.y + 3.0),
        );
        painter.rect(
            back_rect,
            CornerRadius::same(2),
            Color32::TRANSPARENT,
            stroke,
            egui::StrokeKind::Inside,
        );
        // Front document
        let front_rect = egui::Rect::from_min_max(
            egui::pos2(c.x - 7.0, c.y - 3.0),
            egui::pos2(c.x + 2.5, c.y + 7.0),
        );
        let bg = ui.visuals().window_fill;
        painter.rect(
            front_rect,
            CornerRadius::same(2),
            bg,
            stroke,
            egui::StrokeKind::Inside,
        );
    }

    fn draw_mini_pencil_icon_in_rect(ui: &egui::Ui, rect: egui::Rect, color: Color32) {
        let painter = ui.painter();
        let stroke = Stroke::new(1.4_f32, color);
        let c = rect.center();
        // Pencil shaft
        let tip = egui::pos2(c.x - 6.5, c.y + 6.5);
        let body1 = egui::pos2(c.x - 4.5, c.y + 2.5);
        let body2 = egui::pos2(c.x - 2.5, c.y + 4.5);
        let top1 = egui::pos2(c.x + 4.0, c.y - 6.0);
        let top2 = egui::pos2(c.x + 6.0, c.y - 4.0);

        let outline = vec![tip, body1, top1, top2, body2, tip];
        painter.add(egui::epaint::PathShape::line(outline, stroke));
        // Eraser band line
        painter.line_segment(
            [
                egui::pos2(c.x + 2.0, c.y - 3.5),
                egui::pos2(c.x + 3.5, c.y - 2.0),
            ],
            stroke,
        );
    }

    fn draw_mini_open_window_icon_in_rect(ui: &egui::Ui, rect: egui::Rect, color: Color32) {
        let painter = ui.painter();
        let stroke = Stroke::new(1.3_f32, color);
        let c = rect.center();

        // Window box with open top-right corner
        let box_pts = vec![
            egui::pos2(c.x - 1.0, c.y - 5.0),
            egui::pos2(c.x - 5.0, c.y - 5.0),
            egui::pos2(c.x - 5.0, c.y + 5.0),
            egui::pos2(c.x + 5.0, c.y + 5.0),
            egui::pos2(c.x + 5.0, c.y + 1.0),
        ];
        painter.add(egui::epaint::PathShape::line(box_pts, stroke));

        // Arrow diagonal stem
        painter.line_segment(
            [
                egui::pos2(c.x - 1.0, c.y + 1.0),
                egui::pos2(c.x + 5.0, c.y - 5.0),
            ],
            stroke,
        );

        // Arrowhead
        let arrow_head = vec![
            egui::pos2(c.x + 1.5, c.y - 5.0),
            egui::pos2(c.x + 5.0, c.y - 5.0),
            egui::pos2(c.x + 5.0, c.y - 1.5),
        ];
        painter.add(egui::epaint::PathShape::line(arrow_head, stroke));
    }

    fn draw_mini_computer_icon_in_rect(ui: &egui::Ui, rect: egui::Rect, color: Color32) {
        let painter = ui.painter();
        let stroke = Stroke::new(1.4_f32, color);
        let c = rect.center();

        // Monitor screen
        let screen_rect = egui::Rect::from_min_max(
            egui::pos2(c.x - 8.5, c.y - 7.0),
            egui::pos2(c.x + 8.5, c.y + 3.5),
        );
        painter.rect(
            screen_rect,
            CornerRadius::same(2),
            color.gamma_multiply(0.15),
            stroke,
            egui::StrokeKind::Inside,
        );

        // Stand neck
        painter.line_segment(
            [egui::pos2(c.x, c.y + 3.5), egui::pos2(c.x, c.y + 6.5)],
            stroke,
        );

        // Stand foot
        painter.line_segment(
            [
                egui::pos2(c.x - 4.5, c.y + 6.5),
                egui::pos2(c.x + 4.5, c.y + 6.5),
            ],
            stroke,
        );
    }

    fn draw_icon_button(
        ui: &mut egui::Ui,
        tooltip: &str,
        draw_fn: impl FnOnce(&egui::Ui, egui::Rect, Color32),
    ) -> egui::Response {
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(28.0, 26.0), egui::Sense::click());
        Self::paint_icon_button(ui, rect, resp, tooltip, draw_fn)
    }

    fn paint_icon_button(
        ui: &mut egui::Ui,
        rect: egui::Rect,
        resp: egui::Response,
        tooltip: &str,
        draw_fn: impl FnOnce(&egui::Ui, egui::Rect, Color32),
    ) -> egui::Response {
        if resp.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
        }
        if ui.is_rect_visible(rect) {
            let visuals = ui.style().interact(&resp);
            if resp.hovered() || resp.is_pointer_button_down_on() {
                ui.painter().rect(
                    rect,
                    CornerRadius::same(4),
                    visuals.bg_fill,
                    visuals.bg_stroke,
                    egui::StrokeKind::Inside,
                );
            }
            let icon_color = if resp.hovered() {
                ui.visuals().widgets.hovered.fg_stroke.color
            } else {
                ui.visuals().widgets.inactive.fg_stroke.color
            };
            draw_fn(ui, rect, icon_color);
        }
        resp.on_hover_text(tooltip)
    }

    fn galley_baseline_y(galley: &egui::Galley) -> f32 {
        galley
            .rows
            .first()
            .and_then(|row| row.glyphs.first().map(|g| g.pos.y))
            .unwrap_or_else(|| galley.rect.center().y)
    }

    fn galley_ink_center_y(galley: &egui::Galley) -> f32 {
        if galley.mesh_bounds.is_positive() && galley.mesh_bounds.height() > 0.0 {
            galley.mesh_bounds.center().y
        } else {
            galley.rect.center().y
        }
    }

    /// Computes positions for Line 1 of the client browser header so that the proportional
    /// prompt, the monospace destination path, and the trailing edit button share a visual
    /// center and matching text baseline regardless of font ascent/leading differences.
    fn compute_download_header_layout(
        row_rect: egui::Rect,
        prompt_galley: &egui::Galley,
        path_galley: &egui::Galley,
        spacing_x: f32,
        btn_size: egui::Vec2,
    ) -> (egui::Pos2, egui::Pos2, egui::Rect) {
        let row_center_y = row_rect.center().y;
        let prompt_y = row_center_y - Self::galley_ink_center_y(prompt_galley);
        let shared_baseline_y = prompt_y + Self::galley_baseline_y(prompt_galley);
        let path_x = row_rect.left() + prompt_galley.size().x + spacing_x;
        let path_y = shared_baseline_y - Self::galley_baseline_y(path_galley);
        let pencil_x = path_x + path_galley.size().x + spacing_x;
        let pencil_rect = egui::Rect::from_center_size(
            egui::pos2(pencil_x + btn_size.x * 0.5, row_center_y),
            btn_size,
        );
        (
            egui::pos2(row_rect.left(), prompt_y),
            egui::pos2(path_x, path_y),
            pencil_rect,
        )
    }

    pub fn visible_scroll_style() -> egui::style::ScrollStyle {
        egui::style::ScrollStyle {
            floating: false,
            bar_width: 10.0,
            handle_min_length: 24.0,
            bar_inner_margin: 4.0,
            bar_outer_margin: 2.0,
            floating_width: 10.0,
            floating_allocated_width: 10.0,
            foreground_color: true,
            dormant_background_opacity: 1.0,
            active_background_opacity: 1.0,
            interact_background_opacity: 1.0,
            dormant_handle_opacity: 1.0,
            active_handle_opacity: 1.0,
            interact_handle_opacity: 1.0,
            ..Default::default()
        }
    }

    fn render_client_browser_panel(&mut self, ui: &mut egui::Ui) {
        let p = self.palette(ui.ctx());
        // Line 1: Download destination path as clickable link + Change button (at the top)
        {
            let spacing_x = 8.0_f32;
            let btn_size = egui::vec2(28.0, 26.0);
            let prompt_galley = egui::WidgetText::from(
                RichText::new("Save downloads to:")
                    .size(13.5)
                    .color(p.text_muted),
            )
            .into_galley(
                ui,
                Some(egui::TextWrapMode::Extend),
                f32::INFINITY,
                egui::TextStyle::Body,
            );

            let dest_str = clean_display_path(&self.client_dest_folder);
            let max_path_w =
                (ui.available_width() - prompt_galley.size().x - btn_size.x - spacing_x * 2.0)
                    .max(40.0);
            let path_galley = egui::WidgetText::from(
                RichText::new(&dest_str)
                    .size(13.5)
                    .strong()
                    .color(p.accent_blue),
            )
            .into_galley(
                ui,
                Some(egui::TextWrapMode::Truncate),
                max_path_w,
                egui::TextStyle::Body,
            );

            let row_height = btn_size
                .y
                .max(prompt_galley.size().y)
                .max(path_galley.size().y);
            let total_w =
                prompt_galley.size().x + spacing_x + path_galley.size().x + spacing_x + btn_size.x;
            let (_row_id, row_rect) = ui.allocate_space(egui::vec2(total_w, row_height));

            let (prompt_pos, path_pos, pencil_rect) = Self::compute_download_header_layout(
                row_rect,
                &prompt_galley,
                &path_galley,
                spacing_x,
                btn_size,
            );

            let path_rect = egui::Rect::from_min_size(path_pos, path_galley.size());
            let path_resp = ui.interact(
                path_rect,
                ui.make_persistent_id("dest_folder_link"),
                egui::Sense::click(),
            );
            let path_hovered = path_resp.hovered();
            let path_clicked = path_resp.clicked();
            if path_hovered {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
            }
            if path_galley.elided {
                path_resp.on_hover_text(&dest_str);
            }

            if ui.is_rect_visible(row_rect) {
                ui.painter().galley(prompt_pos, prompt_galley, p.text_muted);
                let underline = if path_hovered {
                    Stroke::new(1.0_f32, p.accent_blue)
                } else {
                    Stroke::NONE
                };
                ui.painter().add(
                    egui::epaint::TextShape::new(path_pos, path_galley, p.accent_blue)
                        .with_underline(underline),
                );
            }
            if path_clicked {
                self.clear_errors();
                if let Err(e) = open_folder_in_explorer(&self.client_dest_folder) {
                    self.client_error = Some(e);
                }
            }

            let pencil_interact = ui.interact(
                pencil_rect,
                ui.make_persistent_id("dest_folder_edit_btn"),
                egui::Sense::click(),
            );
            let pencil_resp = Self::paint_icon_button(
                ui,
                pencil_rect,
                pencil_interact,
                "Select a different destination folder for downloads",
                |ui, rect, color| {
                    Self::draw_mini_pencil_icon_in_rect(ui, rect, color);
                },
            );
            if pencil_resp.clicked() {
                self.clear_errors();
                if let Some(picked) = rfd::FileDialog::new().pick_folder() {
                    self.client_dest_folder = picked;
                }
            }
        }

        ui.add_space(4.0);

        // Line 2: Directory Navigation & Remote Path (underneath)
        let has_browser_view = self.client_connected || !self.client_file_list.is_empty();
        ui.horizontal(|ui| {
            if has_browser_view {
                if ui
                    .add_enabled(!self.client_connection_lost, egui::Button::new("⬆ Up"))
                    .clicked()
                {
                    self.navigate_up();
                }
                if ui
                    .add_enabled(!self.client_connection_lost, egui::Button::new("Refresh"))
                    .clicked()
                {
                    self.refresh_client_listing();
                }
                let current_display = if self.client_current_path.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", self.client_current_path)
                };
                ui.vertical(|ui| {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        let path_color = if self.client_connection_lost {
                            p.text_muted
                        } else {
                            p.text_primary
                        };
                        ui.label(
                            RichText::new(current_display)
                                .monospace()
                                .strong()
                                .color(path_color),
                        );
                        if self.client_connection_lost {
                            ui.label(
                                RichText::new("⚠ Host unavailable (connection lost)")
                                    .color(p.accent_red)
                                    .strong(),
                            );
                        }
                    });
                });
            } else if self.client_loading {
                ui.spinner();
                ui.label("Connecting to peer...");
            }
        });

        // Dynamic Directory Browser Area & Adjustable Downloads Panel
        let has_queue_panel = self.active_progress.is_some()
            || !self.download_queue.is_empty()
            || self.keep_downloads_panel_visible;
        let total_avail = ui.available_height();

        let (browser_height, queue_height) = if has_queue_panel {
            let max_queue = (total_avail - 180.0).max(100.0);
            let queue_h = self.download_section_height.clamp(100.0, max_queue);
            let browse_h = (total_avail - queue_h - 48.0).max(80.0);
            (browse_h, Some(queue_h))
        } else {
            ((total_avail - 12.0).max(180.0), None)
        };

        ui.add_space(4.0);
        ui.group(|ui| {
            ui.spacing_mut().scroll = Self::visible_scroll_style();
            let browse_scroll_visibility = if has_browser_view {
                egui::scroll_area::ScrollBarVisibility::AlwaysVisible
            } else {
                egui::scroll_area::ScrollBarVisibility::AlwaysHidden
            };
            ScrollArea::vertical()
                .id_salt("client_file_list_scroll")
                .auto_shrink([false, false])
                .scroll_bar_visibility(browse_scroll_visibility)
                .min_scrolled_height(browser_height)
                .max_height(browser_height)
                .show(ui, |ui| {
                    if !has_browser_view {
                        if !self.client_loading {
                            ui.vertical_centered(|ui| {
                                ui.add_space(40.0);
                                ui.label(
                                    RichText::new("Select a computer from the list on the left to browse shares")
                                        .size(13.5)
                                        .color(p.text_muted),
                                );
                            });
                        }
                        return;
                    }

                    let min_table_w = self.browse_col_name_w
                        + BROWSE_COL_SIZE_W
                        + BROWSE_COL_DATE_W
                        + BROWSE_COL_ACTION_W
                        + (3.0 * 16.0);
                    let row_w = (min_table_w - 6.0).max(self.browse_col_name_w);
                    let mut next_hovered_browse_idx = None;

                    ui.scope(|ui| {
                        ui.style_mut().interaction.selectable_labels = false;
                        ui.style_mut().visuals.faint_bg_color = p.browse_row_stripe_bg;
                        egui::Grid::new("file_grid")
                            .striped(true)
                            .min_col_width(50.0)
                            .spacing([16.0, 8.0])
                            .show(ui, |ui| {
                            // Column 0: Name with drag resize handle
                            ui.horizontal(|ui| {
                                ui.set_width(self.browse_col_name_w);
                                ui.set_max_width(self.browse_col_name_w);
                                ui.add_space(8.0);
                                ui.label(RichText::new("Name").strong());
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    let (res_id, res_rect) = ui.allocate_space(egui::vec2(10.0, 18.0));
                                    let res_resp = ui.interact(res_rect, res_id, egui::Sense::drag());
                                    if res_resp.hovered() || res_resp.dragged() {
                                        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeColumn);
                                        ui.painter().vline(
                                            res_rect.center().x,
                                            res_rect.y_range(),
                                            Stroke::new(2.0_f32, p.accent_blue),
                                        );
                                    } else {
                                        ui.painter().vline(
                                            res_rect.center().x,
                                            res_rect.y_range(),
                                            Stroke::new(1.0_f32, p.border),
                                        );
                                    }
                                    if res_resp.dragged() {
                                        self.browse_col_name_w = (self.browse_col_name_w + res_resp.drag_delta().x).clamp(80.0, 1200.0);
                                    }
                                });
                            });

                            // Column 1: Size (fixed width, centered)
                            ui.horizontal(|ui| {
                                ui.set_width(BROWSE_COL_SIZE_W);
                                ui.centered_and_justified(|ui| {
                                    ui.label(RichText::new("Size").strong());
                                });
                            });

                            // Column 2: Modified (fixed width, centered)
                            ui.horizontal(|ui| {
                                ui.set_width(BROWSE_COL_DATE_W);
                                ui.centered_and_justified(|ui| {
                                    ui.label(RichText::new("Modified").strong());
                                });
                            });

                            // Column 3: Action (fixed width, centered)
                            ui.horizontal(|ui| {
                                ui.set_width(BROWSE_COL_ACTION_W);
                                ui.centered_and_justified(|ui| {
                                    ui.label(RichText::new("Action").strong());
                                });
                            });
                            ui.end_row();

                            let files = self.client_file_list.clone();
                            if files.is_empty() {
                                ui.horizontal(|ui| {
                                    ui.add_space(8.0);
                                    ui.label(
                                        RichText::new("(Folder is empty)")
                                            .italics()
                                            .color(p.text_muted),
                                    );
                                });
                                ui.label("");
                                ui.label("");
                                ui.label("");
                                ui.end_row();
                            } else {
                                for (idx, entry) in files.into_iter().enumerate() {
                                    let is_highlighted = self.hovered_browse_download_idx == Some(idx);
                                    let row_start = ui.cursor().min;
                                    let row_rect = egui::Rect::from_min_size(row_start, egui::vec2(row_w, 24.0));

                                    // Viewport virtualization for massive folders (tens of thousands of files)
                                    if !ui.is_rect_visible(row_rect) && !is_highlighted {
                                        ui.allocate_space(egui::vec2(self.browse_col_name_w, 24.0));
                                        ui.allocate_space(egui::vec2(BROWSE_COL_SIZE_W, 24.0));
                                        ui.allocate_space(egui::vec2(BROWSE_COL_DATE_W, 24.0));
                                        ui.allocate_space(egui::vec2(BROWSE_COL_ACTION_W, 24.0));
                                        ui.end_row();
                                        continue;
                                    }

                                    if is_highlighted {
                                        ui.painter().rect_filled(
                                            row_rect,
                                            CornerRadius::same(4),
                                            p.browse_row_hover_bg,
                                        );
                                    }

                                    if entry.is_dir {
                                        let mut clicked = false;
                                        let dir_color = if self.client_connection_lost {
                                            p.text_muted
                                        } else {
                                            p.accent_blue
                                        };
                                        ui.horizontal(|ui| {
                                            ui.set_width(self.browse_col_name_w);
                                            ui.set_max_width(self.browse_col_name_w);
                                            ui.add_space(8.0);
                                            ui.spacing_mut().item_spacing.x = 6.0;
                                            let icon_resp = Self::draw_mini_folder_icon(ui, dir_color);
                                            let label = egui::Label::new(
                                                RichText::new(&entry.name)
                                                    .strong()
                                                    .color(dir_color),
                                            )
                                            .sense(egui::Sense::click())
                                            .truncate();
                                            let (galley_pos, galley, text_resp) = label.layout_in_ui(ui);

                                            let is_hovered = icon_resp.hovered() || text_resp.hovered() || is_highlighted;
                                            if is_hovered {
                                                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                                            }

                                            if ui.is_rect_visible(text_resp.rect) {
                                                let underline = if is_hovered && !self.client_connection_lost {
                                                    Stroke::new(1.0_f32, dir_color)
                                                } else {
                                                    Stroke::NONE
                                                };
                                                ui.painter().add(
                                                    egui::epaint::TextShape::new(galley_pos, galley, dir_color)
                                                        .with_underline(underline),
                                                );
                                            }

                                            if icon_resp.clicked() || text_resp.clicked() {
                                                clicked = true;
                                            }
                                            text_resp.on_hover_text(&entry.name);
                                        });
                                        if clicked {
                                            self.navigate_into(&entry.name);
                                        }
                                    } else {
                                        ui.horizontal(|ui| {
                                            ui.set_width(self.browse_col_name_w);
                                            ui.set_max_width(self.browse_col_name_w);
                                            ui.add_space(8.0);
                                            let label_text = RichText::new(&entry.name).strong().color(if is_highlighted {
                                                p.accent_blue
                                            } else {
                                                p.text_primary
                                            });
                                            let file_resp = ui.add(
                                                egui::Label::new(label_text)
                                                    .selectable(false)
                                                    .truncate(),
                                            );
                                            if file_resp.hovered() {
                                                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                                            }
                                            file_resp.on_hover_text(&entry.name);
                                        });
                                    }

                                    let size_str = if entry.is_dir {
                                        "-".to_string()
                                    } else {
                                        format_file_size(entry.size)
                                    };
                                    ui.horizontal(|ui| {
                                        ui.set_width(BROWSE_COL_SIZE_W);
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            ui.add_space(6.0);
                                            let size_resp = ui.add(
                                                egui::Label::new(RichText::new(size_str).monospace())
                                                    .selectable(false),
                                            );
                                            if size_resp.hovered() {
                                                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                                            }
                                        });
                                    });

                                    let date_str = if entry.modified_timestamp > 0 {
                                        if let Some(dt) = Local
                                            .timestamp_opt(entry.modified_timestamp as i64, 0)
                                            .single()
                                        {
                                            dt.format("%Y-%m-%d %H:%M").to_string()
                                        } else {
                                            "-".to_string()
                                        }
                                    } else {
                                        "-".to_string()
                                    };
                                    ui.horizontal(|ui| {
                                        ui.set_width(BROWSE_COL_DATE_W);
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            ui.add_space(6.0);
                                            let date_resp = ui.add(
                                                egui::Label::new(date_str).selectable(false),
                                            );
                                            if date_resp.hovered() {
                                                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                                            }
                                        });
                                    });

                                    let row_subpath = if self.client_current_path.is_empty() {
                                        entry.name.clone()
                                    } else {
                                        format!("{}/{}", self.client_current_path, entry.name)
                                    };
                                    let existing_status = self
                                        .download_queue
                                        .iter()
                                        .find(|i| {
                                             i.conn_ctx.ip == self.client_ip
                                                 && i.remote_subpath == row_subpath
                                                 && matches!(
                                                     i.status,
                                                     QueueItemStatus::Pending
                                                         | QueueItemStatus::Downloading
                                                 )
                                         })
                                         .map(|i| i.status.clone());

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.set_min_width(76.0);
                                        ui.add_space(6.0);
                                        match existing_status {
                                            Some(QueueItemStatus::Downloading) => {
                                                let btn_resp = ui.add_enabled(false, egui::Button::new("Active"));
                                                if btn_resp.hovered() {
                                                    next_hovered_browse_idx = Some(idx);
                                                }
                                            }
                                            Some(QueueItemStatus::Pending) => {
                                                let btn_resp = ui.add_enabled(false, egui::Button::new("Queued"));
                                                if btn_resp.hovered() {
                                                    next_hovered_browse_idx = Some(idx);
                                                }
                                            }
                                            _ => {
                                                let is_busy = self.active_queue_id.is_some();
                                                let dl_label = if is_busy {
                                                    "Queue"
                                                } else {
                                                    "Download"
                                                };
                                                let can_download = !self.client_connection_lost;
                                                let btn_resp = ui.add_enabled(
                                                    can_download,
                                                    egui::Button::new(dl_label),
                                                );
                                                if btn_resp.hovered() && can_download {
                                                    next_hovered_browse_idx = Some(idx);
                                                }
                                                if btn_resp.clicked() && can_download {
                                                    self.enqueue_download(entry);
                                                }
                                            }
                                        }
                                    });
                                    ui.end_row();
                                }
                            }
                        });
                    });

                    if self.hovered_browse_download_idx != next_hovered_browse_idx {
                        self.hovered_browse_download_idx = next_hovered_browse_idx;
                        ui.ctx().request_repaint();
                    }
                });
        });

        // Multi-Item Download Queue & Live Progress Panel (Resizable Splitter)
        if let Some(queue_h) = queue_height {
            ui.add_space(2.0);

            // Interactive Resizable Splitter Handle
            let (splitter_rect, splitter_resp) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), 10.0),
                egui::Sense::click_and_drag(),
            );

            if splitter_resp.hovered() || splitter_resp.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
            }

            if splitter_resp.dragged() {
                let delta_y = splitter_resp.drag_delta().y;
                let max_queue = (total_avail - 140.0).max(100.0);
                self.download_section_height =
                    (self.download_section_height - delta_y).clamp(100.0, max_queue);
            }

            // Draw visual separator / resize handle
            let line_color = if splitter_resp.dragged() || splitter_resp.hovered() {
                p.accent_blue
            } else {
                p.border
            };
            ui.painter().hline(
                splitter_rect.x_range(),
                splitter_rect.center().y,
                Stroke::new(1.0_f32, line_color),
            );

            // Subtle center grip indicator
            let grip_rect =
                egui::Rect::from_center_size(splitter_rect.center(), egui::vec2(40.0, 4.0));
            ui.painter().rect_filled(
                grip_rect,
                2.0,
                if splitter_resp.hovered() || splitter_resp.dragged() {
                    p.accent_blue
                } else {
                    p.text_subtle
                },
            );

            ui.add_space(2.0);
            self.render_download_queue_panel(ui, queue_h);
        }
    }

    fn render_download_queue_panel(&mut self, ui: &mut egui::Ui, panel_height: f32) {
        let p = self.palette(ui.ctx());
        let pending_count = self
            .download_queue
            .iter()
            .filter(|i| i.status == QueueItemStatus::Pending)
            .count();
        let active_count = self
            .download_queue
            .iter()
            .filter(|i| i.status == QueueItemStatus::Downloading)
            .count();
        let done_count = self
            .download_queue
            .iter()
            .filter(|i| matches!(i.status, QueueItemStatus::Completed))
            .count();

        let active_speed = self
            .active_progress
            .as_ref()
            .map(|p| p.speed_mbps)
            .filter(|&s| s > 0.0);
        let active_remaining = self
            .active_progress
            .as_ref()
            .map(|p| p.bytes_total.saturating_sub(p.bytes_done))
            .unwrap_or(0);
        let queued_pending_bytes: u64 = self
            .download_queue
            .iter()
            .filter(|i| i.status == QueueItemStatus::Pending)
            .map(|i| i.entry.size)
            .sum();
        let total_remaining_bytes = active_remaining + queued_pending_bytes;

        let active_item = self
            .download_queue
            .iter()
            .find(|i| i.status == QueueItemStatus::Downloading);
        let active_elapsed = active_item.and_then(|i| i.started_at.map(|t| t.elapsed()));

        let active_key = self.active_queue_id.map(|id| id.to_string()).or_else(|| {
            self.active_progress
                .as_ref()
                .map(|p| p.selected_target.clone())
        });

        let raw_active_eta = if let Some(ref prog) = self.active_progress {
            if prog.is_finished {
                Some(0)
            } else {
                estimate_folder_remaining_seconds(
                    active_remaining,
                    prog.speed_mbps,
                    prog.current_file,
                    prog.total_files,
                    active_elapsed,
                )
            }
        } else {
            active_speed.and_then(|spd| estimate_remaining_seconds(active_remaining, spd))
        };
        let active_eta = self
            .active_eta_stabilizer
            .update(active_key.as_deref(), raw_active_eta);

        let raw_total_eta = match (active_eta, active_speed) {
            (Some(act_s), Some(spd)) if queued_pending_bytes > 0 => {
                let pending_secs =
                    estimate_remaining_seconds(queued_pending_bytes, spd).unwrap_or(0);
                Some(act_s + pending_secs)
            }
            (Some(act_s), _) => Some(act_s),
            (None, Some(spd)) => estimate_remaining_seconds(total_remaining_bytes, spd),
            _ => None,
        };
        let total_key = if active_key.is_some() || queued_pending_bytes > 0 {
            Some("total_queue")
        } else {
            None
        };
        let total_eta = self.total_eta_stabilizer.update(total_key, raw_total_eta);

        let mut cancel_current = false;
        let mut cancel_all = false;
        let mut clear_finished = false;
        let mut remove_id: Option<u64> = None;

        let target_h = (ui.available_height() - 4.0).min(panel_height).max(70.0);
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), target_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.group(|ui| {
                    ui.set_min_height(target_h - 8.0);
                    ui.horizontal(|ui| {
                        let mut header_text = format!(
                            "Downloads — Active: {} | Queued: {} | Done: {}",
                            active_count, pending_count, done_count
                        );
                        if let Some(tot_s) = total_eta {
                            let is_active_in_progress = self
                                .active_progress
                                .as_ref()
                                .map(|p| !p.is_finished)
                                .unwrap_or(false);
                            if total_remaining_bytes > 0 || is_active_in_progress {
                                header_text.push_str(&format!(
                                    " | Total ETA: {}",
                                    format_remaining_time(tot_s)
                                ));
                            }
                        }
                        ui.label(RichText::new(header_text).strong());

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if !self.download_queue.is_empty() && ui.button("Clear Done").clicked()
                            {
                                clear_finished = true;
                            }
                            if (active_count > 0 || pending_count > 0)
                                && ui.button("Cancel All").clicked()
                            {
                                cancel_all = true;
                            }
                        });
                    });

                    if let Some(ref prog) = self.active_progress {
                        let pct = if prog.bytes_total > 0 {
                            (prog.bytes_done as f32 / prog.bytes_total as f32).clamp(0.0, 1.0)
                        } else {
                            0.0
                        };

                        ui.horizontal(|ui| {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if self.active_queue_id.is_some() {
                                        let cancel_btn = egui::Button::new(
                                            RichText::new("Cancel").strong().color(Color32::WHITE),
                                        )
                                        .fill(p.accent_red);
                                        if ui.add(cancel_btn).clicked() {
                                            cancel_current = true;
                                        }
                                    }

                                    ui.with_layout(
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            let active_item_ref =
                                                self.active_queue_id.and_then(|aid| {
                                                    self.download_queue.iter().find(|i| i.id == aid)
                                                });
                                            let active_is_dir = active_item_ref
                                                .map(|i| i.entry.is_dir)
                                                .unwrap_or(false);
                                            let active_target_label = match active_item_ref {
                                                Some(item) => format!(
                                                    "{} ({})",
                                                    prog.selected_target, item.peer_name
                                                ),
                                                None => prog.selected_target.clone(),
                                            };
                                            if active_is_dir {
                                                Self::draw_mini_folder_icon(ui, p.accent_green);
                                            }
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(active_target_label)
                                                        .strong()
                                                        .color(p.accent_green),
                                                )
                                                .truncate(),
                                            );
                                            let is_waiting =
                                                crate::core::is_transfer_waiting_status(
                                                    &prog.file_name,
                                                );
                                            if prog.total_files > 1 && !is_waiting {
                                                ui.separator();
                                                let status_text = format!(
                                                    "[{}/{}] {}",
                                                    prog.current_file,
                                                    prog.total_files,
                                                    prog.file_name
                                                );
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(status_text).strong(),
                                                    )
                                                    .truncate(),
                                                );
                                            }
                                        },
                                    );
                                },
                            );
                        });

                        ui.horizontal(|ui| {
                            ui.add(
                                egui::ProgressBar::new(pct)
                                    .show_percentage()
                                    .desired_width(280.0),
                            );

                            if prog.speed_mbps > 0.0 {
                                ui.label(
                                    RichText::new(format!("{:.1} MB/s", prog.speed_mbps))
                                        .monospace(),
                                );
                            }

                            if let Some(act_s) = active_eta {
                                let is_active_in_progress = !prog.is_finished;
                                if active_remaining > 0 || is_active_in_progress {
                                    ui.label(
                                        RichText::new(format!(
                                            "ETA: {}",
                                            format_remaining_time(act_s)
                                        ))
                                        .strong()
                                        .color(p.accent_blue),
                                    );
                                }
                            }

                            if let Some(tot_s) = total_eta {
                                if pending_count > 0 {
                                    ui.label(
                                        RichText::new(format!(
                                            "(Total: {})",
                                            format_remaining_time(tot_s)
                                        ))
                                        .color(p.text_muted),
                                    );
                                }
                            }

                            if prog.bytes_total > 0 {
                                let done_str = format_file_size(prog.bytes_done);
                                let total_str = format_file_size(prog.bytes_total);
                                ui.label(
                                    RichText::new(format!("{} / {}", done_str, total_str))
                                        .color(p.text_muted),
                                );
                            }
                        });
                    }

                    let hide_active_row = self.active_progress.is_some();
                    let include_queue_item = |status: &QueueItemStatus| {
                        !matches!(status, QueueItemStatus::Cancelled)
                            && !(hide_active_row && matches!(status, QueueItemStatus::Downloading))
                    };
                    if self
                        .download_queue
                        .iter()
                        .any(|i| include_queue_item(&i.status))
                    {
                        ui.separator();
                        ui.spacing_mut().scroll = Self::visible_scroll_style();
                        let queue_scroll_h = (ui.available_height() - 8.0).max(35.0);
                        ScrollArea::vertical()
                            .id_salt("download_queue_scroll")
                            .max_height(queue_scroll_h)
                            .auto_shrink([false, false])
                            .scroll_bar_visibility(
                                egui::scroll_area::ScrollBarVisibility::AlwaysVisible,
                            )
                            .show(ui, |ui| {
                                let mut display_items: Vec<_> = self
                                    .download_queue
                                    .iter()
                                    .filter(|i| include_queue_item(&i.status))
                                    .collect();
                                display_items
                                    .sort_by_key(|item| queue_status_sort_rank(&item.status));

                                for item in display_items {
                                    ui.horizontal(|ui| {
                                        let (badge, color) = match &item.status {
                                            QueueItemStatus::Downloading => {
                                                ("Active", p.accent_blue)
                                            }
                                            QueueItemStatus::Pending => ("Queued", p.accent_amber),
                                            QueueItemStatus::Completed => ("Done", p.accent_green),
                                            QueueItemStatus::Cancelled => {
                                                ("Cancelled", p.text_muted)
                                            }
                                            QueueItemStatus::Failed(_) => ("Failed", p.accent_red),
                                        };
                                        ui.label(RichText::new(badge).strong().color(color));
                                        ui.label(format!(
                                            "{} ({})",
                                            item.entry.name, item.peer_name
                                        ));

                                        if matches!(
                                            item.status,
                                            QueueItemStatus::Pending | QueueItemStatus::Failed(_)
                                        ) {
                                            let tip = if item.status == QueueItemStatus::Pending {
                                                "Remove from queue"
                                            } else {
                                                "Remove from list"
                                            };
                                            if ui.button("✖").on_hover_text(tip).clicked() {
                                                remove_id = Some(item.id);
                                            }
                                        }

                                        match &item.status {
                                            QueueItemStatus::Downloading => {
                                                // Active ETA is shown in active download section above, not needed in list
                                            }
                                            QueueItemStatus::Pending => {
                                                if item.entry.is_dir {
                                                    ui.label(
                                                        RichText::new("• Folder")
                                                            .color(p.text_muted),
                                                    );
                                                } else if item.entry.size > 0 {
                                                    let sz_str = format_file_size(item.entry.size);
                                                    if let Some(spd) = active_speed {
                                                        if let Some(item_s) =
                                                            estimate_remaining_seconds(
                                                                item.entry.size,
                                                                spd,
                                                            )
                                                        {
                                                            ui.label(
                                                                RichText::new(format!(
                                                                    "• {} • ETA: {}",
                                                                    sz_str,
                                                                    format_remaining_time(item_s)
                                                                ))
                                                                .color(p.text_muted),
                                                            );
                                                        } else {
                                                            ui.label(
                                                                RichText::new(format!(
                                                                    "• {}",
                                                                    sz_str
                                                                ))
                                                                .color(p.text_muted),
                                                            );
                                                        }
                                                    } else {
                                                        ui.label(
                                                            RichText::new(format!("• {}", sz_str))
                                                                .color(p.text_muted),
                                                        );
                                                    }
                                                }
                                            }
                                            QueueItemStatus::Completed => {
                                                let final_bytes =
                                                    item.total_bytes.unwrap_or(item.entry.size);
                                                let size_str = format_file_size(final_bytes);
                                                let took_str = item.elapsed_duration.map(|dur| {
                                                    if dur.as_secs() == 0 {
                                                        "< 1s".to_string()
                                                    } else {
                                                        format_remaining_time(dur.as_secs())
                                                    }
                                                });
                                                let time_str = item
                                                    .completed_at
                                                    .map(format_completed_timestamp);

                                                let mut parts = vec![size_str];
                                                if let Some(took) = took_str {
                                                    parts.push(format!("Took {}", took));
                                                }
                                                if let Some(finished_ts) = time_str {
                                                    parts.push(finished_ts);
                                                }

                                                let label_text = format!("• {}", parts.join(" • "));
                                                ui.label(
                                                    RichText::new(label_text).color(p.text_muted),
                                                );
                                            }
                                            QueueItemStatus::Failed(ref err) => {
                                                ui.label(
                                                    RichText::new(format!("• Error: {}", err))
                                                        .color(p.accent_red),
                                                );
                                            }
                                            _ => {}
                                        }
                                    });
                                }
                            });
                    }
                });
            },
        );

        if let Some(id) = remove_id {
            self.download_queue.retain(|i| i.id != id);
        }
        if cancel_all {
            self.cancel_all_downloads();
        }
        if clear_finished {
            self.download_queue.retain(|i| {
                matches!(
                    i.status,
                    QueueItemStatus::Pending | QueueItemStatus::Downloading
                )
            });
            if self.download_queue.is_empty() && self.active_progress.is_none() {
                self.keep_downloads_panel_visible = false;
            }
        }
        if cancel_current {
            self.cancel_active_transfer();
        }
    }

    fn render_host_tab(&mut self, ui: &mut egui::Ui) {
        let is_running = self.server_handle.is_some();
        let p = self.palette(ui.ctx());

        ui.add_space(8.0);

        // 1. Host Status & Controls (Top Card - fixed height across stopped/active states)
        let host_ip = self
            .server_handle
            .as_ref()
            .map(|h| h.local_ip.clone())
            .unwrap_or_else(|| {
                self.local_ips
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "127.0.0.1".to_string())
            });

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.set_min_height(36.0);
                if is_running {
                    ui.label(
                        RichText::new("● SHARING ACTIVE ON LAN")
                            .size(15.0)
                            .monospace()
                            .strong()
                            .color(p.accent_green),
                    );
                } else {
                    ui.label(
                        RichText::new("○ SERVER STOPPED")
                            .size(15.0)
                            .monospace()
                            .strong()
                            .color(p.text_muted),
                    );
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if is_running {
                        let stop_btn = egui::Button::new(
                            RichText::new("Stop Sharing")
                                .size(15.0)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .min_size(Vec2::new(170.0, 36.0))
                        .fill(p.accent_red);

                        if ui.add(stop_btn).clicked() {
                            if self.active_server_downloads() > 0 {
                                self.pending_remove_host_folder_idx = None;
                                self.show_stop_server_confirm_dialog = true;
                            } else {
                                self.stop_hosting_server();
                            }
                        }
                    } else if !self.host_folders.is_empty() {
                        let has_valid_pwd = self.ring_secret.trim().len() >= MIN_SECRET_LEN;

                        ui.add_enabled_ui(has_valid_pwd, |ui| {
                            let start_btn = egui::Button::new(
                                RichText::new("Start Sharing")
                                    .size(15.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .min_size(Vec2::new(170.0, 36.0))
                            .fill(p.accent_green);

                            if ui.add(start_btn).clicked() {
                                self.start_hosting_server();
                            }
                        });
                    }
                });
            });

            ui.add_space(6.0);
            ui.separator();
            ui.add_space(4.0);

            {
                let spacing_x = 6.0_f32;
                let btn_size = egui::vec2(28.0, 26.0);
                let prompt_galley = egui::WidgetText::from(
                    RichText::new("Host IP:").size(13.5).color(p.text_muted),
                )
                .into_galley(
                    ui,
                    Some(egui::TextWrapMode::Extend),
                    f32::INFINITY,
                    egui::TextStyle::Body,
                );
                let ip_galley = egui::WidgetText::from(
                    RichText::new(&host_ip)
                        .monospace()
                        .size(13.5)
                        .strong()
                        .color(p.text_primary),
                )
                .into_galley(
                    ui,
                    Some(egui::TextWrapMode::Extend),
                    f32::INFINITY,
                    egui::TextStyle::Monospace,
                );

                let row_height = btn_size
                    .y
                    .max(prompt_galley.size().y)
                    .max(ip_galley.size().y);
                let total_w = prompt_galley.size().x
                    + spacing_x
                    + ip_galley.size().x
                    + spacing_x
                    + btn_size.x;
                let (_row_id, row_rect) = ui.allocate_space(egui::vec2(total_w, row_height));

                let (prompt_pos, ip_pos, copy_rect) = Self::compute_download_header_layout(
                    row_rect,
                    &prompt_galley,
                    &ip_galley,
                    spacing_x,
                    btn_size,
                );

                if ui.is_rect_visible(row_rect) {
                    ui.painter().galley(prompt_pos, prompt_galley, p.text_muted);
                    ui.painter().galley(ip_pos, ip_galley, p.text_primary);
                }

                let copy_interact = ui.interact(
                    copy_rect,
                    ui.make_persistent_id("host_ip_copy_btn"),
                    egui::Sense::click(),
                );
                let copy_ip_resp = Self::paint_icon_button(
                    ui,
                    copy_rect,
                    copy_interact,
                    "Copy Host IP to clipboard",
                    |ui, rect, color| {
                        Self::draw_mini_copy_icon_in_rect(ui, rect, color);
                    },
                );
                if copy_ip_resp.clicked() {
                    self.clear_errors();
                    self.copy_to_clipboard(ui.ctx(), &host_ip, "Host IP");
                }
            }
        });

        ui.add_space(10.0);

        // 2. Folders to Share (Middle Card)
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Folders to Share")
                        .size(16.0)
                        .strong()
                        .color(p.text_primary),
                );
                ui.add_space(4.0);
                if ui
                    .button("Add Folder(s)...")
                    .on_hover_text("Select one or multiple folders to share (Ctrl/Shift+Click)")
                    .clicked()
                {
                    self.clear_errors();
                    if let Some(folders) = rfd::FileDialog::new().pick_folders() {
                        let mut added_any = false;
                        for folder in folders {
                            match validate_shared_folder(&folder) {
                                Ok(safe) => {
                                    if !self.host_folders.contains(&safe) {
                                        self.host_folders.push(safe);
                                        added_any = true;
                                    }
                                }
                                Err(e) => self.host_error = Some(e),
                            }
                        }
                        if added_any {
                            if let Some(ref handle) = self.server_handle {
                                if let Err(e) = handle.update_shared_folders(self.host_folders.clone()) {
                                    self.host_error = Some(e);
                                }
                            } else if self.ring_secret.trim().len() >= MIN_SECRET_LEN {
                                self.start_hosting_server();
                            }
                        }
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !is_running && !self.host_folders.is_empty() && ui.button("Clear All").clicked() {
                        self.clear_errors();
                        self.host_folders.clear();
                    }
                });
            });

            ui.add_space(6.0);

            if self.host_folders.is_empty() {
                ui.label(
                    RichText::new(
                        "No folders added yet. Click 'Add Folder(s)...' or drag & drop folders below.",
                    )
                    .color(p.text_muted),
                );
            } else {
                let mut remove_idx = None;
                let mut open_folder_target = None;
                let mut next_hovered_host_remove = None;
                let scroll_max_h = (ui.available_height() - 85.0).max(120.0);
                ui.spacing_mut().scroll = Self::visible_scroll_style();
                ScrollArea::vertical()
                    .id_salt("host_folders_scroll")
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                    .max_height(scroll_max_h)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for (idx, folder) in self.host_folders.iter().enumerate() {
                            let is_remove_hovered = self.hovered_host_remove_idx == Some(idx);

                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;

                                let btn = ui.button("✖").on_hover_text("Remove folder");
                                if btn.hovered() {
                                    next_hovered_host_remove = Some(idx);
                                }
                                if btn.clicked() {
                                    remove_idx = Some(idx);
                                }

                                let folder_str = clean_display_path(folder);
                                let link_color = if is_remove_hovered {
                                    p.accent_red
                                } else {
                                    p.accent_blue
                                };
                                let link_label = egui::Label::new(
                                    RichText::new(&folder_str)
                                        .size(14.0)
                                        .strong()
                                        .color(link_color),
                                )
                                .sense(egui::Sense::click());
                                let (galley_pos, galley, resp) = link_label.layout_in_ui(ui);
                                let is_link_hovered = resp.hovered();
                                if is_link_hovered {
                                    ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
                                }

                                // Highlight only the selected path not the whole line
                                if is_remove_hovered {
                                    let red_alpha = if p.is_dark { 28 } else { 44 };
                                    ui.painter().rect_filled(
                                        resp.rect.expand2(egui::vec2(4.0, 2.0)),
                                        CornerRadius::same(4),
                                        Color32::from_rgba_unmultiplied(239, 68, 68, red_alpha),
                                    );
                                } else if is_link_hovered {
                                    let blue_alpha = if p.is_dark { 20 } else { 44 };
                                    ui.painter().rect_filled(
                                        resp.rect.expand2(egui::vec2(4.0, 2.0)),
                                        CornerRadius::same(4),
                                        Color32::from_rgba_unmultiplied(37, 99, 235, blue_alpha),
                                    );
                                }

                                if ui.is_rect_visible(resp.rect) {
                                    let underline = if is_link_hovered {
                                        Stroke::new(1.0_f32, link_color)
                                    } else {
                                        Stroke::NONE
                                    };
                                    ui.painter().add(
                                        egui::epaint::TextShape::new(galley_pos, galley, link_color)
                                            .with_underline(underline),
                                    );
                                }
                                if resp.clicked() {
                                    open_folder_target = Some(folder.clone());
                                }
                            });
                        }
                    });

                if self.hovered_host_remove_idx != next_hovered_host_remove {
                    self.hovered_host_remove_idx = next_hovered_host_remove;
                    ui.ctx().request_repaint();
                }

                if let Some(target) = open_folder_target {
                    self.clear_errors();
                    if let Err(e) = open_folder_in_explorer(&target) {
                        self.host_error = Some(e);
                    }
                }

                if let Some(idx) = remove_idx {
                    self.remove_host_folder(idx);
                }
            }

            ui.add_space(8.0);

            // Drag & Drop Box
            let drop_frame = egui::Frame {
                inner_margin: egui::Margin::same(14),
                outer_margin: egui::Margin::same(2),
                corner_radius: CornerRadius::same(8),
                shadow: egui::epaint::Shadow::NONE,
                fill: p.card_bg,
                stroke: Stroke::new(1.0_f32, p.border),
            };
            drop_frame.show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("Drag & Drop Folders Here")
                            .strong()
                            .size(13.5)
                            .color(p.accent_blue),
                    );
                });
            });

            if let Some(ref err) = self.host_error {
                ui.add_space(4.0);
                ui.label(RichText::new(format!("Error: {}", err)).color(p.accent_red));
            }
        });
    }

    fn trigger_ring_scan(&mut self) {
        self.clear_errors();
        let secret = self.ring_secret.trim().to_string();
        if secret.len() < MIN_SECRET_LEN {
            return;
        }
        self.is_scanning = true;

        let (scan_tx, scan_rx) = channel();
        self.scan_rx = Some(scan_rx);
        let is_test = self.test_mode;

        self.tokio_rt.spawn(async move {
            let dur = Duration::from_millis(if is_test { 600 } else { 1500 });
            let mut peers = client::scan_lan_for_hosts(dur, Some(&secret)).await;
            if is_test {
                for mock_peer in default_mock_peers() {
                    if !peers.iter().any(|p| p.ip == mock_peer.ip) {
                        peers.push(mock_peer);
                    }
                }
            }
            sort_peers_alphabetically(&mut peers);
            let _ = scan_tx.send(peers);
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

    fn disconnect_client_session(&mut self) {
        self.client_connected = false;
        self.client_connection_lost = false;
        self.connected_via_direct_ip = false;
        self.mock_session = false;
        self.client_ip.clear();
        self.selected_peer_name.clear();
        self.client_handshake = None;
        self.client_stream = None;
        self.client_current_path.clear();
        self.client_file_list.clear();
        self.client_loading = false;
        self.discovered_peers = if self.test_mode {
            default_mock_peers()
        } else {
            Vec::new()
        };
    }

    fn select_and_connect_peer(&mut self, peer: &DiscoveredPeer) {
        self.clear_errors();
        self.connected_via_direct_ip = false;
        self.client_ip = peer.ip.clone();
        self.client_port = peer.port;
        self.selected_peer_name = peer.host_name.clone();
        if peer.ip.starts_with("mock://") {
            self.connect_mock_session(&peer.host_name, &peer.ip);
        } else {
            self.trigger_connect();
        }
    }

    fn connect_mock_session(&mut self, host_label: &str, mock_ip: &str) {
        self.client_connected = true;
        self.client_connection_lost = false;
        self.connected_via_direct_ip = false;
        self.mock_session = true;
        self.client_ip = mock_ip.to_string();
        self.selected_peer_name = host_label.to_string();
        self.client_stream = None;
        self.client_current_path.clear();
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

    fn trigger_connect(&mut self) {
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

        let pwd = self.ring_secret.trim().to_string();
        let port = self.client_port;
        let tx = self.client_action_tx.clone();
        self.client_loading = true;

        self.tokio_rt.spawn(async move {
            match client::connect_to_host(&ip, port, &pwd).await {
                Ok((stream, resp)) => {
                    let _ = tx.send(ClientActionResult::Connected(stream, resp, ip));
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
            self.client_current_path = target_path;
            self.client_file_list =
                mock_directory_entries(&self.client_ip, &self.client_current_path);
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
            self.client_loading = true;

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

    fn refresh_client_listing(&mut self) {
        self.request_listing_for_path(self.client_current_path.clone());
    }

    fn navigate_into(&mut self, folder_name: &str) {
        let target_path = if self.client_current_path.is_empty() {
            folder_name.to_string()
        } else {
            format!("{}/{}", self.client_current_path, folder_name)
        };
        self.request_listing_for_path(target_path);
    }

    fn navigate_up(&mut self) {
        let target_path = if let Some(idx) = self.client_current_path.rfind('/') {
            self.client_current_path[..idx].to_string()
        } else {
            String::new()
        };
        self.request_listing_for_path(target_path);
    }

    fn cancel_active_transfer(&mut self) {
        self.clear_errors();
        if let Some(tx) = self.transfer_cancel_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(active_id) = self.active_queue_id.take() {
            self.download_queue.retain(|i| i.id != active_id);
        }
        self.active_progress = None;
        self.active_eta_stabilizer.reset();
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.push_client_log(format!("[{}] Transfer cancelled by user.", ts));
    }

    fn cancel_all_downloads(&mut self) {
        self.cancel_active_transfer();
        self.download_queue.retain(|i| {
            !matches!(
                i.status,
                QueueItemStatus::Downloading
                    | QueueItemStatus::Pending
                    | QueueItemStatus::Cancelled
            )
        });
        self.keep_downloads_panel_visible = true;
    }

    fn enqueue_download(&mut self, entry: FileEntry) {
        self.clear_errors();
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
            self.clipboard_flash = Some((
                format!("'{}' is already in the download queue.", entry.name),
                Instant::now(),
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

        let total_bytes = if entry.is_dir { None } else { Some(entry.size) };

        let item = QueuedDownloadItem {
            id,
            peer_name: peer_name.clone(),
            conn_ctx: ConnectionContext {
                ip: self.client_ip.clone(),
                port: self.client_port,
                password: self.ring_secret.trim().to_string(),
                peer_name: Some(peer_name.clone()),
            },
            is_mock: self.mock_session,
            entry: entry.clone(),
            remote_subpath,
            local_dest_dir: self.client_dest_folder.clone(),
            status: QueueItemStatus::Pending,
            started_at: None,
            elapsed_duration: None,
            completed_at: None,
            total_bytes,
        };

        self.download_queue.push_back(item);
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let kind = if entry.is_dir { "folder" } else { "file" };
        self.push_client_log(format!(
            "[{}] Queued {} '{}' from {}.",
            ts, kind, entry.name, peer_name
        ));

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_test_ui(
        ctx: &egui::Context,
        input: egui::RawInput,
        ui_fn: impl FnMut(&mut egui::Ui),
    ) -> egui::FullOutput {
        let mut out = ctx.run_ui(input, ui_fn);
        out.textures_delta.clear();
        out
    }

    fn collect_shape_texts(shape: &egui::epaint::Shape, out: &mut Vec<String>) {
        match shape {
            egui::epaint::Shape::Text(text_shape) => {
                out.push(text_shape.galley.text().to_string());
            }
            egui::epaint::Shape::Vec(shapes) => {
                for child in shapes {
                    collect_shape_texts(child, out);
                }
            }
            _ => {}
        }
    }

    fn collect_rendered_texts(output: &egui::FullOutput) -> Vec<String> {
        let mut texts = Vec::new();
        for clipped in &output.shapes {
            collect_shape_texts(&clipped.shape, &mut texts);
        }
        texts
    }

    #[test]
    fn test_app_icon_loads_correctly() {
        let icon = app_icon().expect("App icon should load from embedded assets");
        assert_eq!(icon.width, 256);
        assert_eq!(icon.height, 256);
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
    }

    #[test]
    fn test_palette_light_and_dark_contrast() {
        let light = AppPalette::new(false);
        assert!(!light.is_dark);
        assert_ne!(light.panel_bg, light.text_primary);
        // Light mode has light background and dark text
        assert!(light.panel_bg.r() > 200 && light.panel_bg.g() > 200 && light.panel_bg.b() > 200);
        assert!(
            light.text_primary.r() < 50
                && light.text_primary.g() < 50
                && light.text_primary.b() < 50
        );
        // Light mode browse alternating row stripe and hover highlight must have clear contrast
        let light_stripe_delta =
            (light.panel_bg.r() as i16 - light.browse_row_stripe_bg.r() as i16).abs();
        assert!(light_stripe_delta >= 12);
        assert_ne!(light.browse_row_hover_bg, light.panel_bg);
        assert_ne!(light.browse_row_hover_bg, light.browse_row_stripe_bg);
        assert!(light.browse_row_hover_bg.b() > light.browse_row_hover_bg.r() + 30);

        let dark = AppPalette::new(true);
        assert!(dark.is_dark);
        assert_ne!(dark.panel_bg, dark.text_primary);
        // Dark mode has dark background and light text
        assert!(dark.panel_bg.r() < 40 && dark.panel_bg.g() < 40 && dark.panel_bg.b() < 40);
        assert!(
            dark.text_primary.r() > 200
                && dark.text_primary.g() > 200
                && dark.text_primary.b() > 200
        );

        // ThemePreference defaults to Auto
        assert_eq!(ThemePreference::default(), ThemePreference::Auto);
    }

    #[test]
    fn test_close_confirmation_and_active_download_warnings() {
        use crate::server::SharedFolderRegistry;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let tokio_rt = tokio::runtime::Runtime::new().unwrap();
        let (server_log_tx, _server_log_rx) = tokio::sync::mpsc::unbounded_channel();
        let (prog_tx, _prog_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_client_action_tx, client_action_rx) = std::sync::mpsc::channel();
        let (_prog_std_tx, prog_std_rx) = std::sync::mpsc::channel();
        let (_server_log_std_tx, server_log_std_rx) = std::sync::mpsc::channel();

        let mut app = LanShareApp {
            tokio_rt,
            theme_preference: ThemePreference::Auto,
            last_applied_dark: None,
            secret_confirmed: true,
            test_mode: false,
            mock_session: false,
            current_tab: AppTab::Host,
            show_about: false,
            focus_about_window: false,
            ring_secret: "secret123".to_string(),
            show_secret_plain: false,
            local_ips: vec!["192.168.1.100".to_string()],
            host_folders: vec![],
            host_error: None,
            server_handle: None,
            server_logs: VecDeque::new(),
            server_log_rx: server_log_std_rx,
            server_log_tx,
            client_ip: String::new(),
            client_port: 4433,
            direct_ip_input: String::new(),
            selected_peer_name: String::new(),
            client_dest_folder: std::env::temp_dir(),
            client_error: None,
            discovered_peers: vec![],
            is_scanning: false,
            scan_rx: None,
            client_connected: false,
            client_connection_lost: false,
            connected_via_direct_ip: false,
            client_handshake: None,
            client_stream: None,
            client_current_path: String::new(),
            client_file_list: vec![],
            client_loading: false,
            client_action_rx,
            client_action_tx: _client_action_tx,
            next_queue_id: 1,
            download_queue: VecDeque::new(),
            keep_downloads_panel_visible: false,
            active_queue_id: None,
            active_progress: None,
            progress_finished_at: None,
            active_eta_stabilizer: EtaStabilizer::new(),
            total_eta_stabilizer: EtaStabilizer::new(),
            progress_rx: prog_std_rx,
            progress_tx: prog_tx,
            transfer_cancel_tx: None,
            client_logs: VecDeque::new(),
            show_log_window: false,
            focus_log_window: false,
            log_auto_scroll: true,
            log_source_filter: LogSourceFilter::All,
            clipboard: None,
            clipboard_flash: None,
            show_close_confirm_dialog: false,
            close_confirmed: false,
            show_stop_server_confirm_dialog: false,
            pending_remove_host_folder_idx: None,

            download_section_height: 220.0,

            browse_col_name_w: 260.0,

            hovered_browse_download_idx: None,
            hovered_host_remove_idx: None,
        };

        // 1. Initially, no active share or transfers: no close confirmation needed
        assert!(!app.needs_close_confirmation());
        assert_eq!(app.active_server_downloads(), 0);

        // 2. Mock an active ServerHandle
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
            registry_notify_tx: tokio::sync::watch::channel(0u64).0,
        };

        app.server_handle = Some(handle);

        // Hosting is active: close confirmation is required
        assert!(app.needs_close_confirmation());
        assert_eq!(app.active_server_downloads(), 0);

        // 3. A peer begins downloading from server
        active_downloads.store(1, Ordering::SeqCst);
        assert_eq!(app.active_server_downloads(), 1);
        assert!(app.needs_close_confirmation());

        // Stop server confirmation triggers when active downloads > 0
        if app.active_server_downloads() > 0 {
            app.show_stop_server_confirm_dialog = true;
        } else {
            app.stop_hosting_server();
        }
        assert!(app.show_stop_server_confirm_dialog);
        assert!(app.server_handle.is_some());

        // Confirming stop shuts down server
        app.show_stop_server_confirm_dialog = false;
        app.stop_hosting_server();
        assert!(app.server_handle.is_none());
        assert_eq!(app.active_server_downloads(), 0);

        // Peer finishes download
        active_downloads.store(0, Ordering::SeqCst);
        assert_eq!(app.active_server_downloads(), 0);

        // 4. Client download only (no hosting)
        assert!(!app.is_hosting_active());
        assert!(!app.has_active_client_downloads());
        assert!(!app.needs_close_confirmation());

        app.active_progress = Some(crate::client::TransferProgress {
            file_name: "test.iso".to_string(),
            bytes_done: 100,
            bytes_total: 1000,
            speed_mbps: 2.5,
            is_finished: false,
            current_file: 1,
            total_files: 1,
            selected_target: "test.iso".to_string(),
            log_message: None,
        });
        assert!(app.has_active_client_downloads());
        assert!(app.needs_close_confirmation());

        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            app.show_close_confirm_dialog = true;
            app.render_close_confirm_modal(ui.ctx());
        });
    }

    #[test]
    fn test_remove_last_host_folder_stops_sharing() {
        use crate::server::SharedFolderRegistry;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let base = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target");
        let pid = std::process::id();
        let dir_a = base.join(format!("lanshare_test_remove_last_a_{}", pid));
        let dir_b = base.join(format!("lanshare_test_remove_last_b_{}", pid));
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::create_dir_all(&dir_a);
        let _ = std::fs::create_dir_all(&dir_b);

        let mut app = create_test_app();
        app.host_folders = vec![dir_a.clone(), dir_b.clone()];

        let (stop_tx, _stop_rx) = tokio::sync::oneshot::channel();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let active_downloads = Arc::new(AtomicUsize::new(0));

        let active_folder_downloads =
            Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));

        app.server_handle = Some(crate::server::ServerHandle {
            is_running: Arc::new(AtomicBool::new(true)),
            local_ip: "192.168.1.100".to_string(),
            all_ips: vec!["192.168.1.100".to_string()],
            port: 22222,
            password: "secret123".to_string(),
            stop_sender: stop_tx,
            shared_folders: Arc::new(std::sync::RwLock::new(app.host_folders.clone())),
            duration_hours: None,
            registry: Arc::new(std::sync::RwLock::new(SharedFolderRegistry::new(
                app.host_folders.clone(),
            ))),
            log_tx,
            active_downloads: active_downloads.clone(),
            active_folder_downloads: active_folder_downloads.clone(),
            registry_notify_tx: tokio::sync::watch::channel(0u64).0,
        });

        // If dir_a has an active transfer while dir_b does not, removing dir_a prompts first
        active_folder_downloads.write().unwrap().insert(
            crate::security::clean_path(&dir_a.canonicalize().unwrap()),
            1,
        );
        app.remove_host_folder(0);
        assert_eq!(app.host_folders, vec![dir_a.clone(), dir_b.clone()]);
        assert!(app.show_stop_server_confirm_dialog);
        assert_eq!(app.pending_remove_host_folder_idx, Some(0));

        // Reset, then remove dir_b (idle) without prompting while dir_a keeps transferring
        app.show_stop_server_confirm_dialog = false;
        app.pending_remove_host_folder_idx = None;
        app.remove_host_folder(1);
        assert_eq!(app.host_folders, vec![dir_a.clone()]);
        assert!(!app.show_stop_server_confirm_dialog);
        assert!(app.server_handle.is_some());
        assert!(app.host_error.is_none());

        // Clear dir_a's folder map entry, set global active_downloads = 1 to test last-folder guard
        active_folder_downloads.write().unwrap().clear();
        active_downloads.store(1, Ordering::SeqCst);
        app.remove_host_folder(0);
        assert_eq!(app.host_folders, vec![dir_a.clone()]);
        assert!(app.show_stop_server_confirm_dialog);
        assert_eq!(app.pending_remove_host_folder_idx, Some(0));
        assert!(app.server_handle.is_some());

        // Reset modal & active download, then remove last folder cleanly
        app.show_stop_server_confirm_dialog = false;
        app.pending_remove_host_folder_idx = None;
        active_downloads.store(0, Ordering::SeqCst);

        app.remove_host_folder(0);
        assert!(app.host_folders.is_empty());
        assert!(app.server_handle.is_none());
        assert!(app.host_error.is_none());

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    fn create_test_app() -> LanShareApp {
        let tokio_rt = tokio::runtime::Runtime::new().unwrap();
        let (server_log_tx, _server_log_rx) = tokio::sync::mpsc::unbounded_channel();
        let (prog_tx, _prog_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_client_action_tx, client_action_rx) = std::sync::mpsc::channel();
        let (_prog_std_tx, prog_std_rx) = std::sync::mpsc::channel();
        let (_server_log_std_tx, server_log_std_rx) = std::sync::mpsc::channel();

        LanShareApp {
            tokio_rt,
            theme_preference: ThemePreference::Auto,
            last_applied_dark: None,
            secret_confirmed: false,
            test_mode: false,
            mock_session: false,
            current_tab: AppTab::Host,
            show_about: false,
            focus_about_window: false,
            ring_secret: String::new(),
            show_secret_plain: false,
            local_ips: vec!["192.168.1.100".to_string()],
            host_folders: vec![],
            host_error: None,
            server_handle: None,
            server_logs: VecDeque::new(),
            server_log_rx: server_log_std_rx,
            server_log_tx,
            client_ip: String::new(),
            client_port: 4433,
            direct_ip_input: String::new(),
            selected_peer_name: String::new(),
            client_dest_folder: std::env::temp_dir(),
            client_error: None,
            discovered_peers: vec![],
            is_scanning: false,
            scan_rx: None,
            client_connected: false,
            client_connection_lost: false,
            connected_via_direct_ip: false,
            client_handshake: None,
            client_stream: None,
            client_current_path: String::new(),
            client_file_list: vec![],
            client_loading: false,
            client_action_rx,
            client_action_tx: _client_action_tx,
            next_queue_id: 1,
            download_queue: VecDeque::new(),
            keep_downloads_panel_visible: false,
            active_queue_id: None,
            active_progress: None,
            progress_finished_at: None,
            active_eta_stabilizer: EtaStabilizer::new(),
            total_eta_stabilizer: EtaStabilizer::new(),
            progress_rx: prog_std_rx,
            progress_tx: prog_tx,
            transfer_cancel_tx: None,
            client_logs: VecDeque::new(),
            show_log_window: false,
            focus_log_window: false,
            log_auto_scroll: true,
            log_source_filter: LogSourceFilter::All,
            clipboard: None,
            clipboard_flash: None,
            show_close_confirm_dialog: false,
            close_confirmed: false,
            show_stop_server_confirm_dialog: false,
            pending_remove_host_folder_idx: None,

            download_section_height: 220.0,

            browse_col_name_w: 260.0,

            hovered_browse_download_idx: None,
            hovered_host_remove_idx: None,
        }
    }

    #[test]
    fn test_status_bar_messages_login_flow() {
        let mut app = create_test_app();
        let p = AppPalette::new(true);

        // 1. Initially empty secret on login
        app.secret_confirmed = false;
        app.ring_secret = String::new();
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "Enter Share-Ring secret to begin");
        assert_eq!(color, p.text_subtle);

        // 2. Secret too short (< MIN_SECRET_LEN chars)
        app.ring_secret = "abc".to_string();
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(
            msg,
            "Secret must be at least 10 characters (3 / 10 required)"
        );
        assert_eq!(color, p.accent_amber);

        // 3. Secret valid (>= 10 chars) - status bar remains clean without distracting filler text
        app.ring_secret = "secret1234".to_string();
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "");
        assert_eq!(color, p.text_subtle);
    }

    #[test]
    fn test_status_bar_messages_main_flow_and_copy_flash() {
        let mut app = create_test_app();
        app.secret_confirmed = true;
        let p = AppPalette::new(true);

        // 1. Default state on main page is quiet (empty)
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "");
        assert_eq!(color, p.text_subtle);

        // 2. Secret copy indicator flash
        app.set_status_flash("Copied LAN Secret!");
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "✓ Copied LAN Secret to clipboard");
        assert_eq!(color, p.accent_green);

        // 3. Logs copy indicator flash
        app.set_status_flash("Copied Logs!");
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "✓ Copied Logs to clipboard");
        assert_eq!(color, p.accent_green);

        // 4. Queue duplicate warning flash
        app.set_status_flash("'test.iso' is already in the download queue.");
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "ℹ 'test.iso' is already in the download queue.");
        assert_eq!(color, p.accent_amber);

        // 5. Expired flash reverts to underlying status (clean / empty)
        app.clipboard_flash = Some((
            "Copied LAN Secret!".to_string(),
            Instant::now() - Duration::from_millis(3000),
        ));
        let (msg, _) = app.current_status_message(&p);
        assert_eq!(msg, "");

        // 6. Scanning status
        app.clipboard_flash = None;
        app.is_scanning = true;
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "Scanning local network for computers...");
        assert_eq!(color, p.accent_blue);
        app.is_scanning = false;

        // 7. Error status
        app.client_error = Some("Failed to reach peer".to_string());
        let (msg, color) = app.current_status_message(&p);
        assert_eq!(msg, "Error: Failed to reach peer");
        assert_eq!(color, p.accent_red);
        app.client_error = None;

        // 8. Active progress status
        app.active_progress = Some(TransferProgress {
            selected_target: "downloads".to_string(),
            file_name: "archive.zip".to_string(),
            current_file: 1,
            total_files: 1,
            bytes_done: 50_000_000,
            bytes_total: 100_000_000,
            speed_mbps: 25.0,
            is_finished: false,
            log_message: None,
        });
        let (msg, color) = app.current_status_message(&p);
        assert!(msg.starts_with("↓ Downloading archive.zip: 50%"));
        assert_eq!(color, p.accent_blue);

        // 9. Network waiting/interrupted status during active transfer shows in amber on status bar
        app.active_progress.as_mut().unwrap().file_name =
            "Network interrupted — waiting to reconnect (attempt 2, next retry in 2s)".to_string();
        let (msg, color) = app.current_status_message(&p);
        assert!(msg.contains("downloads (50%)"));
        assert!(msg.contains("Network interrupted"));
        assert_eq!(color, p.accent_amber);
    }

    #[test]
    fn test_errors_clear_on_subsequent_user_actions() {
        let mut app = create_test_app();
        app.secret_confirmed = true;

        // 1. Navigating between tabs clears both host and client errors
        app.host_error = Some("Security Error: Cannot share home dir".to_string());
        app.client_error = Some("Failed to connect to 10.0.0.5".to_string());
        app.switch_tab(AppTab::Client);
        assert!(app.host_error.is_none());
        assert!(app.client_error.is_none());

        app.client_error = Some("Direct IP timed out".to_string());
        app.switch_tab(AppTab::Host);
        assert!(app.client_error.is_none());

        // 2. Stopping sharing clears stale host error
        app.host_error = Some("Some host validation error".to_string());
        app.stop_hosting_server();
        assert!(app.host_error.is_none());

        // 3. Scanning LAN clears stale direct IP / client errors
        app.client_error = Some("Connection refused".to_string());
        app.ring_secret = "secret1234".to_string();
        app.trigger_ring_scan();
        assert!(app.client_error.is_none());

        // 4. Starting a new connection clears stale errors
        app.client_error = Some("Previous direct IP failure".to_string());
        app.client_ip = "192.168.1.99".to_string();
        app.trigger_connect();
        assert!(app.client_error.is_none());

        // 5. Folder navigation / refresh clears stale errors
        app.client_error = Some("Listing failed".to_string());
        app.navigate_up();
        assert!(app.client_error.is_none());
    }

    #[test]
    fn test_mini_vector_icons_render() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let folder_resp =
                    LanShareApp::draw_mini_folder_icon(ui, Color32::from_rgb(37, 99, 235));
                assert_eq!(folder_resp.rect.width(), 15.0);
                assert_eq!(folder_resp.rect.height(), 12.0);

                LanShareApp::draw_mini_lock_icon(ui, Color32::GRAY);

                let dummy_rect =
                    egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(24.0, 24.0));
                LanShareApp::draw_mini_eye_icon_in_rect(ui, dummy_rect, Color32::GRAY, true);
                LanShareApp::draw_mini_eye_icon_in_rect(ui, dummy_rect, Color32::GRAY, false);
                LanShareApp::draw_mini_copy_icon_in_rect(ui, dummy_rect, Color32::GRAY);
                LanShareApp::draw_mini_pencil_icon_in_rect(ui, dummy_rect, Color32::GRAY);
                LanShareApp::draw_mini_open_window_icon_in_rect(ui, dummy_rect, Color32::GRAY);

                let btn_resp =
                    LanShareApp::draw_icon_button(ui, "Test tooltip", |ui, rect, color| {
                        LanShareApp::draw_mini_copy_icon_in_rect(ui, rect, color);
                    });
                assert_eq!(btn_resp.rect.width(), 28.0);
                assert_eq!(btn_resp.rect.height(), 26.0);
            });
        });
    }

    #[test]
    fn test_ring_secret_frame_bounds_in_left_rail() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.secret_confirmed = true;
            // Secret is hidden by default when logged in
            assert!(!app.show_secret_plain);
            app.render_main_left_rail(ui);

            // Default generated secret (19 chars) must fit on a single line in the widened rail
            let default_gen = generate_random_password();
            let gen_display = format_secret_display(&default_gen, true, 20);
            assert!(
                !gen_display.contains('\n'),
                "Default generated secret must fit on a single line"
            );

            // Test with a long secret to verify multi-line wrapping
            app.ring_secret = "super-long-custom-shared-secret-key-1234".to_string();
            app.show_secret_plain = true;
            let display = format_secret_display(&app.ring_secret, app.show_secret_plain, 20);
            assert!(
                display.contains('\n'),
                "Long secret must wrap into multi-line display"
            );
            app.render_main_left_rail(ui);
        });
    }

    #[test]
    fn test_gui_download_queue_panel_estimates() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.secret_confirmed = true;
            app.active_progress = Some(TransferProgress {
                selected_target: "Downloads".to_string(),
                file_name: "test.iso".to_string(),
                bytes_done: 50 * 1024 * 1024,
                bytes_total: 100 * 1024 * 1024,
                speed_mbps: 5.0,
                is_finished: false,
                current_file: 1,
                total_files: 1,
                log_message: None,
            });
            app.download_queue.push_back(QueuedDownloadItem {
                id: 1,
                peer_name: "Host-A".to_string(),
                conn_ctx: ConnectionContext {
                    ip: "192.168.1.10".to_string(),
                    port: 22222,
                    password: "secret".to_string(),
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
            app.download_queue.push_back(QueuedDownloadItem {
                id: 2,
                peer_name: "Host-A".to_string(),
                conn_ctx: ConnectionContext {
                    ip: "192.168.1.10".to_string(),
                    port: 22222,
                    password: "secret".to_string(),
                    peer_name: None,
                },
                is_mock: false,
                entry: FileEntry {
                    name: "bundle.tar".to_string(),
                    is_dir: false,
                    size: 300 * 1024 * 1024,
                    modified_timestamp: 0,
                },
                remote_subpath: "bundle.tar".to_string(),
                local_dest_dir: PathBuf::from("/tmp"),
                status: QueueItemStatus::Pending,
                started_at: None,
                elapsed_duration: None,
                completed_at: None,
                total_bytes: Some(300 * 1024 * 1024),
            });
            app.download_queue.push_back(QueuedDownloadItem {
                id: 3,
                peer_name: "Host-A".to_string(),
                conn_ctx: ConnectionContext {
                    ip: "192.168.1.10".to_string(),
                    port: 22222,
                    password: "secret".to_string(),
                    peer_name: None,
                },
                is_mock: false,
                entry: FileEntry {
                    name: "finished.zip".to_string(),
                    is_dir: false,
                    size: 50 * 1024 * 1024,
                    modified_timestamp: 0,
                },
                remote_subpath: "finished.zip".to_string(),
                local_dest_dir: PathBuf::from("/tmp"),
                status: QueueItemStatus::Completed,
                started_at: None,
                elapsed_duration: Some(Duration::from_secs(12)),
                completed_at: Some(Local::now()),
                total_bytes: Some(50 * 1024 * 1024),
            });
            // Item 4: Completed folder with entry.size == 0, resolved via total_bytes
            app.download_queue.push_back(QueuedDownloadItem {
                id: 4,
                peer_name: "Host-A".to_string(),
                conn_ctx: ConnectionContext {
                    ip: "192.168.1.10".to_string(),
                    port: 22222,
                    password: "secret".to_string(),
                    peer_name: None,
                },
                is_mock: false,
                entry: FileEntry {
                    name: "AssetsFolder".to_string(),
                    is_dir: true,
                    size: 0,
                    modified_timestamp: 0,
                },
                remote_subpath: "AssetsFolder".to_string(),
                local_dest_dir: PathBuf::from("/tmp"),
                status: QueueItemStatus::Completed,
                started_at: None,
                elapsed_duration: Some(Duration::from_secs(4)),
                completed_at: Some(Local::now()),
                total_bytes: Some(85 * 1024 * 1024),
            });

            egui::CentralPanel::default().show(ui, |ui| {
                app.render_download_queue_panel(ui, 200.0);
            });
            assert!(app.active_eta_stabilizer.current().is_some());
            assert_eq!(app.active_eta_stabilizer.current(), Some(10));
        });
    }

    #[test]
    fn test_gui_download_queue_hides_duplicate_active_row() {
        let make_item = |id: u64, name: &str, status: QueueItemStatus| QueuedDownloadItem {
            id,
            peer_name: "Host-A".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.10".to_string(),
                port: 22222,
                password: "secret".to_string(),
                peer_name: None,
            },
            is_mock: false,
            entry: FileEntry {
                name: name.to_string(),
                is_dir: false,
                size: 100 * 1024 * 1024,
                modified_timestamp: 0,
            },
            remote_subpath: name.to_string(),
            local_dest_dir: PathBuf::from("/tmp"),
            status,
            started_at: None,
            elapsed_duration: Some(Duration::from_secs(5)),
            completed_at: None,
            total_bytes: Some(100 * 1024 * 1024),
        };

        let mut app = create_test_app();
        app.secret_confirmed = true;
        app.active_queue_id = Some(1);
        app.active_progress = Some(TransferProgress {
            selected_target: "movie.mkv".to_string(),
            file_name: "movie.mkv".to_string(),
            bytes_done: 50 * 1024 * 1024,
            bytes_total: 100 * 1024 * 1024,
            speed_mbps: 10.0,
            is_finished: false,
            current_file: 1,
            total_files: 1,
            log_message: None,
        });
        app.download_queue
            .push_back(make_item(1, "movie.mkv", QueueItemStatus::Downloading));
        app.download_queue
            .push_back(make_item(2, "next.zip", QueueItemStatus::Pending));

        let ctx = egui::Context::default();
        let active_out = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_download_queue_panel(ui, 220.0);
            });
        });
        let active_texts = collect_rendered_texts(&active_out);
        assert_eq!(
            active_texts
                .iter()
                .filter(|t| *t == "movie.mkv (Host-A)")
                .count(),
            1,
            "Active download must show target + server name once in progress section: {:?}",
            active_texts
        );
        assert!(
            !active_texts.iter().any(|t| t == "Active"),
            "Queue list must not render duplicate 'Active' badge while progress bar is shown: {:?}",
            active_texts
        );
        assert!(active_texts.iter().any(|t| t == "Queued"));
        assert!(active_texts.iter().any(|t| t == "next.zip (Host-A)"));

        // Network interruption messages must not render on the active target line (shown in status bar instead).
        app.active_progress.as_mut().unwrap().file_name =
            "Network interrupted — waiting to reconnect (attempt 1, next retry in 1s)".to_string();
        let waiting_out = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_download_queue_panel(ui, 220.0);
            });
        });
        let waiting_texts = collect_rendered_texts(&waiting_out);
        assert!(
            !waiting_texts
                .iter()
                .any(|t| t.contains("Network interrupted")),
            "Network error text must not overlap active download row: {:?}",
            waiting_texts
        );

        // Once the active download completes, it moves to Done in the queue list.
        app.active_queue_id = None;
        app.active_progress = None;
        app.download_queue[0].status = QueueItemStatus::Completed;
        let done_out = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_download_queue_panel(ui, 220.0);
            });
        });
        let done_texts = collect_rendered_texts(&done_out);
        assert!(done_texts.iter().any(|t| t == "Done"));
        assert!(done_texts.iter().any(|t| t == "movie.mkv (Host-A)"));
    }

    fn count_vertical_scrollbar_tracks(output: &egui::FullOutput) -> usize {
        fn count_in_shape(shape: &egui::epaint::Shape) -> usize {
            match shape {
                egui::epaint::Shape::Rect(rect_shape) => {
                    let size = rect_shape.rect.size();
                    if (size.x - 10.0).abs() < 1.5 && size.y > 40.0 {
                        1
                    } else {
                        0
                    }
                }
                egui::epaint::Shape::Vec(shapes) => shapes.iter().map(count_in_shape).sum(),
                _ => 0,
            }
        }

        output.shapes.iter().map(|c| count_in_shape(&c.shape)).sum()
    }

    #[test]
    fn test_cancel_all_keeps_done_and_downloads_panel_visible() {
        let make_item = |id: u64, name: &str, status: QueueItemStatus| QueuedDownloadItem {
            id,
            peer_name: "Host-A".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.10".to_string(),
                port: 22222,
                password: "secret".to_string(),
                peer_name: None,
            },
            is_mock: false,
            entry: FileEntry {
                name: name.to_string(),
                is_dir: false,
                size: 1024,
                modified_timestamp: 0,
            },
            remote_subpath: name.to_string(),
            local_dest_dir: PathBuf::from("/tmp"),
            status,
            started_at: None,
            elapsed_duration: Some(Duration::from_secs(2)),
            completed_at: None,
            total_bytes: Some(1024),
        };

        // Case 1: Active + Queued + Done -> Cancel All removes Active & Queued, keeps Done.
        let mut app = create_test_app();
        app.secret_confirmed = true;
        app.active_queue_id = Some(2);
        app.active_progress = Some(TransferProgress {
            selected_target: "active.bin".to_string(),
            file_name: "active.bin".to_string(),
            bytes_done: 512,
            bytes_total: 1024,
            speed_mbps: 1.0,
            is_finished: false,
            current_file: 1,
            total_files: 1,
            log_message: None,
        });
        app.download_queue
            .push_back(make_item(1, "done.zip", QueueItemStatus::Completed));
        app.download_queue
            .push_back(make_item(2, "active.bin", QueueItemStatus::Downloading));
        app.download_queue
            .push_back(make_item(3, "queued.tar", QueueItemStatus::Pending));

        app.cancel_all_downloads();
        assert!(app.active_progress.is_none());
        assert!(app.active_queue_id.is_none());
        assert_eq!(app.download_queue.len(), 1);
        assert_eq!(app.download_queue[0].entry.name, "done.zip");
        assert_eq!(app.download_queue[0].status, QueueItemStatus::Completed);
        assert!(app.keep_downloads_panel_visible);

        let ctx = egui::Context::default();
        let out_with_done = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
            });
        });
        let texts_with_done = collect_rendered_texts(&out_with_done);
        assert!(
            texts_with_done
                .iter()
                .any(|t| t == "Downloads — Active: 0 | Queued: 0 | Done: 1"),
            "{:?}",
            texts_with_done
        );
        assert!(texts_with_done.iter().any(|t| t == "done.zip (Host-A)"));

        // Case 2: Only Active + Queued (0 Done) -> Cancel All empties queue but keeps Downloads section visible.
        let mut app_empty = create_test_app();
        app_empty.secret_confirmed = true;
        app_empty.active_queue_id = Some(10);
        app_empty.active_progress = Some(TransferProgress {
            selected_target: "only_active.bin".to_string(),
            file_name: "only_active.bin".to_string(),
            bytes_done: 128,
            bytes_total: 1024,
            speed_mbps: 1.0,
            is_finished: false,
            current_file: 1,
            total_files: 1,
            log_message: None,
        });
        app_empty.download_queue.push_back(make_item(
            10,
            "only_active.bin",
            QueueItemStatus::Downloading,
        ));
        app_empty.download_queue.push_back(make_item(
            11,
            "only_queued.bin",
            QueueItemStatus::Pending,
        ));

        app_empty.cancel_all_downloads();
        assert!(app_empty.download_queue.is_empty());
        assert!(app_empty.keep_downloads_panel_visible);

        let out_empty_panel = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app_empty.render_client_browser_panel(ui);
            });
        });
        let texts_empty_panel = collect_rendered_texts(&out_empty_panel);
        assert!(
            texts_empty_panel
                .iter()
                .any(|t| t == "Downloads — Active: 0 | Queued: 0 | Done: 0"),
            "Downloads panel must stay visible after Cancel All even with 0 items: {:?}",
            texts_empty_panel
        );
    }

    #[test]
    fn test_scrollbars_hidden_when_empty_and_visible_when_populated() {
        // Browse panel: no host selected -> no scrollbar; host selected -> visible scrollbar.
        let mut app_no_host = create_test_app();
        app_no_host.secret_confirmed = true;
        let ctx_browse_empty = egui::Context::default();
        let _ = run_test_ui(&ctx_browse_empty, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app_no_host.render_client_browser_panel(ui);
            });
        });
        let browse_empty_out = run_test_ui(&ctx_browse_empty, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app_no_host.render_client_browser_panel(ui);
            });
        });
        assert_eq!(
            count_vertical_scrollbar_tracks(&browse_empty_out),
            0,
            "Browse scrollbar must be hidden until a host is selected"
        );

        let mut app_with_host = create_test_app();
        app_with_host.secret_confirmed = true;
        app_with_host.client_connected = true;
        app_with_host.client_file_list = vec![FileEntry {
            name: "sample.txt".to_string(),
            is_dir: false,
            size: 100,
            modified_timestamp: 1700000000,
        }];
        let ctx_browse_host = egui::Context::default();
        let _ = run_test_ui(&ctx_browse_host, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app_with_host.render_client_browser_panel(ui);
            });
        });
        let browse_host_out = run_test_ui(&ctx_browse_host, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app_with_host.render_client_browser_panel(ui);
            });
        });
        assert!(
            count_vertical_scrollbar_tracks(&browse_host_out) >= 1,
            "Browse scrollbar must be visible once a host is selected"
        );

        // Activity Log window: no log lines -> no scrollbar; with log lines -> visible scrollbar.
        let mut app_empty_logs = create_test_app();
        app_empty_logs.show_log_window = true;
        let ctx_logs_empty = egui::Context::default();
        let _ = run_test_ui(&ctx_logs_empty, Default::default(), |ui| {
            app_empty_logs.render_log_window(ui.ctx());
        });
        let log_empty_out = run_test_ui(&ctx_logs_empty, Default::default(), |ui| {
            app_empty_logs.render_log_window(ui.ctx());
        });
        assert_eq!(
            count_vertical_scrollbar_tracks(&log_empty_out),
            0,
            "Log window scrollbar must be hidden when there are no log lines"
        );

        let mut app_with_logs = create_test_app();
        app_with_logs.show_log_window = true;
        app_with_logs
            .client_logs
            .push_back("Sample client log entry".to_string());
        let ctx_logs_pop = egui::Context::default();
        let _ = run_test_ui(&ctx_logs_pop, Default::default(), |ui| {
            app_with_logs.render_log_window(ui.ctx());
        });
        let log_populated_out = run_test_ui(&ctx_logs_pop, Default::default(), |ui| {
            app_with_logs.render_log_window(ui.ctx());
        });
        assert!(
            count_vertical_scrollbar_tracks(&log_populated_out) >= 1,
            "Log window scrollbar must be visible when log lines exist"
        );
    }

    #[test]
    fn test_gui_eta_stabilizer_active_download() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.secret_confirmed = true;
            app.active_queue_id = Some(10);
            app.active_progress = Some(TransferProgress {
                selected_target: "LargeFile.zip".to_string(),
                file_name: "LargeFile.zip".to_string(),
                bytes_done: 0,
                bytes_total: 300 * 1024 * 1024,
                speed_mbps: 1.0, // 300s remaining = 5m (> 2m)
                is_finished: false,
                current_file: 1,
                total_files: 1,
                log_message: None,
            });

            egui::CentralPanel::default().show(ui, |ui| {
                app.render_download_queue_panel(ui, 200.0);
            });

            // Initial render caches 300s (5m)
            assert_eq!(app.active_eta_stabilizer.current(), Some(300));

            // Instantaneous speed fluctuation on next frame (speed drops to 0.5 MB/s -> 600s)
            // Stabilizer should ignore fluctuation within the 4s slow-polling window:
            if let Some(ref mut p) = app.active_progress {
                p.speed_mbps = 0.5;
            }
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_download_queue_panel(ui, 200.0);
            });
            assert_eq!(
                app.active_eta_stabilizer.current(),
                Some(300),
                "ETA should hold cached value and not jump"
            );

            // When ETA drops under 1 minute (e.g. 50 MB at 1 MB/s = 50s):
            if let Some(ref mut p) = app.active_progress {
                p.bytes_done = 250 * 1024 * 1024;
                p.speed_mbps = 1.0;
            }
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_download_queue_panel(ui, 200.0);
            });
            assert_eq!(
                app.active_eta_stabilizer.current(),
                Some(50),
                "ETA should immediately transition to under 1m countdown"
            );
        });
    }

    #[test]
    fn test_render_client_view_and_direct_ip_tip() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.secret_confirmed = true;
            app.client_connected = true;
            app.client_ip = "192.168.1.50".to_string();
            app.discovered_peers = vec![
                DiscoveredPeer {
                    host_name: "Office-PC".to_string(),
                    ip: "192.168.1.50".to_string(),
                    port: DEFAULT_TCP_PORT,
                    last_seen: Instant::now(),
                },
                DiscoveredPeer {
                    host_name: "Alice-Laptop".to_string(),
                    ip: "mock://alice".to_string(),
                    port: DEFAULT_TCP_PORT,
                    last_seen: Instant::now(),
                },
            ];
            app.render_client_view(ui);
        });
    }

    #[test]
    fn test_render_client_browser_with_folders_and_hover_underline() {
        let ctx = egui::Context::default();
        let mut app = create_test_app();
        app.secret_confirmed = true;
        app.client_connected = true;
        app.client_file_list = vec![
            FileEntry {
                name: "Documents".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: 1600000000,
            },
            FileEntry {
                name: "photo.jpg".to_string(),
                is_dir: false,
                size: 1024 * 1024,
                modified_timestamp: 1600000000,
            },
        ];
        // Hover over Name, Size, and Modified cells and verify cursor remains Default (arrow), never Text (I-beam)
        let size_x = app.browse_col_name_w + 50.0;
        let date_x = app.browse_col_name_w + BROWSE_COL_SIZE_W + 70.0;
        for x in [50.0_f32, size_x, date_x] {
            for y in [115.0_f32, 130.0, 145.0, 160.0] {
                let input = egui::RawInput {
                    events: vec![egui::Event::PointerMoved(egui::pos2(x, y))],
                    ..Default::default()
                };
                let out = run_test_ui(&ctx, input, |ui| {
                    egui::CentralPanel::default().show(ui, |ui| {
                        app.render_client_browser_panel(ui);
                    });
                });
                assert_eq!(out.platform_output.cursor_icon, egui::CursorIcon::Default);
            }
        }
    }

    #[test]
    fn test_download_header_row_baseline_and_icon_alignment() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let prompt_galley = egui::WidgetText::from(
                    RichText::new("Save downloads to:").size(13.5),
                )
                .into_galley(
                    ui,
                    Some(egui::TextWrapMode::Extend),
                    f32::INFINITY,
                    egui::TextStyle::Body,
                );
                let path_galley = egui::WidgetText::from(
                    RichText::new(r"C:\Users\Demo\Downloads")
                        .size(13.5)
                        .strong(),
                )
                .into_galley(
                    ui,
                    Some(egui::TextWrapMode::Extend),
                    f32::INFINITY,
                    egui::TextStyle::Body,
                );

                let row_rect = egui::Rect::from_min_size(
                    egui::pos2(20.0, 40.0),
                    egui::vec2(500.0, 24.0),
                );
                let btn_size = egui::vec2(28.0, 26.0);
                let (prompt_pos, path_pos, pencil_rect) = LanShareApp::compute_download_header_layout(
                    row_rect,
                    &prompt_galley,
                    &path_galley,
                    8.0,
                    btn_size,
                );

                let prompt_baseline = prompt_pos.y + LanShareApp::galley_baseline_y(&prompt_galley);
                let path_baseline = path_pos.y + LanShareApp::galley_baseline_y(&path_galley);
                assert!(
                    (prompt_baseline - path_baseline).abs() < 0.01,
                    "Expected shared baseline: prompt={prompt_baseline}, path={path_baseline}"
                );

                let prompt_ink_center =
                    prompt_pos.y + LanShareApp::galley_ink_center_y(&prompt_galley);
                assert!(
                    (prompt_ink_center - pencil_rect.center().y).abs() < 0.01,
                    "Expected prompt visual center ({prompt_ink_center}) to match pencil button center ({})",
                    pencil_rect.center().y
                );
                assert_eq!(pencil_rect.size(), btn_size);
                assert_eq!(path_pos.x, row_rect.left() + prompt_galley.size().x + 8.0);
                assert_eq!(pencil_rect.left(), path_pos.x + path_galley.size().x + 8.0);
            });
        });
    }

    #[test]
    fn test_cancel_download_removes_from_queue_and_autostart_sharing() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut app = create_test_app();
        app.secret_confirmed = true;
        app.ring_secret = "secret1234".to_string();

        // 1. Queue a download and start it
        app.download_queue.push_back(QueuedDownloadItem {
            id: 1,
            peer_name: "Host-A".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.10".to_string(),
                port: 22222,
                password: "secret".to_string(),
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
        app.active_queue_id = Some(1);

        // Cancel the active transfer: should immediately be removed from queue
        app.cancel_active_transfer();
        assert!(app.download_queue.is_empty());
        assert!(app.active_queue_id.is_none());

        // 2. Autostart sharing when first folder is added
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                // When host_folders is empty, render_host_tab should not display Start Sharing button
                app.render_host_tab(ui);
            });
        });

        let base = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target");
        let temp_share = base.join(format!("lanshare_autostart_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_share);
        app.host_folders.push(temp_share.clone());
        assert!(app.server_handle.is_none());
        app.start_hosting_server();
        assert!(app.server_handle.is_some());
        app.stop_hosting_server();
        assert!(app.server_handle.is_none());
        assert!(!app.host_folders.is_empty());

        // When stopped but folders exist (explicitly stopped), render_host_tab shows Start Sharing button
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_host_tab(ui);
            });
        });

        let _ = std::fs::remove_dir_all(&temp_share);
    }

    #[test]
    fn test_ring_secret_change_disabled_when_hosting_or_downloading() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::Arc;

        let mut app = create_test_app();
        app.secret_confirmed = true;

        // 1. Initially idle: changing secret is allowed
        assert!(app.can_change_secret());

        // 2. Active client download via active_progress: changing secret disabled
        app.active_progress = Some(TransferProgress {
            selected_target: "Downloads".to_string(),
            file_name: "test.iso".to_string(),
            bytes_done: 1024,
            bytes_total: 2048,
            speed_mbps: 1.0,
            is_finished: false,
            current_file: 1,
            total_files: 1,
            log_message: None,
        });
        assert!(app.has_active_client_downloads());
        assert!(!app.can_change_secret());

        // 3. Finished progress: allowed again
        app.active_progress.as_mut().unwrap().is_finished = true;
        assert!(!app.has_active_client_downloads());
        assert!(app.can_change_secret());

        // 4. Active download via active_queue_id: disabled
        app.active_queue_id = Some(42);
        assert!(app.has_active_client_downloads());
        assert!(!app.can_change_secret());
        app.active_queue_id = None;
        assert!(app.can_change_secret());

        // 5. Active download via pending/downloading queue item: disabled
        app.download_queue.push_back(QueuedDownloadItem {
            id: 1,
            peer_name: "Peer".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.5".to_string(),
                port: 22222,
                password: "pass".to_string(),
                peer_name: None,
            },
            is_mock: false,
            entry: FileEntry {
                name: "file.bin".to_string(),
                is_dir: false,
                size: 100,
                modified_timestamp: 0,
            },
            remote_subpath: "file.bin".to_string(),
            local_dest_dir: std::path::PathBuf::from("/tmp"),
            status: QueueItemStatus::Pending,
            started_at: None,
            elapsed_duration: None,
            completed_at: None,
            total_bytes: Some(100),
        });
        assert!(app.has_active_client_downloads());
        assert!(!app.can_change_secret());

        app.download_queue.clear();
        assert!(app.can_change_secret());

        // 6. Hosting active: disabled
        let (stop_tx, _) = tokio::sync::oneshot::channel();
        let (log_tx, _) = tokio::sync::mpsc::unbounded_channel();
        app.server_handle = Some(ServerHandle {
            is_running: Arc::new(AtomicBool::new(true)),
            local_ip: "192.168.1.10".to_string(),
            all_ips: vec!["192.168.1.10".to_string()],
            port: 22222,
            password: "secret".to_string(),
            stop_sender: stop_tx,
            shared_folders: Arc::new(std::sync::RwLock::new(vec![])),
            duration_hours: None,
            registry: Arc::new(std::sync::RwLock::new(
                crate::server::SharedFolderRegistry::new(vec![]),
            )),
            log_tx,
            active_downloads: Arc::new(AtomicUsize::new(0)),
            active_folder_downloads: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            registry_notify_tx: tokio::sync::watch::channel(0u64).0,
        });
        assert!(app.is_hosting_active());
        assert!(!app.can_change_secret());
    }

    #[test]
    fn test_shared_folders_link_and_hover_highlight() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.secret_confirmed = true;
            app.host_folders.push(PathBuf::from("/tmp/test_share_a"));
            app.host_folders.push(PathBuf::from("/tmp/test_share_b"));

            // Set remove hover on first folder
            app.hovered_host_remove_idx = Some(0);

            egui::CentralPanel::default().show(ui, |ui| {
                app.render_host_tab(ui);
            });
        });
    }

    #[test]
    fn test_browse_table_download_hover_highlight() {
        let ctx = egui::Context::default();
        let mut app = create_test_app();
        app.secret_confirmed = true;
        app.client_connected = true;
        app.client_file_list = vec![
            FileEntry {
                name: "Massive_Assets_25k_Files".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: 1700000000,
            },
            FileEntry {
                name: "document.pdf".to_string(),
                is_dir: false,
                size: 1024 * 1024,
                modified_timestamp: 1700000000,
            },
        ];

        // Frame 1: let Grid measure layout and locate row 0's Download button
        let raw_input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 800.0),
            )),
            ..Default::default()
        };
        let warmup = run_test_ui(&ctx, raw_input.clone(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
            });
        });
        let mut dl_centers = Vec::new();
        fn collect_dl_centers(shape: &egui::epaint::Shape, out: &mut Vec<egui::Pos2>) {
            match shape {
                egui::epaint::Shape::Text(t) if t.galley.text() == "Download" => {
                    out.push(egui::Rect::from_min_size(t.pos, t.galley.size()).center());
                }
                egui::epaint::Shape::Vec(v) => {
                    for s in v {
                        collect_dl_centers(s, out);
                    }
                }
                _ => {}
            }
        }
        for c in &warmup.shapes {
            collect_dl_centers(&c.shape, &mut dl_centers);
        }
        assert!(!dl_centers.is_empty(), "Expected Download button in warmup");

        // Frame 2 & 3: hover pointer over row 0's Download button -> hover index updates and paints
        let hover_input = egui::RawInput {
            screen_rect: raw_input.screen_rect,
            events: vec![egui::Event::PointerMoved(dl_centers[0])],
            ..Default::default()
        };
        let _ = run_test_ui(&ctx, hover_input.clone(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
            });
        });
        let output = run_test_ui(&ctx, hover_input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
            });
        });
        assert_eq!(app.hovered_browse_download_idx, Some(0));

        let expected_color = app.palette(&ctx).browse_row_hover_bg;
        let expected_max_w = app.browse_col_name_w
            + BROWSE_COL_SIZE_W
            + BROWSE_COL_DATE_W
            + BROWSE_COL_ACTION_W
            + (3.0 * 16.0)
            - 6.0;
        let mut hover_rects = Vec::new();
        let mut dl_btn_rects = Vec::new();
        fn collect_rects(
            shape: &egui::epaint::Shape,
            color: Color32,
            out: &mut Vec<egui::Rect>,
            dl: &mut Vec<egui::Rect>,
        ) {
            match shape {
                egui::epaint::Shape::Rect(r) if r.fill == color => out.push(r.rect),
                egui::epaint::Shape::Text(t) if t.galley.text() == "Download" => {
                    dl.push(egui::Rect::from_min_size(t.pos, t.galley.size()));
                }
                egui::epaint::Shape::Vec(v) => {
                    for s in v {
                        collect_rects(s, color, out, dl);
                    }
                }
                _ => {}
            }
        }
        for c in &output.shapes {
            collect_rects(
                &c.shape,
                expected_color,
                &mut hover_rects,
                &mut dl_btn_rects,
            );
        }
        assert_eq!(hover_rects.len(), 1);
        assert!(
            (hover_rects[0].width() - expected_max_w).abs() < 1.0,
            "Browse hover highlight width ({}) must stop at table content ({}) rather than spanning wide panel",
            hover_rects[0].width(),
            expected_max_w
        );
        assert!(
            hover_rects[0].right() <= dl_btn_rects[0].right() + 8.0,
            "Highlight right ({}) must not extend past Download button ({})",
            hover_rects[0].right(),
            dl_btn_rects[0].right() + 8.0
        );
    }

    #[test]
    fn test_browse_table_resizable_columns() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.secret_confirmed = true;
            app.client_connected = true;
            app.client_file_list = vec![
                FileEntry {
                    name: "sample_extremely_long_filename_that_exceeds_normal_column_width_to_test_truncation.txt".to_string(),
                    is_dir: false,
                    size: 4096,
                    modified_timestamp: 1700000000,
                },
                FileEntry {
                    name: "Long_Folder_Name_That_Should_Truncate".to_string(),
                    is_dir: true,
                    size: 0,
                    modified_timestamp: 1700000000,
                },
            ];

            assert_eq!(app.browse_col_name_w, 260.0);
            assert_eq!(BROWSE_COL_SIZE_W, 85.0);
            assert_eq!(BROWSE_COL_DATE_W, 135.0);

            // Adjust name column width smaller than long text to test truncation
            app.browse_col_name_w = 120.0;

            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
            });

            assert_eq!(app.browse_col_name_w, 120.0);

            // Now expand wider
            app.browse_col_name_w = 400.0;
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
            });

            assert_eq!(app.browse_col_name_w, 400.0);
        });
    }

    #[test]
    fn test_visible_scroll_style_properties() {
        let style = LanShareApp::visible_scroll_style();
        assert!(
            !style.floating,
            "Scrollbar must be solid/non-floating to avoid overlapping and auto-hiding"
        );
        assert_eq!(style.bar_width, 10.0);
        assert!(
            style.foreground_color,
            "Must use foreground contrast color for thumb visibility"
        );
        assert_eq!(
            style.dormant_handle_opacity, 1.0,
            "Handle must remain 100% visible even when dormant"
        );
        assert_eq!(
            style.dormant_background_opacity, 1.0,
            "Track must remain 100% visible even when dormant"
        );

        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.secret_confirmed = true;
            app.client_connected = true;
            app.client_file_list = vec![FileEntry {
                name: "file.txt".to_string(),
                is_dir: false,
                size: 1024,
                modified_timestamp: 1700000000,
            }];
            app.host_folders.push(PathBuf::from("/tmp/share"));
            app.show_log_window = true;
            app.client_logs.push_back("Log line 1".to_string());
            app.download_queue.push_back(QueuedDownloadItem {
                id: 1,
                peer_name: "Host-A".to_string(),
                conn_ctx: ConnectionContext {
                    ip: "192.168.1.10".to_string(),
                    port: 22222,
                    password: "secret".to_string(),
                    peer_name: None,
                },
                is_mock: false,
                entry: FileEntry {
                    name: "queued.zip".to_string(),
                    is_dir: false,
                    size: 2048,
                    modified_timestamp: 0,
                },
                remote_subpath: "queued.zip".to_string(),
                local_dest_dir: PathBuf::from("/tmp"),
                status: QueueItemStatus::Pending,
                started_at: None,
                elapsed_duration: None,
                completed_at: None,
                total_bytes: None,
            });

            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
                app.render_download_queue_panel(ui, 160.0);
                app.render_host_tab(ui);
            });
            app.render_log_window(ui.ctx());
        });
    }

    #[test]
    fn test_activity_log_window_filters_and_spooling_link() {
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            let mut app = create_test_app();
            app.show_log_window = true;
            assert_eq!(app.log_source_filter, LogSourceFilter::All);

            app.client_logs
                .push_back("Downloaded 'test.bin' (1 MB)".to_string());
            app.server_logs.push_back(ServerLogEvent {
                timestamp: "12:00:00".to_string(),
                message: "Peer connected".to_string(),
                is_error: false,
            });

            // Render with All filter
            app.render_log_window(ui.ctx());

            // Switch to Client filter
            app.log_source_filter = LogSourceFilter::Client;
            app.render_log_window(ui.ctx());

            // Switch to Server filter
            app.log_source_filter = LogSourceFilter::Server;
            app.render_log_window(ui.ctx());
        });
    }

    #[test]
    fn test_connection_loss_preserves_files_and_blocks_navigation_and_actions() {
        let mut app = create_test_app();
        app.secret_confirmed = true;
        app.client_connected = true;
        app.client_ip = "192.168.1.50".to_string();
        app.selected_peer_name = "Office-PC".to_string();
        app.client_current_path = "Docs".to_string();
        app.client_file_list = vec![
            FileEntry {
                name: "SubFolder".to_string(),
                is_dir: true,
                size: 0,
                modified_timestamp: 1700000000,
            },
            FileEntry {
                name: "report.pdf".to_string(),
                is_dir: false,
                size: 2048,
                modified_timestamp: 1700000000,
            },
        ];
        app.download_queue.push_back(QueuedDownloadItem {
            id: 1,
            peer_name: "Office-PC".to_string(),
            conn_ctx: ConnectionContext {
                ip: "192.168.1.50".to_string(),
                port: DEFAULT_TCP_PORT,
                password: "secret".to_string(),
                peer_name: None,
            },
            is_mock: false,
            entry: app.client_file_list[1].clone(),
            remote_subpath: "Docs/report.pdf".to_string(),
            local_dest_dir: std::env::temp_dir(),
            status: QueueItemStatus::Completed,
            started_at: None,
            elapsed_duration: Some(Duration::from_secs(1)),
            completed_at: Some(Local::now()),
            total_bytes: Some(2048),
        });

        // 1. If connected via Direct IP, a UDP scan returning empty must not kill the session
        app.connected_via_direct_ip = true;
        let (scan_tx, scan_rx) = std::sync::mpsc::channel();
        scan_tx.send(Vec::new()).unwrap();
        app.scan_rx = Some(scan_rx);
        app.poll_scan_results();
        assert!(!app.client_connection_lost);

        // 2. If discovered via LAN scan and host disappears on next scan:
        //    connection becomes lost, but files, path, and downloads remain visible
        app.connected_via_direct_ip = false;
        let (scan_tx2, scan_rx2) = std::sync::mpsc::channel();
        scan_tx2.send(Vec::new()).unwrap();
        app.scan_rx = Some(scan_rx2);
        app.poll_scan_results();

        assert!(app.client_connection_lost);
        assert!(app.client_error.is_some());
        assert!(app.client_error.as_deref().unwrap().contains("Office-PC"));
        assert_eq!(app.client_current_path, "Docs");
        assert_eq!(app.client_file_list.len(), 2);
        assert_eq!(app.download_queue.len(), 1);

        // 3. Navigating into folder, navigating up, refreshing, or queueing downloads
        //    when unavailable must NOT append/change path or queue items, and must show error
        app.clear_errors();
        app.navigate_into("SubFolder");
        assert_eq!(app.client_current_path, "Docs");
        assert!(app.client_error.is_some());

        app.clear_errors();
        app.navigate_up();
        assert_eq!(app.client_current_path, "Docs");
        assert!(app.client_error.is_some());

        app.clear_errors();
        app.refresh_client_listing();
        assert!(app.client_error.is_some());

        app.clear_errors();
        let new_file = FileEntry {
            name: "other.bin".to_string(),
            is_dir: false,
            size: 100,
            modified_timestamp: 1700000000,
        };
        app.enqueue_download(new_file);
        assert_eq!(app.download_queue.len(), 1);
        assert!(app.client_error.is_some());

        // 4. ListingFailed with transport loss marks unavailable and preserves view
        app.client_connection_lost = false;
        let _ = app.client_action_tx.send(ClientActionResult::ListingFailed(
            None,
            "Host is not responding (connection timed out)".to_string(),
        ));
        app.poll_client_action_results();
        assert!(app.client_connection_lost);
        assert_eq!(app.client_current_path, "Docs");
        assert_eq!(app.client_file_list.len(), 2);

        // 5. ConnectFailed while file list is displayed preserves file list & marks lost
        let _ = app.client_action_tx.send(ClientActionResult::ConnectFailed(
            "Connection refused".to_string(),
        ));
        app.poll_client_action_results();
        assert!(app.client_connection_lost);
        assert_eq!(app.client_file_list.len(), 2);
        assert_eq!(app.download_queue.len(), 1);

        // 6. Browser panel still renders safely with file list in unavailable state
        let ctx = egui::Context::default();
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_client_browser_panel(ui);
            });
        });

        // 7. Reconnecting clears connection lost state
        app.connect_mock_session("Office-PC", "mock://office-pc");
        assert!(!app.client_connection_lost);
        assert!(app.client_error.is_none());
    }

    #[test]
    fn test_clipboard_login_copy_and_host_header_fixed_height() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::Arc;

        let ctx = egui::Context::default();
        let mut app = create_test_app();
        assert!(app.ring_secret.is_empty());
        app.ring_secret = generate_random_password();
        let expected_secret = app.ring_secret.clone();

        // 1. Login dialog renders with guidance text and copy_to_clipboard emits CopyText
        let out = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_initial_secret_dialog(ui);
            });
            app.copy_to_clipboard(ui.ctx(), &expected_secret, "LAN Secret");
        });
        let rendered = collect_rendered_texts(&out).join("\n");
        assert!(rendered.contains("Enter Share-Ring Secret"));
        assert!(
            rendered.contains("Join an existing ring by entering a secret others shared with you,")
        );
        assert!(rendered.contains("or create a new ring by typing or generating one."));
        assert!(out.platform_output.commands.iter().any(|cmd| {
            matches!(cmd, egui::OutputCommand::CopyText(txt) if txt == &expected_secret)
        }));
        let (msg, _) = app.current_status_message(&AppPalette::new(true));
        assert_eq!(msg, "✓ Copied LAN Secret to clipboard");
        assert!(!app.secret_confirmed);

        // Pressing Enter on login screen even when text field is not focused (e.g. after clicking Random) confirms secret
        // and does not auto-select any peer even when peers are present on the ring
        app.test_mode = true;
        app.client_connected = true;
        app.client_ip = "mock://gaming-pc".to_string();
        let mut enter_input = egui::RawInput::default();
        enter_input.events.push(egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: Some(egui::Key::Enter),
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        let _ = run_test_ui(&ctx, enter_input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                app.render_initial_secret_dialog(ui);
            });
        });
        assert!(app.secret_confirmed);
        assert!(!app.client_connected);
        assert!(app.client_ip.is_empty());
        assert!(app.client_file_list.is_empty());
        assert_eq!(app.discovered_peers.len(), 2);
        app.test_mode = false;

        // 2. Host tab keeps identical height across stopped & active sharing states
        app.current_tab = AppTab::Host;

        let mut stopped_card_h = 0.0_f32;
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let resp = ui.vertical(|ui| {
                    app.render_host_tab(ui);
                });
                stopped_card_h = resp.response.rect.height();
            });
        });

        let (stop_tx, _stop_rx) = tokio::sync::oneshot::channel();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        app.server_handle = Some(ServerHandle {
            is_running: Arc::new(AtomicBool::new(true)),
            local_ip: "192.168.1.100".to_string(),
            all_ips: vec!["192.168.1.100".to_string()],
            port: 4433,
            password: expected_secret,
            stop_sender: stop_tx,
            shared_folders: Arc::new(std::sync::RwLock::new(vec![])),
            duration_hours: None,
            registry: Arc::new(std::sync::RwLock::new(
                crate::server::SharedFolderRegistry::new(vec![]),
            )),
            log_tx,
            active_downloads: Arc::new(AtomicUsize::new(0)),
            active_folder_downloads: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            registry_notify_tx: tokio::sync::watch::channel(0u64).0,
        });

        let mut active_card_h = 0.0_f32;
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                let resp = ui.vertical(|ui| {
                    app.render_host_tab(ui);
                });
                active_card_h = resp.response.rect.height();
            });
        });

        assert!(
            (stopped_card_h - active_card_h).abs() < 0.5,
            "Host header/layout must not resize when Stop Sharing appears ({} vs {})",
            stopped_card_h,
            active_card_h
        );
    }

    #[test]
    fn test_about_link_uses_default_cursor_and_stays_centered() {
        let ctx = egui::Context::default();
        let app = create_test_app();
        let p = app.palette(&ctx);

        let mut link_rect = egui::Rect::NOTHING;
        let _ = run_test_ui(&ctx, Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    link_rect = LanShareApp::render_about_link(
                        ui,
                        &p,
                        "Check for updates (GitHub Releases)",
                        GITHUB_RELEASES_URL,
                    )
                    .rect;
                });
            });
        });

        let hover_input = egui::RawInput {
            events: vec![egui::Event::PointerMoved(link_rect.center())],
            ..Default::default()
        };
        let out = run_test_ui(&ctx, hover_input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    let _ = LanShareApp::render_about_link(
                        ui,
                        &p,
                        "Check for updates (GitHub Releases)",
                        GITHUB_RELEASES_URL,
                    );
                });
            });
        });
        assert_eq!(out.platform_output.cursor_icon, egui::CursorIcon::Default);
    }
}
