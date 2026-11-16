#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use lanshare::app::LanShareApp;
use lanshare::core::{read_secret_from_env, read_secret_from_stdin, validate_cli_secret};
use lanshare::protocol::MIN_SECRET_LEN;

fn print_help() {
    println!(
        "LanShare GUI (lanshare-gui) — Encrypted zero-config LAN folder sharing powered by Share-Ring"
    );
    println!();
    println!("USAGE:");
    println!("  lanshare-gui [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --test, --mock              Launch in Single-User Test Mode with simulated peers");
    println!(
        "  --secret-env <VAR>          Read Share-Ring secret from environment variable (min {} chars)",
        MIN_SECRET_LEN
    );
    println!(
        "  --secret-stdin              Read Share-Ring secret from standard input (min {} chars)",
        MIN_SECRET_LEN
    );
    println!("  -s, --secret <SECRET>       Pass Share-Ring secret directly (less secure; visible in process list)");
    println!("  -V, --version               Print version information");
    println!("  -h, --help                  Print this help message");
}

fn main() -> eframe::Result<()> {
    // Install Ring crypto provider for Rustls 0.23
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut test_mode = false;
    let mut secret: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "-V" | "--version" => {
                println!("lanshare-gui {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--test" | "--mock" => test_mode = true,
            "--secret-env" => {
                let Some(var_name) = args.next() else {
                    eprintln!("Error: --secret-env requires a variable name.");
                    std::process::exit(2);
                };
                match read_secret_from_env(&var_name) {
                    Ok(s) => secret = Some(s),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(2);
                    }
                }
            }
            "--secret-stdin" => match read_secret_from_stdin() {
                Ok(s) => secret = Some(s),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(2);
                }
            },
            "-s" | "--secret" => {
                let Some(val) = args.next() else {
                    eprintln!("Error: {} requires a secret value.", arg);
                    std::process::exit(2);
                };
                eprintln!(
                    "Warning: passing --secret on the command line may expose it in process listings; prefer --secret-env or --secret-stdin."
                );
                match validate_cli_secret(val) {
                    Ok(s) => secret = Some(s),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(2);
                    }
                }
            }
            unknown => {
                eprintln!("Unknown option '{}'. Run with --help for usage.", unknown);
                std::process::exit(2);
            }
        }
    }

    let window_title = if test_mode {
        "LanShare (Test Mode)"
    } else {
        "LanShare"
    };

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1220.0, 800.0])
        .with_min_inner_size(lanshare::app::MIN_WINDOW_INNER_SIZE)
        .with_title(window_title);

    if let Some(icon) = lanshare::app::app_icon() {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        "LanShare",
        native_options,
        Box::new(move |cc| Ok(Box::new(LanShareApp::with_secret(cc, test_mode, secret)))),
    )
}
