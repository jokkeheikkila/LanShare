use lanshare::cli::{
    format_cli_help, parse_cli_args, resolve_cli_secret, run_cli_download, run_cli_host,
    run_cli_list, run_cli_peers, validate_cli_download_inputs, validate_cli_host_folders,
    CliInvocation,
};
use lanshare::protocol::DEFAULT_TCP_PORT;
use lanshare::tui::{run_tui, LanShareTui};
use tokio::runtime::Runtime;

fn resolve_secret_or_exit(secret: Option<String>) -> String {
    match resolve_cli_secret(secret) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
    }
}

fn main() -> std::io::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args.iter().any(|a| a == "-s" || a == "--secret") {
        eprintln!(
            "Warning: passing --secret on the command line may expose it in process listings; prefer the default interactive prompt, --secret-env, or LANSHARE_SECRET."
        );
    }

    let invocation = match parse_cli_args(&raw_args) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
    };

    match invocation {
        CliInvocation::Help => {
            println!("{}", format_cli_help());
            Ok(())
        }
        CliInvocation::Version => {
            println!("lanshare-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliInvocation::Tui {
            test_mode,
            autostart,
            secret,
            host_folders,
        } => {
            let app = LanShareTui::new(test_mode, secret, host_folders, autostart);
            run_tui(app)
        }
        CliInvocation::Host {
            secret,
            folders,
            test_mode,
        } => {
            let validated_folders = match validate_cli_host_folders(&folders) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(2);
                }
            };
            let secret = resolve_secret_or_exit(secret);
            let rt = Runtime::new().expect("Failed to initialize Tokio runtime");
            let mut stdout = std::io::stdout();
            if let Err(e) = rt.block_on(run_cli_host(
                &secret,
                &validated_folders,
                test_mode,
                None,
                &mut stdout,
            )) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            Ok(())
        }
        CliInvocation::Peers { secret, test_mode } => {
            let secret = resolve_secret_or_exit(secret);
            let rt = Runtime::new().expect("Failed to initialize Tokio runtime");
            let mut stdout = std::io::stdout();
            if let Err(e) = rt.block_on(run_cli_peers(&secret, test_mode, &mut stdout)) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            Ok(())
        }
        CliInvocation::List {
            secret,
            peer,
            remote_path,
            test_mode,
        } => {
            let secret = resolve_secret_or_exit(secret);
            let rt = Runtime::new().expect("Failed to initialize Tokio runtime");
            let mut stdout = std::io::stdout();
            if let Err(e) = rt.block_on(run_cli_list(
                &secret,
                &peer,
                DEFAULT_TCP_PORT,
                &remote_path,
                test_mode,
                &mut stdout,
            )) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            Ok(())
        }
        CliInvocation::Download {
            secret,
            peer,
            dest_dir,
            remote_paths,
            test_mode,
        } => {
            if let Err(e) =
                validate_cli_download_inputs(dest_dir.as_deref(), &remote_paths, test_mode)
            {
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }
            let secret = resolve_secret_or_exit(secret);
            let rt = Runtime::new().expect("Failed to initialize Tokio runtime");
            let mut stdout = std::io::stdout();
            if let Err(e) = rt.block_on(run_cli_download(
                &secret,
                &peer,
                DEFAULT_TCP_PORT,
                dest_dir,
                &remote_paths,
                test_mode,
                &mut stdout,
            )) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            Ok(())
        }
    }
}
