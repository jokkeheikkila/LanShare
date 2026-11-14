use std::path::PathBuf;

fn find_msvc_rc_exe() -> PathBuf {
    // 1. Check if `rc.exe` is already available in PATH (e.g. Developer PowerShell / CI)
    if let Ok(status) = std::process::Command::new("rc.exe").arg("/?").output() {
        if status.status.success() || !status.stdout.is_empty() || !status.stderr.is_empty() {
            return PathBuf::from("rc.exe");
        }
    }

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let arch_dirs: &[&str] = match target_arch.as_str() {
        "aarch64" => &["arm64", "x64", "x86"],
        "x86" => &["x86", "x64"],
        _ => &["x64", "x86"],
    };

    // 2. Check WindowsSdkVerBinPath / WindowsSdkBinPath if set
    for env_key in ["WindowsSdkVerBinPath", "WindowsSdkBinPath"] {
        if let Ok(base) = std::env::var(env_key) {
            let base_path = PathBuf::from(base);
            for arch in arch_dirs {
                let candidate = base_path.join(arch).join("rc.exe");
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }

    // 3. Search standard Windows Kits installations (works in normal PowerShell / CMD)
    let mut roots = Vec::new();
    if let Ok(sdk_dir) = std::env::var("WindowsSdkDir") {
        roots.push(PathBuf::from(sdk_dir).join("bin"));
    }
    if let Ok(pfx86) = std::env::var("ProgramFiles(x86)") {
        roots.push(PathBuf::from(&pfx86).join(r"Windows Kits\10\bin"));
        roots.push(PathBuf::from(&pfx86).join(r"Windows Kits\8.1\bin"));
    }
    if let Ok(pf) = std::env::var("ProgramFiles") {
        roots.push(PathBuf::from(&pf).join(r"Windows Kits\10\bin"));
    }
    roots.push(PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin"));

    for bin_root in roots {
        if !bin_root.is_dir() {
            continue;
        }

        // Collect versioned subdirectories (e.g. 10.0.26100.0, 10.0.22621.0)
        if let Ok(entries) = std::fs::read_dir(&bin_root) {
            let mut version_dirs: Vec<((u32, u32, u32, u32), PathBuf)> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let path = e.path();
                    if !path.is_dir() {
                        return None;
                    }
                    let name = e.file_name().to_string_lossy().to_string();
                    let parts: Vec<u32> = name.split('.').filter_map(|s| s.parse().ok()).collect();
                    if parts.len() >= 2 {
                        let ver = (
                            *parts.first().unwrap_or(&0),
                            *parts.get(1).unwrap_or(&0),
                            *parts.get(2).unwrap_or(&0),
                            *parts.get(3).unwrap_or(&0),
                        );
                        Some((ver, path))
                    } else {
                        None
                    }
                })
                .collect();

            // Newest SDK version first
            version_dirs.sort_by_key(|a| std::cmp::Reverse(a.0));

            for (_, ver_dir) in version_dirs {
                for arch in arch_dirs {
                    let candidate = ver_dir.join(arch).join("rc.exe");
                    if candidate.is_file() {
                        return candidate;
                    }
                }
            }
        }

        // Fallback: unversioned `bin\<arch>\rc.exe`
        for arch in arch_dirs {
            let candidate = bin_root.join(arch).join("rc.exe");
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    PathBuf::from("rc.exe")
}

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/lanshare.rc");

    // When targeting Windows, compile and embed icon and version metadata.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if let Ok(out_dir) = std::env::var("OUT_DIR") {
            let rc_file = "assets/lanshare.rc";
            let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

            if target_env == "msvc" {
                let res_file = format!("{}/lanshare.res", out_dir);
                let rc_exe = find_msvc_rc_exe();
                match std::process::Command::new(&rc_exe)
                    .args(["/nologo", "/i", "assets", "/fo", &res_file, rc_file])
                    .status()
                {
                    Ok(status) if status.success() => {
                        println!("cargo:rustc-link-arg={}", res_file);
                    }
                    Ok(status) => {
                        println!(
                            "cargo:warning=rc.exe failed with status {}; Windows resources were not embedded.",
                            status
                        );
                    }
                    Err(err) => {
                        println!(
                            "cargo:warning=Could not invoke rc.exe ({}); Windows resources were not embedded.",
                            err
                        );
                    }
                }
            } else {
                let res_file = format!("{}/lanshare_res.o", out_dir);
                let windres_cmd = if std::process::Command::new("windres")
                    .arg("--version")
                    .output()
                    .is_ok()
                {
                    "windres"
                } else {
                    "x86_64-w64-mingw32-windres"
                };
                match std::process::Command::new(windres_cmd)
                    .args(["-I", "assets", "-i", rc_file, "-O", "coff", "-o", &res_file])
                    .status()
                {
                    Ok(status) if status.success() => {
                        println!("cargo:rustc-link-arg={}", res_file);
                    }
                    Ok(status) => {
                        println!(
                            "cargo:warning={} failed with status {}; Windows resources were not embedded.",
                            windres_cmd, status
                        );
                    }
                    Err(err) => {
                        println!(
                            "cargo:warning=Could not invoke {} ({}); Windows resources were not embedded.",
                            windres_cmd, err
                        );
                    }
                }
            }
        }
    }
}
