use std::fs;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

/// Cleans Windows extended-length path prefix (`\\?\` or `\\?\UNC\`) to standard path.
pub fn clean_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{}", stripped))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Formats a path cleanly for user-facing UI and logs without Windows verbatim prefix (`\\?\`).
pub fn clean_display_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", stripped)
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        s.to_string()
    }
}

/// Detects whether a path metadata represents a symbolic link or Windows reparse point (junction / mount).
pub fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        meta.file_type().is_symlink()
            || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// Sanitizes a server-supplied relative path on the client side.
/// Rejects path traversal (`..`), root components (`/`, `C:\`), reserved characters, reserved Windows device names,
/// and any existing local symbolic links or Windows reparse points along the destination path.
/// Splits on both `/` and `\` and pushes segments via `PathBuf::push` for cross-platform compatibility.
pub fn sanitize_client_relative_path(
    base_dir: &Path,
    untrusted_rel: &str,
) -> Result<PathBuf, String> {
    if untrusted_rel.starts_with('/') || untrusted_rel.starts_with('\\') {
        return Err("Access denied: Server sent invalid or traversal path component.".to_string());
    }

    if let Ok(meta) = fs::symlink_metadata(base_dir) {
        if is_symlink_or_reparse(&meta) {
            return Err("Security error: Local destination base directory is a symbolic link or reparse point.".to_string());
        }
    }

    let mut safe_path = base_dir.to_path_buf();
    let mut pushed_any = false;

    const RESERVED_NAMES: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    for raw_seg in untrusted_rel.split(['/', '\\']).filter(|s| !s.is_empty()) {
        let trimmed_raw = raw_seg.trim();
        if raw_seg == "." || raw_seg == ".." || trimmed_raw == "." || trimmed_raw == ".." {
            return Err(
                "Access denied: Server sent invalid or traversal path component.".to_string(),
            );
        }

        let trim_name = trimmed_raw.trim_end_matches(['.', ' ']);
        if trim_name.is_empty() {
            return Err("Empty path component received from server.".to_string());
        }
        // Check illegal characters (including drive colons like C: and null bytes)
        if trim_name.chars().any(|c| {
            matches!(
                c,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\0'
            )
        }) {
            return Err(format!(
                "Illegal character in remote filename: {}",
                trim_name
            ));
        }
        // Check reserved Windows device names
        let upper = trim_name.to_ascii_uppercase();
        let stem = upper.split('.').next().unwrap_or(&upper);
        if RESERVED_NAMES.contains(&stem) {
            return Err(format!(
                "Reserved Windows device name in remote path: {}",
                trim_name
            ));
        }

        safe_path.push(trim_name);
        if let Ok(meta) = fs::symlink_metadata(&safe_path) {
            if is_symlink_or_reparse(&meta) {
                return Err(format!(
                    "Security error: Local destination '{}' is a symbolic link or reparse point.",
                    trim_name
                ));
            }
        }
        pushed_any = true;
    }

    if !pushed_any {
        return Err("Empty relative path from server.".to_string());
    }
    Ok(safe_path)
}

/// Safely creates any missing parent directories for `dir_path` while verifying via `symlink_metadata`
/// that neither `dir_path` nor its created/existing parent directories are symbolic links or reparse points.
pub fn ensure_safe_client_dir(dir_path: &Path) -> Result<(), String> {
    let mut missing_dirs = Vec::new();
    let mut cur = Some(dir_path);

    while let Some(p) = cur {
        match fs::symlink_metadata(p) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    return Err(format!(
                        "Security error: Local directory '{}' is a symbolic link or reparse point.",
                        clean_display_path(p)
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!(
                        "Local path '{}' exists and is not a directory.",
                        clean_display_path(p)
                    ));
                }
                break;
            }
            Err(_) => {
                missing_dirs.push(p.to_path_buf());
                cur = p.parent();
            }
        }
    }

    for dir_to_create in missing_dirs.into_iter().rev() {
        if let Err(e) = fs::create_dir(&dir_to_create) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(format!(
                    "Failed to create destination folder '{}': {}",
                    clean_display_path(&dir_to_create),
                    e
                ));
            }
        }
        let meta = fs::symlink_metadata(&dir_to_create).map_err(|e| {
            format!(
                "Failed to inspect destination folder '{}': {}",
                clean_display_path(&dir_to_create),
                e
            )
        })?;
        if is_symlink_or_reparse(&meta) || !meta.is_dir() {
            return Err(format!(
                "Security error: Created destination folder '{}' is a symbolic link or invalid directory.",
                clean_display_path(&dir_to_create)
            ));
        }
    }

    Ok(())
}

/// Verifies that `dest_file_path` and its intermediate parent directories are not symbolic links or reparse points,
/// creating any missing parent directories safely before opening `dest_file_path` for writing.
pub fn ensure_safe_client_dest_path(dest_file_path: &Path) -> Result<(), String> {
    if let Some(parent) = dest_file_path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_safe_client_dir(parent)?;
        }
    }

    if let Ok(meta) = fs::symlink_metadata(dest_file_path) {
        if is_symlink_or_reparse(&meta) {
            return Err(format!(
                "Security error: Refusing to overwrite symbolic link or reparse point '{}'.",
                clean_display_path(dest_file_path)
            ));
        }
        if meta.is_dir() {
            return Err(format!(
                "Destination path '{}' is an existing directory, not a file.",
                clean_display_path(dest_file_path)
            ));
        }
    }

    Ok(())
}

/// Validates that a user-selected folder or regular file is safe to share.
/// Blocks symlinks/reparse points, filesystem/drive roots, Windows & Linux system directories,
/// user home roots, and sensitive folders/files inside restricted directories.
pub fn validate_shared_path(path: &Path) -> Result<PathBuf, String> {
    let raw_meta = fs::symlink_metadata(path).map_err(|e| format!("Cannot resolve path: {}", e))?;
    if is_symlink_or_reparse(&raw_meta) {
        return Err("Access denied: Symbolic links and junctions cannot be shared.".to_string());
    }

    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path: {}", e))?;

    if !canonical.is_dir() && !canonical.is_file() {
        return Err("Selected path must be a regular file or folder.".to_string());
    }

    // Convert to uppercase string for case-insensitive Windows comparisons
    let norm = clean_display_path(&canonical).to_uppercase();

    // 1. Block filesystem root ("/") and Windows drive roots ("C:\", "D:\", etc.)
    if canonical == Path::new("/")
        || canonical.parent().is_none()
        || (norm.len() <= 3 && norm.ends_with(r":\"))
    {
        return Err(
            "Sharing an entire drive or filesystem root is not allowed for security reasons."
                .to_string(),
        );
    }

    // 2. Block Linux / Unix system directories (and any file inside them)
    const UNIX_SYSTEM_DIRS: [&str; 9] = [
        "/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/usr", "/var", "/run",
    ];
    for sys_dir in &UNIX_SYSTEM_DIRS {
        let sys_path = Path::new(sys_dir);
        if canonical == sys_path || canonical.starts_with(sys_path) {
            return Err(format!(
                "Sharing system path ({}) is strictly prohibited.",
                sys_dir
            ));
        }
        if let Ok(canon_sys) = sys_path.canonicalize() {
            if canonical == canon_sys || canonical.starts_with(&canon_sys) {
                return Err(format!(
                    "Sharing system path ({}) is strictly prohibited.",
                    sys_dir
                ));
            }
        }
    }
    if canonical == Path::new("/home") {
        return Err("Sharing /home root is strictly prohibited.".to_string());
    }

    // 3. Dynamically query system and user profile environment variables
    let sys_vars = [
        "SystemRoot",
        "windir",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
        "USERPROFILE",
        "HOME",
        "PUBLIC",
        "ALLUSERSPROFILE",
    ];

    for var in &sys_vars {
        if let Ok(val) = std::env::var(var) {
            if val.trim().is_empty() {
                continue;
            }
            if let Ok(canon_val) = Path::new(&val).canonicalize() {
                let val_norm = clean_display_path(&canon_val).to_uppercase();
                if canonical == canon_val || norm == val_norm || norm == format!(r"{}\", val_norm) {
                    return Err(format!(
                        "Sharing system or profile root folder ({}) is strictly prohibited.",
                        var
                    ));
                }
                // Check if user tried to share a parent directory of SystemRoot, USERPROFILE, or HOME
                if canonical.is_dir()
                    && (*var == "SystemRoot" || *var == "USERPROFILE" || *var == "HOME")
                    && canon_val.starts_with(&canonical)
                {
                    return Err(format!(
                        "Sharing parent directory of {} is strictly prohibited.",
                        var
                    ));
                }
            }
        }
    }

    // 4. Sensitive subfolder names
    let forbidden_names = [
        "APPDATA",
        ".SSH",
        ".GNUPG",
        "$RECYCLE.BIN",
        "SYSTEM VOLUME INFORMATION",
    ];

    for component in canonical.components() {
        if let Component::Normal(comp) = component {
            let comp_upper = comp.to_string_lossy().to_uppercase();
            for forbidden in &forbidden_names {
                if comp_upper == *forbidden {
                    return Err(format!("Path contains restricted folder: {}", comp_upper));
                }
            }
        }
    }

    Ok(clean_path(&canonical))
}

/// Validates that a user-selected folder is safe to share.
pub fn validate_shared_folder(path: &Path) -> Result<PathBuf, String> {
    let safe = validate_shared_path(path)?;
    if !safe.is_dir() {
        return Err("Selected path is not a directory.".to_string());
    }
    Ok(safe)
}

/// Validates that a user-selected regular file is safe to share.
pub fn validate_shared_file(path: &Path) -> Result<PathBuf, String> {
    let safe = validate_shared_path(path)?;
    if !safe.is_file() {
        return Err("Selected path is not a regular file.".to_string());
    }
    Ok(safe)
}

/// Resolves a requested relative subpath inside the shared root,
/// strictly enforcing chroot jail confinement and verifying each intermediate directory is not a symlink/reparse point.
pub fn resolve_safe_path(shared_root: &Path, subpath: &str) -> Result<PathBuf, String> {
    let canonical_root = shared_root
        .canonicalize()
        .map_err(|e| format!("Invalid root folder: {}", e))?;

    let clean_subpath = subpath.trim_start_matches(['/', '\\']);

    if clean_subpath.is_empty() {
        return Ok(clean_path(&canonical_root));
    }

    let mut current = canonical_root.clone();

    for part in clean_subpath.split(['/', '\\']).filter(|s| !s.is_empty()) {
        if part == "." || part == ".." || part.contains('\0') {
            return Err("Access denied: Invalid or traversal path component.".to_string());
        }

        let mut comps = Path::new(part).components();
        match (comps.next(), comps.next()) {
            (Some(Component::Normal(os_part)), None) => {
                current.push(os_part);

                // Inspect each segment before canonicalizing to prevent jumping through junctions/symlinks
                let meta = fs::symlink_metadata(&current)
                    .map_err(|_| "Requested path not found or inaccessible.".to_string())?;

                if is_symlink_or_reparse(&meta) {
                    return Err(
                        "Access denied: Symbolic links and junctions are blocked.".to_string()
                    );
                }
            }
            _ => {
                return Err("Access denied: Invalid or traversal path component.".to_string());
            }
        }
    }

    let canonical = current
        .canonicalize()
        .map_err(|_| "Requested path not found or inaccessible.".to_string())?;

    // Final chroot jail check
    if !canonical.starts_with(&canonical_root) {
        return Err("Access denied: Path traversal attempted.".to_string());
    }

    Ok(clean_path(&canonical))
}

/// Verifies whether an IP address belongs to a private RFC 1918 LAN, loopback, link-local,
/// or Tailscale / CGNAT private overlay subnet (RFC 6598 100.64.0.0/10, RFC 4193 IPv6 ULA fc00::/7).
pub fn is_private_lan_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() {
                return true;
            }
            // RFC 6598 CGNAT / Shared Address Space (100.64.0.0/10 used universally by Tailscale)
            let oct = ipv4.octets();
            oct[0] == 100 && (oct[1] >= 64 && oct[1] <= 127)
        }
        IpAddr::V6(ipv6) => {
            // Loopback, link-local unicast (fe80::/10), or ULA unique local (fc00::/7, including Tailscale fd7a:115c:a1e0::/48)
            let seg0 = ipv6.segments()[0];
            ipv6.is_loopback() || ipv6.is_unicast_link_local() || (seg0 & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_client_relative_path_traversal() {
        let base = PathBuf::from(r"C:\Downloads");
        assert!(sanitize_client_relative_path(&base, "../evil.exe").is_err());
        assert!(sanitize_client_relative_path(&base, "..\\evil.exe").is_err());
        assert!(sanitize_client_relative_path(&base, "/etc/passwd").is_err());
        assert!(sanitize_client_relative_path(&base, r"C:\Windows\System32").is_err());
        assert!(sanitize_client_relative_path(&base, "sub/../../evil.exe").is_err());
    }

    #[test]
    fn test_sanitize_client_relative_path_reserved() {
        let base = PathBuf::from(r"C:\Downloads");
        assert!(sanitize_client_relative_path(&base, "CON.txt").is_err());
        assert!(sanitize_client_relative_path(&base, "nul").is_err());
        assert!(sanitize_client_relative_path(&base, "com1.pdf").is_err());
        assert!(sanitize_client_relative_path(&base, "bad:name.txt").is_err());
        assert!(sanitize_client_relative_path(&base, "file*name.txt").is_err());
    }

    #[test]
    fn test_sanitize_client_relative_path_valid() {
        let base = PathBuf::from(r"C:\Downloads");
        let safe = sanitize_client_relative_path(&base, "photos/summer/pic.jpg").unwrap();
        assert_eq!(safe, base.join("photos").join("summer").join("pic.jpg"));

        let safe_backslash =
            sanitize_client_relative_path(&base, r"photos\summer\pic.jpg").unwrap();
        assert_eq!(
            safe_backslash,
            base.join("photos").join("summer").join("pic.jpg")
        );
    }

    #[test]
    fn test_resolve_safe_path_and_validation() {
        let base = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target");
        let test_dir = base.join(format!("lanshare_sec_test_{}", std::process::id()));
        let sub_dir = test_dir.join("nested").join("docs");
        let _ = fs::create_dir_all(&sub_dir);
        let file_path = sub_dir.join("readme.txt");
        let _ = fs::write(&file_path, b"hello");

        // Valid subfolder resolution with forward and backslashes
        let resolved_fwd = resolve_safe_path(&test_dir, "nested/docs/readme.txt").unwrap();
        let resolved_bck = resolve_safe_path(&test_dir, r"nested\docs\readme.txt").unwrap();
        assert_eq!(resolved_fwd, resolved_bck);
        assert!(resolved_fwd.ends_with("readme.txt"));

        // Traversal blocked
        assert!(resolve_safe_path(&test_dir, "../etc/passwd").is_err());
        assert!(resolve_safe_path(&test_dir, r"nested\..\..\outside").is_err());

        // Validate shared folder allows safe project subfolder
        assert!(validate_shared_folder(&test_dir).is_ok());
        // Validate shared file allows regular file, blocks folders in file validator,
        // and blocks files inside restricted or system folders
        assert!(validate_shared_path(&file_path).is_ok());
        assert!(validate_shared_file(&file_path).is_ok());
        assert!(validate_shared_file(&test_dir).is_err());
        assert!(validate_shared_folder(&file_path).is_err());

        // Sensitive subfolders (.ssh / .gnupg) and files inside them blocked
        let ssh_dir = test_dir.join(".ssh");
        let gnupg_dir = test_dir.join(".gnupg");
        let _ = fs::create_dir_all(&ssh_dir);
        let _ = fs::create_dir_all(&gnupg_dir);
        let ssh_key = ssh_dir.join("id_ed25519");
        let _ = fs::write(&ssh_key, b"secret");
        assert!(validate_shared_folder(&ssh_dir).is_err());
        assert!(validate_shared_folder(&gnupg_dir).is_err());
        assert!(validate_shared_file(&ssh_key).is_err());

        #[cfg(unix)]
        {
            assert!(validate_shared_folder(Path::new("/")).is_err());
            assert!(validate_shared_folder(Path::new("/etc")).is_err());
            assert!(validate_shared_path(Path::new("/etc/hosts")).is_err());
            let link_path = test_dir.join("link_to_file.txt");
            if std::os::unix::fs::symlink(&file_path, &link_path).is_ok() {
                assert!(validate_shared_path(&link_path).is_err());
            }
            if let Ok(home) = std::env::var("HOME") {
                let home_path = Path::new(&home);
                if home_path.exists() {
                    assert!(validate_shared_folder(home_path).is_err());
                }
            }
        }

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_private_lan_ip() {
        assert!(is_private_lan_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_lan_ip(&"192.168.1.100".parse().unwrap()));
        assert!(is_private_lan_ip(&"10.0.0.5".parse().unwrap()));
        assert!(is_private_lan_ip(&"172.16.5.1".parse().unwrap()));

        // Tailscale IPv4 range (100.64.0.0/10)
        assert!(is_private_lan_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_private_lan_ip(&"100.115.92.19".parse().unwrap()));
        assert!(is_private_lan_ip(&"100.127.255.254".parse().unwrap()));
        assert!(!is_private_lan_ip(&"100.63.255.255".parse().unwrap()));
        assert!(!is_private_lan_ip(&"100.128.0.0".parse().unwrap()));

        // Tailscale IPv6 ULA (fd7a:115c:a1e0::/48) & loopback
        assert!(is_private_lan_ip(&"fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(is_private_lan_ip(&"::1".parse().unwrap()));

        // Public WAN IP addresses are strictly rejected
        assert!(!is_private_lan_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_lan_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_private_lan_ip(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn test_client_dest_symlink_blocking() {
        let test_dir =
            std::env::temp_dir().join(format!("lanshare_symlink_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&test_dir);
        let _ = fs::create_dir_all(&test_dir);

        let real_file = test_dir.join("real.txt");
        let _ = fs::write(&real_file, b"safe");
        assert!(ensure_safe_client_dest_path(&real_file).is_ok());

        let new_nested = test_dir.join("new_sub").join("downloaded.bin");
        assert!(ensure_safe_client_dest_path(&new_nested).is_ok());
        assert!(test_dir.join("new_sub").is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target_outside = test_dir.join("outside_secret.txt");
            let _ = fs::write(&target_outside, b"do not overwrite");

            let symlink_file = test_dir.join("evil_link.txt");
            symlink(&target_outside, &symlink_file).unwrap();

            // Must block both in sanitize_client_relative_path and ensure_safe_client_dest_path
            assert!(sanitize_client_relative_path(&test_dir, "evil_link.txt").is_err());
            assert!(ensure_safe_client_dest_path(&symlink_file).is_err());

            // Dangling symlink must also be blocked
            let dangling_link = test_dir.join("dangling.txt");
            symlink(test_dir.join("nonexistent_target.txt"), &dangling_link).unwrap();
            assert!(sanitize_client_relative_path(&test_dir, "dangling.txt").is_err());
            assert!(ensure_safe_client_dest_path(&dangling_link).is_err());

            // Symlinked intermediate directory must also be blocked
            let symlink_dir = test_dir.join("linked_dir");
            symlink(&test_dir, &symlink_dir).unwrap();
            assert!(sanitize_client_relative_path(&test_dir, "linked_dir/inside.txt").is_err());
            assert!(ensure_safe_client_dest_path(&symlink_dir.join("inside.txt")).is_err());
        }

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_windows_trailing_space_and_unc_display_normalization() {
        let test_dir =
            std::env::temp_dir().join(format!("lanshare_sec_norm_{}", std::process::id()));
        let _ = fs::remove_dir_all(&test_dir);
        let _ = fs::create_dir_all(&test_dir);

        assert_eq!(
            sanitize_client_relative_path(&test_dir, "report.txt ").unwrap(),
            test_dir.join("report.txt")
        );
        assert!(sanitize_client_relative_path(&test_dir, "CON ").is_err());
        assert!(sanitize_client_relative_path(&test_dir, ".. ").is_err());
        assert_eq!(
            sanitize_client_relative_path(&test_dir, "subdir /file.txt").unwrap(),
            test_dir.join("subdir").join("file.txt")
        );

        assert_eq!(
            clean_display_path(Path::new(r"\\?\UNC\server\share\folder")),
            r"\\server\share\folder"
        );
        assert_eq!(
            clean_display_path(Path::new(r"\\?\C:\Users\alice\Docs")),
            r"C:\Users\alice\Docs"
        );

        let _ = fs::remove_dir_all(&test_dir);
    }
}
