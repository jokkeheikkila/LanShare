use local_ip_address::{list_afinet_netifas, local_ip};
use ring::rand::SecureRandom;
use ring::{aead, hmac, pbkdf2};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme,
};
use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Fills a fixed-size array with cryptographically strong random bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    static RNG: OnceLock<ring::rand::SystemRandom> = OnceLock::new();
    let rng = RNG.get_or_init(ring::rand::SystemRandom::new);
    let mut buf = [0u8; N];
    rng.fill(&mut buf).expect("OS CSPRNG failure");
    buf
}

type KeyCacheEntry = (String, [u8; 32], [u8; 32]);
type DerivedKeyCache = Mutex<VecDeque<KeyCacheEntry>>;

fn derive_secret_subkeys(secret: &str) -> ([u8; 32], [u8; 32]) {
    let trimmed = secret.trim();
    static KEY_CACHE: OnceLock<DerivedKeyCache> = OnceLock::new();
    let cache = KEY_CACHE.get_or_init(|| Mutex::new(VecDeque::with_capacity(8)));
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, discovery_key, tls_key)) = guard.iter().find(|(s, _, _)| s == trimmed) {
            return (*discovery_key, *tls_key);
        }
    }

    let iters = NonZeroU32::new(PBKDF2_ITERATIONS).expect("non-zero PBKDF2 iterations");
    let mut discovery_key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        b"LANSHARE-V2-UDP-DISCOVERY-KDF-SALT",
        trimmed.as_bytes(),
        &mut discovery_key,
    );
    let mut tls_key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iters,
        b"LANSHARE-V2-TLS-AUTH-KDF-SALT",
        trimmed.as_bytes(),
        &mut tls_key,
    );

    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if guard.len() >= 8 {
        guard.pop_front();
    }
    guard.push_back((trimmed.to_string(), discovery_key, tls_key));
    (discovery_key, tls_key)
}

/// Computes the TLS exporter buffer for channel binding with the given RFC 5705 / RFC 8446 label.
pub fn compute_tls_exporter_with_label<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    label: &[u8],
) -> Result<[u8; 32], String> {
    let mut exporter_buf = [0u8; 32];
    conn.export_keying_material(&mut exporter_buf, label, None)
        .map_err(|e| format!("Failed to export TLS keying material: {}", e))?;
    Ok(exporter_buf)
}

/// Computes the TLS exporter buffer for client-to-server channel binding.
pub fn compute_tls_exporter<Data>(
    conn: &rustls::ConnectionCommon<Data>,
) -> Result<[u8; 32], String> {
    compute_tls_exporter_with_label(conn, b"EXPORTER-lanshare-auth-v1")
}

/// Computes a client-to-server channel-bound authentication token bound to the underlying TLS session (RFC 5705 / RFC 8446)
/// using HMAC-SHA256 keyed by the PBKDF2-stretched TLS subkey.
pub fn compute_tls_auth_token<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    password: &str,
) -> Result<Vec<u8>, String> {
    let exporter_buf = compute_tls_exporter(conn)?;
    let (_, tls_key) = derive_secret_subkeys(password);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &tls_key);
    let tag = hmac::sign(&key, &exporter_buf);
    Ok(tag.as_ref().to_vec())
}

/// Verifies a client-to-server channel-bound authentication token in constant time using HMAC-SHA256.
pub fn verify_tls_auth_token<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    password: &str,
    auth_token: &[u8],
) -> bool {
    if password.trim().is_empty() || auth_token.is_empty() {
        return false;
    }
    let exporter_buf = match compute_tls_exporter(conn) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let (_, tls_key) = derive_secret_subkeys(password);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &tls_key);
    hmac::verify(&key, &exporter_buf, auth_token).is_ok()
}

/// Computes a server-to-client channel-bound authentication token bound to the TLS session
/// using a distinct exporter label (`"EXPORTER-lanshare-server-auth-v1"`), proving to the client
/// that the server also possesses the Share-Ring secret.
pub fn compute_tls_server_auth_token<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    password: &str,
) -> Result<Vec<u8>, String> {
    let exporter_buf = compute_tls_exporter_with_label(conn, b"EXPORTER-lanshare-server-auth-v1")?;
    let (_, tls_key) = derive_secret_subkeys(password);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &tls_key);
    let tag = hmac::sign(&key, &exporter_buf);
    Ok(tag.as_ref().to_vec())
}

/// Verifies a server-to-client channel-bound authentication token in constant time using HMAC-SHA256.
pub fn verify_tls_server_auth_token<Data>(
    conn: &rustls::ConnectionCommon<Data>,
    password: &str,
    server_auth_token: &[u8],
) -> bool {
    if password.trim().is_empty() || server_auth_token.is_empty() {
        return false;
    }
    let exporter_buf =
        match compute_tls_exporter_with_label(conn, b"EXPORTER-lanshare-server-auth-v1") {
            Ok(b) => b,
            Err(_) => return false,
        };
    let (_, tls_key) = derive_secret_subkeys(password);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &tls_key);
    hmac::verify(&key, &exporter_buf, server_auth_token).is_ok()
}

/// Encrypts a V3 UDP discovery/control payload with `CHACHA20_POLY1305` keyed by the
/// PBKDF2-stretched UDP discovery subkey, binding `aad_magic` as Authenticated Associated Data.
pub fn seal_discovery_payload(
    aad_magic: &str,
    plaintext: &[u8],
    secret: &str,
) -> ([u8; 12], Vec<u8>) {
    let (discovery_key, _) = derive_secret_subkeys(secret);
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &discovery_key)
        .expect("32-byte ChaCha20-Poly1305 key");
    let key = aead::LessSafeKey::new(unbound);
    let nonce_bytes: [u8; 12] = random_bytes();
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad_magic.as_bytes()), &mut in_out)
        .expect("AEAD seal_in_place_append_tag");
    (nonce_bytes, in_out)
}

/// Decrypts and authenticates a V3 UDP discovery/control payload with `CHACHA20_POLY1305`
/// in constant time against the user's Share-Ring secret and `aad_magic`.
pub fn open_discovery_payload(
    aad_magic: &str,
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    secret: &str,
) -> Option<Vec<u8>> {
    if secret.trim().is_empty() || ciphertext.len() < aead::CHACHA20_POLY1305.tag_len() {
        return None;
    }
    let (discovery_key, _) = derive_secret_subkeys(secret);
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &discovery_key).ok()?;
    let key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce_bytes);
    let mut in_out = ciphertext.to_vec();
    let plain = key
        .open_in_place(nonce, aead::Aad::from(aad_magic.as_bytes()), &mut in_out)
        .ok()?;
    Some(plain.to_vec())
}

/// Computes an HMAC-SHA256 Share-Ring discovery probe tag over `(nonce, label)` keyed by
/// the PBKDF2-stretched UDP discovery subkey.
pub fn compute_ring_probe_tag(label: &str, nonce: &[u8; 16], secret: &str) -> Vec<u8> {
    let (discovery_key, _) = derive_secret_subkeys(secret);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &discovery_key);
    let mut msg = Vec::with_capacity(48 + label.len());
    msg.extend_from_slice(b"LANSHARE-RING-PROBE-V3:");
    msg.extend_from_slice(nonce);
    msg.push(b':');
    msg.extend_from_slice(label.as_bytes());
    let tag = hmac::sign(&key, &msg);
    tag.as_ref().to_vec()
}

/// Verifies a UDP probe's Share-Ring tag in constant time against the user's Share-Ring secret.
pub fn verify_ring_probe_tag(label: &str, nonce: &[u8; 16], secret: &str, ring_tag: &[u8]) -> bool {
    if secret.trim().is_empty() || ring_tag.is_empty() {
        return false;
    }
    let (discovery_key, _) = derive_secret_subkeys(secret);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &discovery_key);
    let mut msg = Vec::with_capacity(48 + label.len());
    msg.extend_from_slice(b"LANSHARE-RING-PROBE-V3:");
    msg.extend_from_slice(nonce);
    msg.push(b':');
    msg.extend_from_slice(label.as_bytes());
    hmac::verify(&key, &msg, ring_tag).is_ok()
}

/// Returns the local computer name (Windows or Linux).
pub fn get_computer_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "LanShareHost".to_string())
}

/// Computes the true IPv4 directed subnet broadcast address (`ip | !netmask`) for an interface.
/// Returns `None` for point-to-point or host-only masks (`/31`, `/32`, or invalid `0.0.0.0` masks).
pub fn compute_directed_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr) -> Option<Ipv4Addr> {
    let mask_u32 = u32::from(netmask);
    // Reject 0.0.0.0, /31 (0xFFFFFFFE), and /32 (0xFFFFFFFF), and require contiguous leading 1s
    if mask_u32 == 0 || mask_u32 >= 0xFFFF_FFFE {
        return None;
    }
    let inv = !mask_u32;
    if (inv & (inv + 1)) != 0 {
        return None;
    }
    let bcast = Ipv4Addr::from(u32::from(ip) | inv);
    if bcast == ip || bcast.is_loopback() {
        return None;
    }
    Some(bcast)
}

/// Checks whether two IPv4 addresses belong to the same subnet under `netmask`.
pub fn ipv4_in_same_subnet(a: Ipv4Addr, b: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    let mask = u32::from(netmask);
    if mask == 0 {
        return false;
    }
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// Structure representing an active broadcast-capable local IPv4 interface and its netmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalIpv4Subnet {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
}

/// Queries active broadcast-capable private IPv4 interfaces and their true subnet masks.
/// Skips loopback, point-to-point/tunnel (VPN), and down interfaces.
#[cfg(unix)]
pub fn get_local_ipv4_subnets() -> Vec<LocalIpv4Subnet> {
    let mut subnets = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` initializes `ifap` with a linked list of interface structures
    // allocated by libc, which we traverse read-only and free via `freeifaddrs` before returning.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 || ifap.is_null() {
            return subnets;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let flags = ifa.ifa_flags as libc::c_int;
            let is_up = (flags & libc::IFF_UP) != 0;
            let is_bcast = (flags & libc::IFF_BROADCAST) != 0;
            let is_loopback = (flags & libc::IFF_LOOPBACK) != 0;
            let is_p2p = (flags & libc::IFF_POINTOPOINT) != 0;

            if is_up
                && is_bcast
                && !is_loopback
                && !is_p2p
                && !ifa.ifa_addr.is_null()
                && !ifa.ifa_netmask.is_null()
                && (*ifa.ifa_addr).sa_family as libc::c_int == libc::AF_INET
                && (*ifa.ifa_netmask).sa_family as libc::c_int == libc::AF_INET
            {
                let addr_in = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let mask_in = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
                let netmask = Ipv4Addr::from(u32::from_be(mask_in.sin_addr.s_addr));

                if !ip.is_loopback()
                    && (ip.is_private() || ip.is_link_local())
                    && !subnets.iter().any(|s: &LocalIpv4Subnet| s.ip == ip)
                {
                    if let Some(broadcast) = compute_directed_broadcast(ip, netmask) {
                        subnets.push(LocalIpv4Subnet {
                            ip,
                            netmask,
                            broadcast,
                        });
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    subnets
}

#[cfg(not(unix))]
pub fn get_local_ipv4_subnets() -> Vec<LocalIpv4Subnet> {
    let mut subnets = Vec::new();
    if let Ok(ifaces) = list_afinet_netifas() {
        for (_name, ip) in ifaces {
            if let IpAddr::V4(ipv4) = ip {
                // Only include RFC 1918 / link-local LAN interfaces (exclude CGNAT 100.64.0.0/10 VPN tunnels)
                if !ipv4.is_loopback()
                    && (ipv4.is_private() || ipv4.is_link_local())
                    && !subnets.iter().any(|s: &LocalIpv4Subnet| s.ip == ipv4)
                {
                    let netmask = Ipv4Addr::new(255, 255, 255, 0);
                    if let Some(broadcast) = compute_directed_broadcast(ipv4, netmask) {
                        subnets.push(LocalIpv4Subnet {
                            ip: ipv4,
                            netmask,
                            broadcast,
                        });
                    }
                }
            }
        }
    }
    subnets
}

/// Returns true if `target_ip` is on the same L2 IPv4 subnet as any local broadcast interface,
/// or is loopback (`127.0.0.0/8` / `::1`).
pub fn is_same_local_subnet(target_ip: IpAddr) -> bool {
    if target_ip.is_loopback() {
        return true;
    }
    if let IpAddr::V4(target_v4) = target_ip {
        for sub in get_local_ipv4_subnets() {
            if ipv4_in_same_subnet(sub.ip, target_v4, sub.netmask) {
                return true;
            }
        }
    }
    false
}

/// Structure representing a local network interface and its deduplicated target broadcast addresses.
#[derive(Debug, Clone)]
pub struct BroadcastBinding {
    pub bind_ip: Ipv4Addr,
    pub targets: Vec<SocketAddr>,
}

/// Retrieves local IPv4 broadcast bindings using each interface's real subnet broadcast address.
/// Emits exactly 1 broadcast target per unique broadcast domain (no ARP neighbor sweeping or 3x duplicates),
/// falling back to a single `255.255.255.255` target only when no interface-specific broadcast exists.
pub fn get_broadcast_bindings(port: u16) -> Vec<BroadcastBinding> {
    let mut bindings = Vec::new();
    let mut seen_targets = HashSet::new();

    for sub in get_local_ipv4_subnets() {
        let target = SocketAddr::V4(SocketAddrV4::new(sub.broadcast, port));
        if seen_targets.insert(target) {
            bindings.push(BroadcastBinding {
                bind_ip: sub.ip,
                targets: vec![target],
            });
        }
    }

    if bindings.is_empty() {
        bindings.push(BroadcastBinding {
            bind_ip: Ipv4Addr::UNSPECIFIED,
            targets: vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, port))],
        });
    }

    bindings
}

/// Returns a prioritized list of local LAN IP addresses (prioritizing 192.168.x.x, then 10.x.x.x).
pub fn get_all_local_lan_ips() -> Vec<String> {
    let mut ips = Vec::new();

    if let Ok(ifaces) = list_afinet_netifas() {
        for (_name, ip) in ifaces {
            if let IpAddr::V4(ipv4) = ip {
                if !ipv4.is_loopback() && crate::security::is_private_lan_ip(&ip) {
                    ips.push(ipv4.to_string());
                }
            }
        }
    }

    if ips.is_empty() {
        if let Ok(ip) = local_ip() {
            ips.push(ip.to_string());
        } else {
            ips.push("127.0.0.1".to_string());
        }
    } else {
        // Prioritize 192.168.x.x, then 10.x.x.x, then 172.x.x.x, then Tailscale 100.x.x.x
        ips.sort_by_key(|ip| {
            if ip.starts_with("192.168.") {
                0
            } else if ip.starts_with("10.") {
                1
            } else if ip.starts_with("172.") {
                2
            } else if ip.starts_with("100.") {
                3
            } else {
                4
            }
        });
        ips.dedup();
    }

    ips
}

/// Generates an in-memory ephemeral self-signed certificate and private key.
pub fn generate_ephemeral_tls() -> Result<
    (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let subject_alt_names = vec!["localhost".to_string(), "lanshare.local".to_string()];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)?;

    let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(certified_key.signing_key.serialize_der().into());

    Ok((vec![cert_der], key_der))
}

/// Builds a ServerConfig using the ephemeral certificate and ring crypto provider.
pub fn make_server_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"lanshare".to_vec()];
    Ok(config)
}

/// Custom verifier to trust ephemeral self-signed server certificates on the LAN.
/// The session is password-protected at the application handshake level.
#[derive(Debug)]
struct DangerNoVerify;

impl ServerCertVerifier for DangerNoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

/// Builds a ClientConfig configured to accept ephemeral self-signed LAN certificates.
pub fn make_client_tls_config() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerNoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"lanshare".to_vec()];
    config
}

/// Sends a 4-byte big-endian length-prefixed payload.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Frame payload exceeds 16MB limit",
        ));
    }
    let len = data.len() as u32;
    writer.write_u32(len).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a 4-byte big-endian length-prefixed payload (max 16 MB frame).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Frame payload exceeds 16MB limit",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v3_aead_discovery_seal_and_open() {
        let plain = b"{\"host_name\":\"Gaming-PC\",\"port\":22222}";
        let (nonce, ciphertext) =
            seal_discovery_payload("LANSHARE_BEACON_V3", plain, "lan-party-42");

        // Ciphertext must not contain plaintext hostname
        assert!(!String::from_utf8_lossy(&ciphertext).contains("Gaming-PC"));

        let opened = open_discovery_payload(
            "LANSHARE_BEACON_V3",
            &nonce,
            &ciphertext,
            "  lan-party-42  ",
        );
        assert_eq!(opened.as_deref(), Some(&plain[..]));

        // Wrong secret, wrong AAD magic, or tampered ciphertext must fail
        assert!(
            open_discovery_payload("LANSHARE_BEACON_V3", &nonce, &ciphertext, "wrong-secret")
                .is_none()
        );
        assert!(
            open_discovery_payload("LANSHARE_REVCONN_V3", &nonce, &ciphertext, "lan-party-42")
                .is_none()
        );

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0xFF;
        assert!(
            open_discovery_payload("LANSHARE_BEACON_V3", &nonce, &tampered, "lan-party-42")
                .is_none()
        );
    }

    #[test]
    fn test_ring_probe_hmac_verification() {
        let nonce = [7u8; 16];
        let tag = compute_ring_probe_tag("LANSHARE_PROBE_V3", &nonce, "lan-party-42");
        assert!(verify_ring_probe_tag(
            "LANSHARE_PROBE_V3",
            &nonce,
            "lan-party-42",
            &tag
        ));
        assert!(verify_ring_probe_tag(
            "LANSHARE_PROBE_V3",
            &nonce,
            "  lan-party-42  ",
            &tag
        ));
        assert!(!verify_ring_probe_tag(
            "LANSHARE_PROBE_V3",
            &nonce,
            "wrong-secret",
            &tag
        ));
        assert!(!verify_ring_probe_tag(
            "OTHER_LABEL",
            &nonce,
            "lan-party-42",
            &tag
        ));
    }

    #[test]
    fn test_compute_directed_broadcast_and_subnet_matching() {
        // /24 subnet
        assert_eq!(
            compute_directed_broadcast(
                Ipv4Addr::new(192, 168, 1, 42),
                Ipv4Addr::new(255, 255, 255, 0)
            ),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        // /16 corporate or large LAN party subnet (must NOT be 10.20.1.255!)
        assert_eq!(
            compute_directed_broadcast(Ipv4Addr::new(10, 20, 1, 42), Ipv4Addr::new(255, 255, 0, 0)),
            Some(Ipv4Addr::new(10, 20, 255, 255))
        );
        // /20 subnet
        assert_eq!(
            compute_directed_broadcast(
                Ipv4Addr::new(172, 16, 18, 99),
                Ipv4Addr::new(255, 255, 240, 0)
            ),
            Some(Ipv4Addr::new(172, 16, 31, 255))
        );
        // /22 subnet
        assert_eq!(
            compute_directed_broadcast(
                Ipv4Addr::new(192, 168, 4, 10),
                Ipv4Addr::new(255, 255, 252, 0)
            ),
            Some(Ipv4Addr::new(192, 168, 7, 255))
        );
        // /25 subnet
        assert_eq!(
            compute_directed_broadcast(
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(255, 255, 255, 128)
            ),
            Some(Ipv4Addr::new(192, 168, 1, 127))
        );
        // /31 and /32 point-to-point/host masks must return None
        assert_eq!(
            compute_directed_broadcast(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(255, 255, 255, 254)
            ),
            None
        );
        assert_eq!(
            compute_directed_broadcast(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(255, 255, 255, 255)
            ),
            None
        );
        assert_eq!(
            compute_directed_broadcast(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(0, 0, 0, 0)),
            None
        );

        // Subnet matching
        let mask_22 = Ipv4Addr::new(255, 255, 252, 0);
        assert!(ipv4_in_same_subnet(
            Ipv4Addr::new(10, 0, 4, 5),
            Ipv4Addr::new(10, 0, 7, 250),
            mask_22
        ));
        assert!(!ipv4_in_same_subnet(
            Ipv4Addr::new(10, 0, 4, 5),
            Ipv4Addr::new(10, 0, 8, 1),
            mask_22
        ));
    }

    #[tokio::test]
    async fn test_mutual_tls_auth_tokens_and_domain_separation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (certs, key) = generate_ephemeral_tls().unwrap();
        let server_cfg = Arc::new(make_server_tls_config(certs, key).unwrap());
        let client_cfg = Arc::new(make_client_tls_config());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            acceptor.accept(tcp).await.unwrap()
        });

        let tcp_client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_cfg);
        let sname = ServerName::try_from("lanshare.local").unwrap().to_owned();
        let client_tls = connector.connect(sname, tcp_client).await.unwrap();
        let server_tls = server_task.await.unwrap();

        let secret = "ring-secret-99";
        let client_tok = compute_tls_auth_token(client_tls.get_ref().1, secret).unwrap();
        let server_tok = compute_tls_server_auth_token(server_tls.get_ref().1, secret).unwrap();

        // Client and server tokens must be distinct (domain-separated exporter labels)
        assert_ne!(client_tok, server_tok);

        // Server verifies client token, client verifies server token
        assert!(verify_tls_auth_token(
            server_tls.get_ref().1,
            secret,
            &client_tok
        ));
        assert!(verify_tls_server_auth_token(
            client_tls.get_ref().1,
            secret,
            &server_tok
        ));

        // Replaying client token as server token (or vice-versa) must fail
        assert!(!verify_tls_server_auth_token(
            client_tls.get_ref().1,
            secret,
            &client_tok
        ));
        assert!(!verify_tls_auth_token(
            server_tls.get_ref().1,
            secret,
            &server_tok
        ));

        // Wrong secret or empty token must fail
        assert!(!verify_tls_server_auth_token(
            client_tls.get_ref().1,
            "wrong",
            &server_tok
        ));
        assert!(!verify_tls_server_auth_token(
            client_tls.get_ref().1,
            secret,
            &[]
        ));
    }
}
