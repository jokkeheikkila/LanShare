use local_ip_address::{list_afinet_netifas, local_ip};
use ring::rand::SecureRandom;
use ring::{hmac, pbkdf2};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme,
};
use std::collections::VecDeque;
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

/// Computes an HMAC-SHA256 Share-Ring discovery tag over `(nonce, host_name, port)` keyed by
/// the PBKDF2-stretched UDP discovery subkey.
pub fn compute_ring_beacon_tag(
    host_name: &str,
    port: u16,
    nonce: &[u8; 16],
    secret: &str,
) -> Vec<u8> {
    let (discovery_key, _) = derive_secret_subkeys(secret);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &discovery_key);
    let mut msg = Vec::with_capacity(64 + host_name.len());
    msg.extend_from_slice(b"LANSHARE-RING-BEACON-V2:");
    msg.extend_from_slice(nonce);
    msg.push(b':');
    msg.extend_from_slice(host_name.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(&port.to_be_bytes());
    let tag = hmac::sign(&key, &msg);
    tag.as_ref().to_vec()
}

/// Verifies a UDP beacon's Share-Ring tag in constant time against the user's Share-Ring secret.
pub fn verify_ring_beacon_tag(
    host_name: &str,
    port: u16,
    nonce: &[u8; 16],
    secret: &str,
    ring_tag: &[u8],
) -> bool {
    if secret.trim().is_empty() || ring_tag.is_empty() {
        return false;
    }
    let (discovery_key, _) = derive_secret_subkeys(secret);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &discovery_key);
    let mut msg = Vec::with_capacity(64 + host_name.len());
    msg.extend_from_slice(b"LANSHARE-RING-BEACON-V2:");
    msg.extend_from_slice(nonce);
    msg.push(b':');
    msg.extend_from_slice(host_name.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(&port.to_be_bytes());
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

/// Reads active private LAN IPv4 addresses from the OS ARP cache (`/proc/net/arp` on Linux).
/// Sending unicast UDP beacons to active ARP neighbors automatically punches stateful firewall
/// (`nf_conntrack` / `ufw` / `firewalld`) pinholes without requiring root or firewall changes.
pub fn get_lan_arp_neighbors() -> Vec<Ipv4Addr> {
    let mut neighbors = Vec::new();
    let local_ips = get_all_local_lan_ips();

    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let mut parts = line.split_whitespace();
            if let Some(ip_str) = parts.next() {
                if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                    if !ipv4.is_loopback()
                        && (ipv4.is_private() || ipv4.is_link_local())
                        && !local_ips.iter().any(|l| l == ip_str)
                        && !neighbors.contains(&ipv4)
                    {
                        neighbors.push(ipv4);
                    }
                }
            }
        }
    }

    neighbors
}

/// Structure representing a local network interface and its target broadcast/unicast addresses.
#[derive(Debug, Clone)]
pub struct BroadcastBinding {
    pub bind_ip: Ipv4Addr,
    pub targets: Vec<SocketAddr>,
}

/// Retrieves all local IPv4 LAN addresses and their respective directed subnet broadcast + ARP neighbor targets.
/// Ensures UDP beacons are transmitted out of EVERY physical/virtual network adapter and punch stateful firewall holes.
pub fn get_broadcast_bindings(port: u16) -> Vec<BroadcastBinding> {
    let mut bindings = Vec::new();
    let arp_neighbors = get_lan_arp_neighbors();

    if let Ok(ifaces) = list_afinet_netifas() {
        for (_name, ip) in ifaces {
            if let IpAddr::V4(ipv4) = ip {
                if !ipv4.is_loopback() && crate::security::is_private_lan_ip(&ip) {
                    let octets = ipv4.octets();
                    // Directed subnet broadcast (e.g. 192.168.8.255 for /24)
                    let subnet_bcast = Ipv4Addr::new(octets[0], octets[1], octets[2], 255);

                    let mut targets = vec![
                        SocketAddr::V4(SocketAddrV4::new(subnet_bcast, port)),
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, port)),
                    ];

                    // Add unicast targets for ARP neighbors in the same /24 subnet to punch conntrack holes
                    for neighbor in &arp_neighbors {
                        let n_oct = neighbor.octets();
                        if n_oct[0] == octets[0] && n_oct[1] == octets[1] && n_oct[2] == octets[2] {
                            let target = SocketAddr::V4(SocketAddrV4::new(*neighbor, port));
                            if !targets.contains(&target) {
                                targets.push(target);
                            }
                        }
                    }

                    bindings.push(BroadcastBinding {
                        bind_ip: ipv4,
                        targets,
                    });
                }
            }
        }
    }

    // Always include a fallback 0.0.0.0 binding to limited broadcast + all ARP neighbors
    let mut fallback_targets = vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, port))];
    for neighbor in arp_neighbors {
        let target = SocketAddr::V4(SocketAddrV4::new(neighbor, port));
        if !fallback_targets.contains(&target) {
            fallback_targets.push(target);
        }
    }
    bindings.push(BroadcastBinding {
        bind_ip: Ipv4Addr::UNSPECIFIED,
        targets: fallback_targets,
    });

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
    fn test_ring_beacon_hmac_verification() {
        let nonce = [7u8; 16];
        let tag = compute_ring_beacon_tag("Gaming-PC", 22222, &nonce, "lan-party-42");
        assert!(verify_ring_beacon_tag(
            "Gaming-PC",
            22222,
            &nonce,
            "lan-party-42",
            &tag
        ));
        assert!(verify_ring_beacon_tag(
            "Gaming-PC",
            22222,
            &nonce,
            "  lan-party-42  ",
            &tag
        ));
        assert!(!verify_ring_beacon_tag(
            "Gaming-PC",
            22222,
            &nonce,
            "wrong-secret",
            &tag
        ));
        assert!(!verify_ring_beacon_tag(
            "Other-PC",
            22222,
            &nonce,
            "lan-party-42",
            &tag
        ));
        assert!(!verify_ring_beacon_tag(
            "Gaming-PC",
            22223,
            &nonce,
            "lan-party-42",
            &tag
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
