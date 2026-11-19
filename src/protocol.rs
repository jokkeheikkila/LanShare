use serde::{Deserialize, Serialize};

pub const DEFAULT_TCP_PORT: u16 = 22222;
pub const DEFAULT_UDP_PORT: u16 = 22223;
pub const MIN_SECRET_LEN: usize = 10;
pub const BEACON_MAGIC: &str = "LANSHARE_BEACON_V2";
pub const PROBE_MAGIC: &str = "LANSHARE_PROBE_V2";
pub const REVERSE_MAGIC: &str = "LANSHARE_REVCONN_V2";

/// UDP Beacon broadcasted or sent via unicast by the server for LAN discovery.
/// Includes a cryptographic HMAC-SHA256 `ring_tag` over `(nonce, host_name, port)` keyed by a
/// PBKDF2-stretched discovery subkey, ensuring only peers with the matching secret reveal the share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    pub magic: String,
    pub host_name: String,
    pub port: u16,
    #[serde(default)]
    pub nonce: [u8; 16],
    #[serde(default)]
    pub ring_tag: Vec<u8>,
}

impl DiscoveryBeacon {
    pub fn new(host_name: String, port: u16, secret: &str) -> Self {
        let nonce: [u8; 16] = crate::network::random_bytes();
        let ring_tag = crate::network::compute_ring_beacon_tag(&host_name, port, &nonce, secret);
        Self {
            magic: BEACON_MAGIC.to_string(),
            host_name,
            port,
            nonce,
            ring_tag,
        }
    }
}

/// Active UDP discovery probe sent by a scanning client so hosts with the matching LAN secret
/// immediately reply via unicast (punching through client stateful firewalls like ufw/firewalld/Windows Firewall).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryProbe {
    pub magic: String,
    pub nonce: [u8; 16],
    pub ring_tag: Vec<u8>,
}

impl DiscoveryProbe {
    pub fn new(secret: &str) -> Self {
        let nonce: [u8; 16] = crate::network::random_bytes();
        let ring_tag = crate::network::compute_ring_beacon_tag("LANSHARE_PROBE", 0, &nonce, secret);
        Self {
            magic: PROBE_MAGIC.to_string(),
            nonce,
            ring_tag,
        }
    }

    pub fn verify(&self, secret: &str) -> bool {
        self.magic == PROBE_MAGIC
            && crate::network::verify_ring_beacon_tag(
                "LANSHARE_PROBE",
                0,
                &self.nonce,
                secret,
                &self.ring_tag,
            )
    }
}

/// Authenticated UDP request sent by a client when direct TCP connection to a host is blocked by the host's firewall.
/// Prompts the host to initiate an outbound TCP connection back to the client's listener port and run the TLS server handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseConnectRequest {
    pub magic: String,
    pub client_name: String,
    pub tcp_port: u16,
    pub nonce: [u8; 16],
    pub ring_tag: Vec<u8>,
}

impl ReverseConnectRequest {
    pub fn new(client_name: String, tcp_port: u16, secret: &str) -> Self {
        let nonce: [u8; 16] = crate::network::random_bytes();
        let ring_tag =
            crate::network::compute_ring_beacon_tag(&client_name, tcp_port, &nonce, secret);
        Self {
            magic: REVERSE_MAGIC.to_string(),
            client_name,
            tcp_port,
            nonce,
            ring_tag,
        }
    }

    pub fn verify(&self, secret: &str) -> bool {
        self.magic == REVERSE_MAGIC
            && self.tcp_port > 0
            && crate::network::verify_ring_beacon_tag(
                &self.client_name,
                self.tcp_port,
                &self.nonce,
                secret,
                &self.ring_tag,
            )
    }
}

/// Discovered peer information displayed in the client UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub host_name: String,
    pub ip: String,
    pub port: u16,
    pub last_seen: std::time::Instant,
}

/// Metadata for a file or directory entry in the remote browser.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_timestamp: u64, // Unix epoch timestamp in seconds
}

/// Initial handshake request from client using channel-bound auth token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub auth_token: Vec<u8>,
    pub client_name: String,
}

/// Handshake response from server (strictly read-only share).
/// Includes `server_auth_token` bound to the TLS session using a distinct exporter label
/// so the client can mutually authenticate that the server knows the Share-Ring secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub authenticated: bool,
    pub server_name: String,
    pub message: String,
    #[serde(default)]
    pub server_auth_token: Vec<u8>,
}

/// Read-only requests that a client can send over the authenticated TLS connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientCommand {
    /// List directory contents at `subpath` (relative to shared root, empty for root).
    ListDirectory { subpath: String },
    /// Request to download a single file at `subpath` with optional resume offset.
    DownloadFile { subpath: String, resume_offset: u64 },
    /// Request recursive manifest of a directory at `subpath` to download entire folder.
    GetDirectoryManifest { subpath: String },
}

/// Server response header before raw streams or structured payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerCommandResponse {
    DirectoryListing {
        current_path: String,
        entries: Vec<FileEntry>,
        #[serde(default)]
        notice: Option<String>,
    },
    DirectoryManifest {
        root_folder_name: String,
        files: Vec<ManifestFileEntry>,
        #[serde(default)]
        has_more: bool,
    },
    DownloadReady {
        file_name: String,
        remaining_size: u64,
        total_size: u64,
        start_offset: u64,
        #[serde(default)]
        has_digest_trailer: bool,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFileEntry {
    pub relative_path: String, // e.g. "sub/doc.txt"
    pub file_size: u64,
}
