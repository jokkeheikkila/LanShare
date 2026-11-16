# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.1.x   | Yes       |
| 1.0.x   | Yes       |
| < 1.0.0 | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in LanShare, please **do not** open a public GitHub issue with exploit details.

Instead, report it privately via GitHub Security Advisories (**Security -> Advisories -> Report a vulnerability** on the repository) and include:

1. A description of the vulnerability and affected component (e.g., discovery, TLS authentication, path sanitization, or transfer integrity).
2. Minimal steps to reproduce or a proof of concept.
3. The LanShare version, OS, and configuration involved.

You can expect an acknowledgment and initial triage update before any fix is published or coordinated for disclosure.

## Security Model & Threat Assumptions

- **Local-Network Scope**: LanShare rejects connections to public/non-private IP addresses and is designed strictly for trusted/isolated local networks (LAN).
- **Authenticated Discovery & Mutual TLS (V2)**:
  - Share-Ring secrets require at least **10 characters** and derive independent subkeys via PBKDF2-HMAC-SHA256 (`100,000` rounds, domain-separated salts) for UDP discovery beacons, TLS SPKI pinning/client identity proofs, and handshake authentication.
  - UDP discovery payloads expose only opaque random nonces and HMAC tags; host IPs are taken from verified network packets rather than untrusted payload lists.
- **File & Transfer Integrity**:
  - Remote paths undergo strict client-side sanitization (blocking path traversal, Windows reserved names, trailing dots/spaces, and symlinks/reparse points) and `O_NOFOLLOW` checks on supported Unix systems.
  - Streamed file chunks include per-transfer SHA-256 verification and strict byte-count/resume-offset validation.
- **Automation Best Practices**: Prefer `--secret-env <VAR>` or `--secret-stdin` over `-s`/`--secret <SECRET>` so secrets do not appear in process listings or shell history.
