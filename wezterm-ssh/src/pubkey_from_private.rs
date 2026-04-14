//! Derive the SSH-wire-format public key blob from an `IdentityFile`
//! path, mirroring OpenSSH's own fallback strategy in
//! `authfile.c::sshkey_load_public`:
//!
//! 1. Try to parse the file at `path` itself as an OpenSSH public
//!    key — supports the case where the user points `IdentityFile`
//!    directly at a `.pub` file.
//! 2. Try to read `<path>.pub` from disk — the fast happy path for
//!    the common case where `ssh-keygen` wrote the public half
//!    alongside the private half.
//! 3. Fall back to parsing the private key file itself and
//!    extracting the public key from the **unencrypted** OpenSSH
//!    envelope (`-----BEGIN OPENSSH PRIVATE KEY-----` format). This
//!    works even when the private key is passphrase-protected,
//!    because the public key blob is stored in the envelope header
//!    before the encrypted section, just like OpenSSH's
//!    `sshkey_parse_private2_pubkey()` in `sshkey.c`.
//!
//! A stale `.pub` file next to a rotated private key would match
//! the wrong blob and filter the wrong agent identity, so step 2 is
//! only a performance shortcut — if it fails for any reason we drop
//! straight through to step 3 rather than giving up.

use std::path::Path;

/// Hard ceiling for identity-file reads. Realistic OpenSSH keys
/// stay well below 20 KiB; any file beyond 1 MiB is either a user
/// typo (`IdentityFile` pointing at `/var/log/syslog`), a pathological
/// setup, or a pseudo-file like `/dev/zero` that would otherwise
/// stream unbounded data into our buffer. The read is performed
/// via `Read::take`, so character devices and FIFOs work as long as
/// their stream stays inside this budget.
const MAX_IDENTITY_FILE_BYTES: u64 = 1024 * 1024;

/// Read a file into memory with a hard upper bound of
/// [`MAX_IDENTITY_FILE_BYTES`]. Returns `None` if the file cannot be
/// opened; returns the (possibly truncated) prefix otherwise. A
/// truncated prefix is guaranteed to fail downstream parsing rather
/// than silently accept a partially-read key.
fn read_identity_file_capped(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(MAX_IDENTITY_FILE_BYTES)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

/// Error type returned by [`derive_public_blob`].
#[derive(Debug, thiserror::Error)]
pub enum DerivePubkeyError {
    #[error("failed to parse private key at {path:?}: {source}")]
    Parse {
        path: String,
        #[source]
        source: ssh_key::Error,
    },
    #[error("failed to encode public key for {path:?}: {source}")]
    Encode {
        path: String,
        #[source]
        source: ssh_key::Error,
    },
}

/// Try to produce the SSH-wire-format public key blob for the key
/// referenced by `path`. See the module-level doc comment for the
/// fallback strategy.
///
/// Returns `Ok(None)` when no readable public key material could be
/// found at all (neither the `.pub` file nor the private envelope).
/// Returns `Err` only when a file exists but cannot be parsed — the
/// caller is expected to log and continue rather than propagate the
/// error (matching how `collect_identity_blobs` already handles
/// missing `.pub` files today).
pub fn derive_public_blob(path: &Path) -> Result<Option<Vec<u8>>, DerivePubkeyError> {
    // Read `path` once so strategies 1 and 3 can share the same
    // bytes. Strategies are tried in OpenSSH's `sshkey_load_public`
    // order: path-as-pub, then sibling `.pub`, then private envelope.
    // The read is size-capped to avoid user-typo induced memory
    // blow-ups (e.g. `IdentityFile /var/log/syslog` or `/dev/zero`).
    let path_bytes = read_identity_file_capped(path);

    // Strategy 1: `path` itself is a `.pub`-style public key file
    // (the user pointed `IdentityFile` directly at one).
    if let Some(bytes) = path_bytes.as_deref() {
        if let Some(blob) = parse_openssh_public_line(bytes) {
            log::trace!(
                "pubkey for {:?}: strategy 1 (path is itself a .pub file)",
                path.display()
            );
            return Ok(Some(blob));
        }
    }

    // Strategy 2: `<path>.pub` sibling on disk — the fast happy path
    // when ssh-keygen wrote the public half alongside the private
    // half.
    if let Some((blob, pub_path)) = try_sibling_pub(path) {
        log::trace!(
            "pubkey for {:?}: strategy 2 (sibling {:?})",
            path.display(),
            pub_path.display()
        );
        return Ok(Some(blob));
    }

    // Strategy 3: parse `path` as an OpenSSH private key envelope
    // and return its public half from the unencrypted prefix. Works
    // even for passphrase-protected keys, because the public blob
    // lives in the envelope header before the encrypted key data.
    if let Some(bytes) = path_bytes {
        let path_str = path.to_string_lossy().into_owned();
        match ssh_key::PrivateKey::from_openssh(bytes.as_slice()) {
            Ok(private) => {
                let public = private.public_key();
                let blob = public
                    .to_bytes()
                    .map_err(|source| DerivePubkeyError::Encode {
                        path: path_str,
                        source,
                    })?;
                log::trace!(
                    "pubkey for {:?}: strategy 3 (from OpenSSH private key envelope)",
                    path.display()
                );
                return Ok(Some(blob));
            }
            Err(parse_err) => {
                log::debug!(
                    "pubkey for {:?}: all three strategies failed; surfacing parse error",
                    path.display()
                );
                return Err(DerivePubkeyError::Parse {
                    path: path_str,
                    source: parse_err,
                });
            }
        }
    }

    // `path` is not readable and sibling `.pub` is missing too.
    log::debug!(
        "pubkey for {:?}: no public or private key material found",
        path.display()
    );
    Ok(None)
}

/// Try the `.pub` sibling of `path`. For `foo/id_rsa` this checks
/// `foo/id_rsa.pub`. Returns the decoded blob and the path that
/// served it so the caller can log which file actually answered.
fn try_sibling_pub(path: &Path) -> Option<(Vec<u8>, std::path::PathBuf)> {
    let pub_path = match path.file_name() {
        Some(name) => path.with_file_name(format!("{}.pub", name.to_string_lossy())),
        None => return None,
    };
    let bytes = read_identity_file_capped(&pub_path)?;
    parse_openssh_public_line(&bytes).map(|blob| (blob, pub_path))
}

/// Parse a single-line OpenSSH public key (`algo base64-blob
/// [comment]`) from raw file contents, tolerant of trailing
/// whitespace and CR/LF. Returns the decoded binary blob or `None`
/// if the file does not look like a single-line public key.
fn parse_openssh_public_line(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.lines().next()?;
    let b64 = line.split_whitespace().nth(1)?;
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    struct TempKeyDir {
        path: std::path::PathBuf,
    }

    impl TempKeyDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wezterm-ssh-pubderive-{}-{}",
                std::process::id(),
                name
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("mkdir tempdir");
            Self { path }
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempKeyDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Generate an SSH key via the system `ssh-keygen` binary, so we
    /// exercise the real OpenSSH private key format end-to-end.
    /// Returns `None` if `ssh-keygen` is not on PATH so the test
    /// can skip cleanly on minimal CI images.
    fn keygen(dir: &Path, key_type: &str, passphrase: Option<&str>) -> Option<std::path::PathBuf> {
        let path = dir.join(format!("id_{}", key_type));
        let status = Command::new("ssh-keygen")
            .arg("-t")
            .arg(key_type)
            .arg("-f")
            .arg(&path)
            .arg("-C")
            .arg("test@wezterm")
            .arg("-q")
            .arg("-N")
            .arg(passphrase.unwrap_or(""))
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        Some(path)
    }

    /// Invoke `derive_public_blob` and unwrap to the actual blob,
    /// failing the test loudly if anything along the way misfired.
    fn derive(path: &Path) -> Vec<u8> {
        match derive_public_blob(path) {
            Ok(Some(blob)) => blob,
            Ok(None) => panic!("derive_public_blob({}) returned None", path.display()),
            Err(e) => panic!("derive_public_blob({}) errored: {:#}", path.display(), e),
        }
    }

    #[test]
    fn ed25519_strategy_2_sibling_pub_fast_path() {
        // The happy path: ssh-keygen wrote `id_ed25519` and
        // `id_ed25519.pub` side by side. Strategy 2 finds the
        // sibling .pub first.
        let dir = TempKeyDir::new("ed25519-sibling");
        let Some(private) = keygen(&dir.path, "ed25519", None) else {
            return;
        };
        let blob = derive(&private);
        assert!(!blob.is_empty(), "derived blob should be non-empty");
    }

    #[test]
    fn ed25519_strategy_3_private_envelope_when_sibling_removed() {
        // The motivation for this module: even with the `.pub`
        // file gone, the blob must still be obtainable from the
        // unencrypted envelope of the private key.
        let dir = TempKeyDir::new("ed25519-envelope");
        let Some(private) = keygen(&dir.path, "ed25519", None) else {
            return;
        };
        std::fs::remove_file(dir.join("id_ed25519.pub")).expect("remove sibling");
        let blob = derive(&private);
        assert!(!blob.is_empty());
    }

    #[test]
    fn ed25519_strategy_3_survives_passphrase_protection() {
        // Core assertion: an encrypted OpenSSH private key still
        // has its public half readable, because the envelope
        // header stores it before the encrypted block. This is
        // what lets wezterm-ssh match agent keys for YubiKey /
        // hardware-backed setups without prompting for a
        // passphrase.
        let dir = TempKeyDir::new("ed25519-passphrase");
        let Some(private) = keygen(&dir.path, "ed25519", Some("correct horse battery staple"))
        else {
            return;
        };
        std::fs::remove_file(dir.join("id_ed25519.pub")).expect("remove sibling");
        let blob = derive(&private);
        assert!(!blob.is_empty());
    }

    #[test]
    fn ed25519_envelope_and_sibling_blobs_are_byte_identical() {
        // The fast path and the envelope path must produce
        // byte-for-byte the same blob; anything else means we
        // have a correctness gap between the two strategies.
        let dir = TempKeyDir::new("ed25519-consistency");
        let Some(private) = keygen(&dir.path, "ed25519", None) else {
            return;
        };

        let from_sibling = derive(&private);

        std::fs::remove_file(dir.join("id_ed25519.pub")).expect("remove sibling");
        let from_envelope = derive(&private);

        assert_eq!(
            from_sibling, from_envelope,
            "sibling and envelope must agree on the public key blob"
        );
    }

    #[test]
    fn ecdsa_strategy_3_envelope_roundtrip() {
        // ECDSA uses a different inner encoding but the same
        // envelope, so the extraction path should behave
        // identically to ed25519.
        let dir = TempKeyDir::new("ecdsa-envelope");
        let Some(private) = keygen(&dir.path, "ecdsa", None) else {
            return;
        };
        let sibling = dir.join("id_ecdsa.pub");
        let from_sibling = derive(&private);
        std::fs::remove_file(&sibling).expect("remove sibling");
        let from_envelope = derive(&private);
        assert_eq!(from_sibling, from_envelope);
    }

    #[test]
    fn strategy_1_path_points_directly_at_pub_file() {
        // OpenSSH's `sshkey_load_public` also accepts the case
        // where the user set `IdentityFile` to a `.pub` file
        // directly. Strategy 1 handles that without touching any
        // siblings.
        let dir = TempKeyDir::new("direct-pub");
        let Some(private) = keygen(&dir.path, "ed25519", None) else {
            return;
        };
        let pub_path = dir.join("id_ed25519.pub");
        let blob = derive(&pub_path);
        let from_private = derive(&private);
        assert_eq!(
            blob, from_private,
            "direct .pub read must yield the same blob as the private envelope"
        );
    }

    #[test]
    fn missing_identity_file_returns_none_not_error() {
        // A missing IdentityFile should be logged and skipped by
        // the caller, not treated as a hard error.
        let dir = TempKeyDir::new("missing");
        let absent = dir.join("does_not_exist");
        let result = derive_public_blob(&absent).expect("no IO error for missing file");
        assert!(result.is_none());
    }

    #[test]
    fn garbage_file_surfaces_parse_error() {
        // A file that exists but is neither a valid public key nor
        // a valid OpenSSH private key must surface as a parse
        // error so the operator can see something is wrong.
        let dir = TempKeyDir::new("garbage");
        let path = dir.join("garbage");
        std::fs::write(&path, b"this is not a key\n").expect("write");
        let err = derive_public_blob(&path).expect_err("garbage file should error");
        assert!(
            matches!(err, DerivePubkeyError::Parse { .. }),
            "expected Parse error, got {:?}",
            err
        );
    }

    #[test]
    fn parse_openssh_public_line_handles_trailing_newline() {
        // Regression check for the helper that reads `.pub`
        // content: a trailing CR/LF must not stop the decoder
        // from finding the base64 blob.
        let content = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAA alice\r\n";
        let blob = parse_openssh_public_line(content).expect("parse ok");
        assert!(!blob.is_empty());
    }

    #[test]
    fn parse_openssh_public_line_rejects_single_token() {
        // A file with only the algorithm name is not a valid
        // public key and must be rejected so the caller can drop
        // through to Strategy 3.
        assert!(parse_openssh_public_line(b"ssh-rsa").is_none());
    }

    #[test]
    fn parse_openssh_public_line_rejects_invalid_base64() {
        assert!(parse_openssh_public_line(b"ssh-rsa !!!not-base64!!!").is_none());
    }

    #[test]
    fn read_identity_file_capped_enforces_upper_bound() {
        // Write a file that exceeds MAX_IDENTITY_FILE_BYTES by a
        // comfortable margin, then confirm that the helper stops
        // reading at the cap rather than slurping the whole thing.
        // This is the protection against user-typo IdentityFile
        // values pointing at `/var/log/syslog` or `/dev/zero`.
        let dir = TempKeyDir::new("size-cap");
        let path = dir.join("oversize");
        let oversize_len = (MAX_IDENTITY_FILE_BYTES as usize) + 4096;
        std::fs::write(&path, vec![b'A'; oversize_len]).expect("write oversize");

        let bytes = read_identity_file_capped(&path).expect("open ok");
        assert_eq!(
            bytes.len() as u64,
            MAX_IDENTITY_FILE_BYTES,
            "helper must truncate at the cap"
        );
    }

    #[test]
    fn oversize_file_does_not_ooming_derive() {
        // End-to-end: point derive_public_blob at a multi-megabyte
        // garbage file and verify we (a) don't hang or allocate the
        // whole thing, and (b) surface a clean parse error instead
        // of a crash.
        let dir = TempKeyDir::new("oversize-derive");
        let path = dir.join("garbage_key");
        let oversize_len = (MAX_IDENTITY_FILE_BYTES as usize) + 1024;
        std::fs::write(&path, vec![b'Z'; oversize_len]).expect("write oversize");

        match derive_public_blob(&path) {
            Ok(Some(_)) => panic!("oversize garbage should not decode to a blob"),
            Ok(None) => panic!("oversize file exists so we should try to parse it"),
            Err(DerivePubkeyError::Parse { .. }) => {
                // expected: the truncated prefix is not a valid
                // OpenSSH private key envelope
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
        }
    }
}
