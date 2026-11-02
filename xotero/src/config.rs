use std::collections::HashMap;

use hmac::digest::CtOutput;
use sha2::{Digest, Sha256};

use crate::domain::{LibraryId, Permissions, UserId};
use crate::s3;

pub(crate) struct Config {
    /// Static recovery token digests only, loaded from secret files at boot.
    pub(crate) keys: HashMap<[u8; 32], Permissions>,
    /// Dedicated stable secret for restart-safe browser login key derivation.
    pub(crate) login_kdf_key: Vec<u8>,
    pub(crate) user_id: UserId,
    pub(crate) username: String,
    pub(crate) display_name: String,
    pub(crate) bootstrap_instance_admin: bool,
    /// Migration 0001 creates one legacy personal library with ID 1. Keeping its
    /// scope in application state makes every storage call explicit.
    pub(crate) library_id: LibraryId,
    pub(crate) bind: String,
    /// Client-facing base URL (e.g. the reverse-proxy address). Used for the
    /// login and upload URLs handed to the client, which must be reachable by it
    /// — not the internal bind address. (Downloads use a pre-signed bucket URL.)
    pub(crate) public_url: String,
    pub(crate) web_origin: String,
    pub(crate) database_url: String,
    pub(crate) s3: s3::Config,
    pub(crate) upload_concurrency: usize,
    pub(crate) upload_parts: usize,
    pub(crate) upload_max_bytes: u64,
    pub(crate) upload_timeout: std::time::Duration,
}

impl Config {
    pub(crate) fn recovery_permissions(&self, digest: &[u8]) -> Option<Permissions> {
        recovery_permissions(&self.keys, digest)
    }

    pub(crate) fn from_env() -> Self {
        let keys = load_keys();
        let bind = std::env::var("XOTERO_BIND").unwrap_or_else(|_| "127.0.0.1:8189".into());
        let bind_address: std::net::SocketAddr =
            bind.parse().expect("XOTERO_BIND must be a socket address");
        assert!(
            bind_address.ip().is_loopback(),
            "XOTERO_BIND must be loopback so only the trusted local proxy can set OIDC headers"
        );
        let user_id = std::env::var("XOTERO_USER_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .and_then(UserId::new)
            .unwrap_or_else(|| UserId::new(1).expect("default user ID is positive"));
        let username = std::env::var("XOTERO_USERNAME").unwrap_or_else(|_| "xotero".into());
        let display_name = std::env::var("XOTERO_DISPLAY_NAME").unwrap_or_else(|_| "xotero".into());
        let library_id = LibraryId::new(1).expect("legacy library ID is positive");
        let public_url =
            std::env::var("XOTERO_PUBLIC_URL").unwrap_or_else(|_| format!("http://{bind}"));
        let web_origin =
            configured_web_origin(&public_url).unwrap_or_else(|error| panic!("{error}"));
        Self {
            keys,
            login_kdf_key: load_login_kdf_key(),
            user_id,
            username,
            display_name,
            bootstrap_instance_admin: match std::env::var("XOTERO_BOOTSTRAP_INSTANCE_ADMIN")
                .as_deref()
            {
                Ok("true") => true,
                Ok("false") | Err(std::env::VarError::NotPresent) => false,
                _ => panic!("XOTERO_BOOTSTRAP_INSTANCE_ADMIN must be true or false"),
            },
            library_id,
            public_url,
            web_origin,
            bind,
            database_url: std::env::var("XOTERO_DATABASE_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or_else(|_| "postgres://localhost/xotero".into()),
            s3: load_s3(),
            upload_concurrency: positive_env("XOTERO_UPLOAD_CONCURRENCY", 4),
            upload_parts: positive_env("XOTERO_UPLOAD_PARTS", 2),
            upload_max_bytes: positive_env("XOTERO_UPLOAD_MAX_BYTES", 256 * 1024 * 1024),
            upload_timeout: std::time::Duration::from_secs(positive_env(
                "XOTERO_UPLOAD_TIMEOUT",
                300,
            )),
        }
    }
}

fn configured_web_origin(value: &str) -> Result<String, &'static str> {
    let uri: axum::http::Uri = value.parse().map_err(|_| "invalid XOTERO_PUBLIC_URL")?;
    let scheme = uri
        .scheme_str()
        .ok_or("XOTERO_PUBLIC_URL needs a scheme")?
        .to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err("XOTERO_PUBLIC_URL needs HTTP(S)");
    }
    let authority = uri
        .authority()
        .ok_or("XOTERO_PUBLIC_URL needs an authority")?;
    if authority.as_str().contains('@') {
        return Err("XOTERO_PUBLIC_URL cannot contain credentials");
    }
    let host = authority.host();
    let suffix = authority
        .as_str()
        .strip_prefix(host)
        .ok_or("invalid XOTERO_PUBLIC_URL authority")?;
    let port = if suffix.is_empty() {
        None
    } else {
        let digits = suffix
            .strip_prefix(':')
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .ok_or("invalid XOTERO_PUBLIC_URL port")?;
        Some(
            digits
                .parse::<u16>()
                .map_err(|_| "invalid XOTERO_PUBLIC_URL port")?,
        )
    };
    let host = if let Some(literal) = host.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        let address = literal
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| "XOTERO_PUBLIC_URL needs a valid IPv6 literal")?;
        if address.to_ipv4_mapped().is_some() {
            // Browser URL serialization uses hexadecimal even for mapped IPv4;
            // std Display instead emits a dotted-decimal tail for this case.
            let segments = address.segments();
            format!("[::ffff:{:x}:{:x}]", segments[6], segments[7])
        } else {
            format!("[{address}]")
        }
    } else {
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err("XOTERO_PUBLIC_URL needs an ASCII hostname or IP literal");
        }
        let host = host.to_ascii_lowercase();
        match host.parse::<std::net::Ipv4Addr>() {
            Ok(address) => address.to_string(),
            Err(_) => {
                let last = host
                    .trim_end_matches('.')
                    .rsplit('.')
                    .next()
                    .unwrap_or_default();
                if last.bytes().all(|b| b.is_ascii_digit())
                    || last
                        .strip_prefix("0x")
                        .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err("XOTERO_PUBLIC_URL IPv4 must use canonical dotted decimal");
                }
                host
            }
        }
    };
    match (scheme.as_str(), port) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => Ok(format!("{scheme}://{host}")),
        (_, Some(port)) => Ok(format!("{scheme}://{host}:{port}")),
    }
}

fn positive_env<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr + Default + PartialOrd,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .ok()
            .filter(|value| *value > T::default())
            .unwrap_or_else(|| panic!("{name} must be a positive integer")),
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => panic!("{name} must be Unicode"),
    }
}

/// Build the digest→access map from secret files. `XOTERO_KEYS` is a
/// comma-separated list of `<role>:<path>` entries (`rw`/`ro`), each path a
/// single-line token (a sops-nix secret exposed via systemd LoadCredential).
fn load_keys() -> HashMap<[u8; 32], Permissions> {
    load_keys_from(
        |name| std::env::var_os(name),
        |path| std::fs::read_to_string(path),
    )
    .unwrap_or_else(|error| panic!("{error}"))
}

fn recovery_permissions(
    keys: &HashMap<[u8; 32], Permissions>,
    digest: &[u8],
) -> Option<Permissions> {
    let digest: [u8; 32] = digest.try_into().ok()?;
    let digest = CtOutput::<Sha256>::new(digest.into());
    keys.iter().find_map(|(key, permissions)| {
        (CtOutput::<Sha256>::new((*key).into()) == digest).then_some(*permissions)
    })
}

fn load_keys_from(
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
    read: impl Fn(&str) -> std::io::Result<String>,
) -> Result<HashMap<[u8; 32], Permissions>, &'static str> {
    let read_token = |path: &str| {
        if path.is_empty() {
            return Err("recovery key file path must be nonempty");
        }
        let value = read(path).map_err(|_| "cannot read recovery key file as UTF-8")?;
        let token = value.trim();
        if token.is_empty() || token.contains(['\r', '\n']) {
            return Err("recovery key file must contain one nonempty token");
        }
        Ok(token.to_owned())
    };
    // The removed single-key sources fail startup so a deployment that still sets
    // them notices instead of silently losing its recovery credential.
    if env("XOTERO_API_KEY_FILE").is_some() || env("XOTERO_API_KEY").is_some() {
        return Err("XOTERO_API_KEY_FILE and XOTERO_API_KEY are removed; use XOTERO_KEYS");
    }
    let mut keys = HashMap::new();
    let mut insert = |token: &str, write| {
        if token.trim().is_empty() {
            return Err("recovery token must be nonempty");
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let permissions = Permissions::recovery(write);
        if recovery_permissions(&keys, &digest).is_some_and(|existing| existing != permissions) {
            return Err("recovery token has conflicting roles");
        }
        keys.insert(digest, permissions);
        Ok(())
    };
    if let Some(manifest) = env("XOTERO_KEYS") {
        let manifest = manifest.to_str().ok_or("XOTERO_KEYS must be Unicode")?;
        for entry in manifest.split(',') {
            let (role, path) = entry
                .split_once(':')
                .ok_or("XOTERO_KEYS requires nonempty role:path entries")?;
            let write = match role {
                "rw" => true,
                "ro" => false,
                _ => return Err("XOTERO_KEYS role must be exactly rw or ro"),
            };
            insert(&read_token(path)?, write)?;
        }
    }
    Ok(keys)
}

fn load_login_kdf_key() -> Vec<u8> {
    let path = std::env::var("XOTERO_LOGIN_KDF_KEY_FILE")
        .expect("XOTERO_LOGIN_KDF_KEY_FILE must point to a stable login KDF credential");
    let mut key =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read login KDF key {path}: {error}"));
    while matches!(key.last(), Some(b'\n' | b'\r')) {
        key.pop();
    }
    assert!(
        key.len() >= 32,
        "login KDF credential must contain at least 32 bytes"
    );
    key
}

/// Object storage settings from the environment. The access/secret keys prefer
/// a file (`*_FILE`, a systemd credential) over the raw env var, which is
/// visible in /proc — the same precedence as the API keys. `path_style` defaults
/// on (required by RustFS/MinIO, accepted by R2); `region` defaults to `auto`
/// (R2 ignores it). Defaults target a local RustFS for development.
fn load_s3() -> s3::Config {
    let from_file_or_env = |file: &str, var: &str| {
        std::env::var(file)
            .ok()
            .map(|path| {
                std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read S3 key file {path}: {e}"))
                    .trim()
                    .to_string()
            })
            .or_else(|| std::env::var(var).ok())
            .unwrap_or_default()
    };
    s3::Config {
        endpoint: std::env::var("XOTERO_S3_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".into()),
        region: std::env::var("XOTERO_S3_REGION").unwrap_or_else(|_| "auto".into()),
        bucket: std::env::var("XOTERO_S3_BUCKET").unwrap_or_else(|_| "zotero".into()),
        access_key: from_file_or_env("XOTERO_S3_ACCESS_KEY_FILE", "XOTERO_S3_ACCESS_KEY"),
        secret_key: from_file_or_env("XOTERO_S3_SECRET_KEY_FILE", "XOTERO_S3_SECRET_KEY"),
        path_style: std::env::var("XOTERO_S3_PATH_STYLE")
            .map(|v| v != "false")
            .unwrap_or(true),
        // Short by default: the client follows the download redirect right away,
        // so the URL needn't stay valid long (it is an unauthenticated capability).
        presign_ttl: std::env::var("XOTERO_S3_PRESIGN_TTL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Output};

    #[test]
    fn web_origin_matches_browser_serialization() {
        for (configured, expected) in [
            (
                "https://LIBRARY.EXAMPLE.TEST:443/library/",
                "https://library.example.test",
            ),
            (
                "http://LIBRARY.EXAMPLE.TEST:80/",
                "http://library.example.test",
            ),
            (
                "https://library.example.test",
                "https://library.example.test",
            ),
            (
                "https://LIBRARY.EXAMPLE.TEST:8443/path",
                "https://library.example.test:8443",
            ),
            (
                "https://[2001:0DB8:0:0:0:0:0:1]:443/path",
                "https://[2001:db8::1]",
            ),
            ("http://[2001:db8::1]:80/", "http://[2001:db8::1]"),
            ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
            (
                "https://[::ffff:192.0.2.1]:443/",
                "https://[::ffff:c000:201]",
            ),
            ("https://[::192.0.2.1]/", "https://[::c000:201]"),
            ("http://127.0.0.1:80/", "http://127.0.0.1"),
            ("https://127.0.0.1:8189/", "https://127.0.0.1:8189"),
        ] {
            assert_eq!(
                configured_web_origin(configured),
                Ok(expected.to_owned()),
                "{configured}"
            );
        }
    }

    #[test]
    fn web_origin_rejects_unsupported_authority() {
        for value in [
            "https://user:secret@example.test/",
            "https://example.test:/",
            "https://example.test:abc/",
            "https://example.test:65536/",
            "https://[not-ipv6]/",
            "https://[fe80::1%25eth0]/",
            "https://example.test:+443/",
            "https://example%2etest/",
            "https://127.1/",
            "https://0x7f000001/",
            "https://0177.0.0.1/",
        ] {
            assert!(configured_web_origin(value).is_err(), "{value}");
        }
    }

    fn key_loader_child(input: Option<(&str, &std::ffi::OsStr)>) -> Output {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "config::tests::key_loader_subprocess",
                "--nocapture",
            ])
            .env_clear()
            .env("XOTERO_CONFIG_TEST", "1");
        if let Some((name, value)) = input {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    #[test]
    fn key_loader_subprocess() {
        if std::env::var_os("XOTERO_CONFIG_TEST").is_none() {
            return;
        }
        let keys = load_keys();
        for name in [
            "XOTERO_UPLOAD_CONCURRENCY",
            "XOTERO_UPLOAD_PARTS",
            "XOTERO_UPLOAD_MAX_BYTES",
            "XOTERO_UPLOAD_TIMEOUT",
        ] {
            positive_env::<usize>(name, 1);
        }
        if std::env::var_os("XOTERO_KEYS").is_none() {
            assert!(keys.is_empty());
        }
    }

    #[test]
    fn upload_bounds_reject_zero_negative_malformed_and_overflow() {
        for name in [
            "XOTERO_UPLOAD_CONCURRENCY",
            "XOTERO_UPLOAD_PARTS",
            "XOTERO_UPLOAD_MAX_BYTES",
            "XOTERO_UPLOAD_TIMEOUT",
        ] {
            for value in ["0", "-1", "", "invalid", "18446744073709551616"] {
                // Given invalid selected limits, when parsing in isolation.
                let result = key_loader_child(Some((name, value.as_ref())));
                // Then no default or unlimited setting may replace them.
                assert!(!result.status.success(), "{name} accepted {value:?}");
            }
            assert!(key_loader_child(Some((name, "1".as_ref())))
                .status
                .success());
        }
    }

    #[test]
    fn absent_recovery_sources_do_not_create_a_key() {
        // Given no credential source, when loading in an isolated process.
        let result = key_loader_child(None);
        // Then no implicit key exists.
        assert!(result.status.success(), "implicit recovery key remains");
    }

    #[test]
    fn explicit_empty_manifest_is_rejected() {
        // Given an explicitly empty manifest, when loading it.
        let result = key_loader_child(Some(("XOTERO_KEYS", std::ffi::OsStr::new(""))));
        // Then it cannot silently become an empty or development credential.
        assert!(!result.status.success(), "empty manifest accepted");
    }

    #[test]
    fn malformed_manifests_are_rejected_without_echoing_input() {
        for manifest in [
            ",",
            "rw:/dev/null,",
            ",rw:/dev/null",
            "rw:/dev/null,,ro:/dev/null",
            "admin:/dev/null",
            "RW:/dev/null",
            "rw:/dev/null",
            "MANIFEST_SECRET_MARKER_83",
        ] {
            // Given an untrusted manifest, when parsing it.
            let result = key_loader_child(Some(("XOTERO_KEYS", manifest.as_ref())));
            // Then startup rejects it without copying untrusted input to stderr.
            assert!(!result.status.success(), "invalid manifest accepted");
            assert!(!String::from_utf8_lossy(&result.stderr).contains("MANIFEST_SECRET_MARKER_83"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_manifest_is_rejected() {
        use std::os::unix::ffi::OsStrExt;
        // Given non-Unicode environment bytes, when loading the manifest.
        let result = key_loader_child(Some(("XOTERO_KEYS", std::ffi::OsStr::from_bytes(b"\xff"))));
        // Then invalid bytes cannot become a credential.
        assert!(!result.status.success(), "manifest ignored invalid Unicode");
    }

    fn parse(
        manifest: Option<&str>,
        file: Option<&str>,
        token: Option<&str>,
    ) -> Result<HashMap<[u8; 32], Permissions>, &'static str> {
        load_keys_from(
            |name| {
                match name {
                    "XOTERO_KEYS" => manifest,
                    "XOTERO_API_KEY_FILE" => file,
                    "XOTERO_API_KEY" => token,
                    _ => unreachable!(),
                }
                .map(Into::into)
            },
            |path| match path {
                "rw" | "same" => Ok("RECOVERY_RW_MARKER_417\n".into()),
                "ro" => Ok("RECOVERY_RO_MARKER_628\r\n".into()),
                "blank" => Ok(" \t\r\n".into()),
                "multiline" => Ok("first\nsecond\n".into()),
                _ => Err(std::io::ErrorKind::NotFound.into()),
            },
        )
    }

    #[test]
    fn file_tokens_retain_only_digests_and_exact_permissions() {
        // Given separate rw/ro files, when loading with a repeated rw token.
        let keys = parse(Some("rw:rw,ro:ro,rw:same"), None, None).unwrap();
        // Then only two SHA-256 digests with their original scopes remain.
        assert_eq!(keys.len(), 2);
        for (token, write) in [
            ("RECOVERY_RW_MARKER_417", true),
            ("RECOVERY_RO_MARKER_628", false),
        ] {
            let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            assert_eq!(keys[&digest], Permissions::recovery(write));
            assert_eq!(
                recovery_permissions(&keys, &digest),
                Some(Permissions::recovery(write))
            );
            for offset in [0, 16, 31] {
                let mut wrong = digest;
                wrong[offset] ^= 1;
                assert_eq!(recovery_permissions(&keys, &wrong), None);
            }
        }
        for length in [0, 31, 33] {
            assert_eq!(recovery_permissions(&keys, &vec![0; length]), None);
        }
    }

    #[test]
    fn duplicate_role_conflicts_fail_in_both_orders() {
        for manifest in ["rw:rw,ro:same", "ro:same,rw:rw"] {
            // Given one digest with opposing roles, when parsing either order.
            let result = parse(Some(manifest), None, None);
            // Then neither last-wins nor role widening is permitted.
            assert!(result.is_err());
        }
    }

    #[test]
    fn removed_single_key_sources_are_rejected() {
        for (manifest, file, token) in [
            (None, Some("rw"), None),
            (None, None, Some("token")),
            (Some("ro:ro"), Some("rw"), None),
            (Some("ro:ro"), None, Some("token")),
        ] {
            // Given a removed source, even beside a valid manifest.
            let result = parse(manifest, file, token);
            // Then startup fails instead of ignoring the configured credential.
            assert!(result.is_err());
        }
    }
}
