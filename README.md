# xotero

A self-hosted, multi-user server for the [Zotero](https://www.zotero.org) Web API.
One deployment holds many users, private personal libraries, and shared group
libraries, with no zotero.org account or third-party cloud. Metadata lives in
PostgreSQL and attachment bytes live in S3-compatible storage.

> **Status: in active development (pre-1.0).** Interfaces, the schema, and the
> deployment surface may still change without notice. This pre-alpha server has
> not received a security audit.
>
> See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the release plan and debt list, and
> [`docs/DESIGN.md`](docs/DESIGN.md) for how the system works.

## How it works

- **Server.** A Rust/axum service backed by PostgreSQL. Library objects stay
  canonical `jsonb` documents, and each library has its own version counter so
  `since` reads and `If-Unmodified-Since-Version` writes stay coherent.
- **Identity.** OIDC stays at a trusted reverse proxy. The server maps the verified
  `(issuer, subject)` claims to a local user, and email is never an identity key.
- **Authorization.** Every request resolves to one user or group library and its
  permissions before a handler reads data. Group roles are owner, admin, and
  member.
- **API keys.** Keys are stored as digests, owned by a user, scoped to libraries
  and to read, write, notes, and files permissions, and revoked immediately.
- **Attachments.** Uploads pass through the server for verification and go to a
  library-scoped object. Downloads redirect to a short-lived pre-signed URL.

The API contract is in [`docs/API.md`](docs/API.md). The executable inventory of
supported routes is in `checks/contracts`.

## Clients

Pinned upstream [Web Library](https://github.com/zotero/web-library) is the
supported client target, and its packaging is still in progress. Until then, use
the HTTP API with an API key. The browser-approved login flow at `/keys/sessions`
stays available for issuing keys, but desktop Zotero is not a supported client.

## Components (flake outputs)

| Output                | Purpose                                                  |
| --------------------- | -------------------------------------------------------- |
| `packages.xotero`     | the server binary                                        |
| `nixosModules.xotero` | systemd service, local PostgreSQL, loaded credentials    |
| `packages.zotero-schema` | Zotero schema served by `/schema`, pinned via Web Library |
| `overlays.default`    | adds `pkgs.xotero` and `pkgs.zotero-schema`              |

## Deployment

The server must bind to a loopback address behind a reverse proxy. The proxy
authenticates the browser with OIDC, removes any identity headers sent by the
caller, and sets `X-Xotero-OIDC-Issuer` and `X-Xotero-OIDC-Subject` from verified
claims. Expose the server only over HTTPS.

**Generate the secrets** (one line each):

```sh
openssl rand -hex 32
```

Store them with sops-nix, clan vars, or another secret manager. The server reads
them from files.

```nix
imports = [ inputs.xotero.nixosModules.xotero ];
nixpkgs.overlays = [ inputs.xotero.overlays.default ];

services.xotero = {
  enable = true;
  bind = "127.0.0.1:8189";
  publicUrl = "https://zotero.example.org";   # no trailing slash

  # The first user. This runs once, and later starts never repair the mapping.
  bootstrapUserId = 1;
  bootstrapUsername = "alice";
  bootstrapDisplayName = "Alice";
  bootstrapOidcIssuer = "https://id.example.org";
  bootstrapOidcSubject = "248289761001";

  # At least 32 bytes. Replicas must share this value.
  loginKdfKeyFile = config.sops.secrets."xotero/login-kdf".path;

  s3 = {
    endpoint = "https://<account>.r2.cloudflarestorage.com";
    bucket = "zotero";
    accessKeyFile = config.sops.secrets."xotero/s3-access".path;
    secretKeyFile = config.sops.secrets."xotero/s3-secret".path;
  };

  # Optional recovery credentials. Users get their own database keys.
  keys.recovery.file = config.sops.secrets."xotero/recovery-key".path;
};
```

Attachment upload limits are set with `uploadConcurrency`, `uploadParts`,
`uploadMaxBytes`, and `uploadTimeout`.

## Security

- **Authorize first.** The server authorizes a request before it reads the body.
  Lookup failures stop the request.
- **User-owned keys.** Each key belongs to one user and has explicit scopes. No
  shared key is returned to several users.
- **Recovery credentials.** Configured keys are validated at startup and kept only
  as digests.
- **File access.** Registration rechecks the original upload authority. File
  downloads use expiring pre-signed URLs, so they need no API key.
- **Secrets at rest.** API secrets and S3 keys are provisioned out of band and
  loaded as systemd credentials. They never enter the Nix store or environment.
- **Encryption at rest** for attachment bytes is the object store's concern.

## Status

Implemented and covered by NixOS VM tests:

- objects, settings, deletions, conditional writes, and full-text content
- the three-step attachment upload and S3-backed download
- OIDC identity mapping, database API keys, and browser login sessions
- personal and private group libraries with role-based access
- the read and query API, including search, filters, sorting, and pagination

Remaining work includes the packaged Web Library, full public API coverage,
exports, health endpoints, graceful shutdown, and backup and restore drills.
Internal Zotero.org infrastructure is out of scope.

## Development

```sh
nix develop            # postgres + sqlx-cli + rust toolchain + clippy
cargo fmt
cargo clippy --all-targets --all-features
cargo test
nix build .#xotero
```

Run against a local database and an S3-compatible store (e.g. RustFS on `:9000`):

```sh
XOTERO_DATABASE_URL='postgres:///xotero?host=/run/postgresql' \
XOTERO_S3_ENDPOINT='http://127.0.0.1:9000' XOTERO_S3_BUCKET='zotero' \
XOTERO_S3_ACCESS_KEY='...' XOTERO_S3_SECRET_KEY='...' \
XOTERO_BOOTSTRAP_OIDC_ISSUER='https://id.example.org' \
XOTERO_BOOTSTRAP_OIDC_SUBJECT='dev-user' \
XOTERO_LOGIN_KDF_KEY_FILE='./login-kdf' \
  result/bin/xotero
```

Configuration uses environment variables. The main groups are `XOTERO_BIND`,
`XOTERO_PUBLIC_URL`, `XOTERO_DATABASE_URL`, `XOTERO_S3_*`, `XOTERO_BOOTSTRAP_*`,
`XOTERO_UPLOAD_*`, `XOTERO_USER_ID`, `XOTERO_USERNAME`, `XOTERO_DISPLAY_NAME`,
`XOTERO_LOGIN_KDF_KEY_FILE`, and `XOTERO_KEYS`.

See [`docs/TESTING.md`](docs/TESTING.md) for the verification tiers. For example,
`nix build .#checks.x86_64-linux.nixos-sync` runs the full flow against RustFS.

## License

[MIT](LICENSE).
