# xotero testing

## Purpose

Test the server against its production-shaped Linux environment and upstream Web
Library. NixOS checks are the repeatable contract gate. Web Library is the only
supported client, so the desktop GUI tier is retired.

## Verification tiers

### Tier 0: fast code checks

Run before every code commit:

- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`, also run by
  `checks.x86_64-linux.clippy`
- `cargo fmt --check`
- treefmt/flake formatting check
- shellcheck for changed scripts

### Tier 1: x86_64-linux NixOS integration

Use real PostgreSQL and RustFS, not mocks.

- `checks.x86_64-linux.api-contracts`
  - executable inventory of supported Web API contracts
  - fixture and wire-format validation
- `checks.x86_64-linux.nixos-sync`
  - metadata/settings/collections/searches/full-text sync
  - conditional writes, conflicts, deletions, pagination, and query formats
  - attachment authorization, upload, registration, download, and cleanup
  - compressed Zotero ZIP contract with separate original/blob hashes
  - wrong ZIP hash rejection
  - pending upload survival across authorization/upload restarts
  - S3 `application/zip` metadata and compressed response headers
  - public schema, mapping lists, and every item template against the pinned
    schema, including locale fallback and 400 errors
- `checks.x86_64-linux.nixos-key-auth`
  - populated-schema migration through latest version
  - OIDC identity mapping and ownership
  - DB-backed scoped keys and revocation
  - personal/group authorization and role boundaries
  - restart and startup-failure behavior
- `checks.x86_64-linux.nixos-admin`
  - instance authority, one-shot bootstrap, and audit
  - web sessions and CSRF
  - user, identity, key, group, membership, and ownership administration
- `checks.x86_64-linux.nixos-operations`
  - `xotero migrate` on a fresh database: current schema, no listener, no
    identity rows beyond the migrations' own, idempotent rerun, and usage exit 2 for unknown arguments
  - fresh database through the unit: `ExecStartPre` migrates, then an
    authenticated request succeeds
  - populated v13 database, from the fixture shared with `nixos-key-auth`:
    the unit upgrades to current and the old item, setting, and full text read
    back through the API
  - failed migration: the unit fails in `ExecStartPre` and nothing listens

### Tier 2: real browser Web Library (planned)

Plan Task 32 adds this gate. Task 30 names the check `nixos-web-library`. It must
load the packaged UI, map the current user, and call the real authorized API.

### Role and isolation coverage

Use real database and object-storage services. Cover:

```text
user A personal -> user B denied
user A group owner -> full group control
user B group admin -> upstream admin permissions
user C group member -> configured read/write/file permissions
removed member -> immediate access loss
revoked key -> immediate access loss
same item key in two libraries -> isolated metadata and bytes
```

### API contract entries

Each inventory entry in `checks/contracts` links upstream documentation, the
`dataserver` location, request and response fixtures, the integration test, and
its profile and support status.

## Historical desktop compatibility run

Run `20260723T190144Z-setup` on 2026-07-24 passed a two-user private-group sync
with a stock Zotero client, migrations 1 through 13, and a compressed attachment.
Desktop support has since been removed, so this run is history and not a gate.

## Current status

Tasks 1 to 20 of the roadmap are merged. CI passes these checks on `main`:

- `checks.x86_64-linux.api-contracts`
- `checks.x86_64-linux.clippy`
- `checks.x86_64-linux.formatting`
- `checks.x86_64-linux.nixos-admin`
- `checks.x86_64-linux.nixos-key-auth`
- `checks.x86_64-linux.nixos-sync`

Structure status:

- repository root has a Cargo workspace, so `cargo clippy` works from the
  repository root;
- Nix expressions live under `nix/`;
- `xotero/src/main.rs` is reduced to bootstrap logic;
- HTTP handlers live under `xotero/src/handlers/`;
- request access, middleware, headers, and validation live under
  `xotero/src/http/`;
- store facade remains in `xotero/src/store/mod.rs`, with each domain in its own
  module.

## Remaining release-gate work

- Add the real browser gate. Plan Task 32.
- Add backup/restore drill covering metadata, full text, original item hashes,
  compressed blob hashes, and S3 bytes. Plan Task 37.
- Resolve or expire three legacy pending rows from the failed pre-migration ZIP
  attempts; they cannot register because migration cannot reconstruct ZIP hash.
