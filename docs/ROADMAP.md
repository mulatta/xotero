# xotero roadmap

This file holds what comes next. `DESIGN.md` describes what exists today.

## Product direction

1. Inventory and specify the upstream Zotero API layers.
2. Build the xotero server first, including multi-user, groups, roles, and
   library-scoped permissions.
3. Evolve and optimize PostgreSQL storage through explicit migrations.
4. Use pinned upstream Web Library as the only client. Desktop support and any
   dedicated or custom client are out of scope.
5. Enter beta when Web Library works end to end, then harden multi-user operation.
6. Use release candidates to stabilize the server and Web Library together.

## Compatibility promise

The final target is the complete **public** Zotero API, delivered in versioned
compatibility profiles. Internal Zotero.org operations and production
infrastructure are not part of that promise.

A supported endpoint must match upstream behavior in:

- HTTP method and path;
- authentication and authorization;
- request and response JSON;
- required and exposed headers;
- pagination and filtering;
- library and object version semantics;
- conditional reads and writes;
- group and role permissions;
- file registration, upload, and download;
- error status and retry behavior;
- documented output formats.

Partial endpoint compatibility is not sufficient. Unsupported endpoints and
formats must fail explicitly rather than return a plausible but incompatible
shape.

### Sources of truth

Compatibility work uses these sources, in order, with conflicts recorded:

1. Versioned public Zotero Web API documentation
2. Requests made by pinned upstream `zotero/web-library`
3. Upstream `zotero/dataserver` controllers, models, and tests
4. Existing xotero behavior, only where it does not conflict with upstream

The `dataserver` source defines many edge cases not described in public docs. Its
MySQL schema, sharding, caches, queues, billing, and operational services do not
constrain xotero internals.

## API compatibility profiles

### Profile A: Sync and Data Core

Required before alpha:

- API keys and current-key introspection
- OIDC-backed browser sessions
- Browser-approved login sessions that issue user-owned API keys
- Users and personal libraries
- Groups, memberships, and upstream role semantics
- Items, collections, saved searches, tags, and settings
- Deleted-object feeds
- Full-text synchronization
- Attachment registration, upload, replacement, and download
- Library and object versions
- Conditional reads and writes
- Pagination, sorting, filtering, and documented query behavior
- Personal and group library route families
- Read, write, notes, and file permissions

Profile A is sufficient for Web Library and core Web API consumers. It must
support multiple users and private groups before alpha, even though multi-user
production hardening continues during beta.

### Profile B: Public API Completeness

Implemented incrementally during alpha and beta, and required for the eventual
public-API-complete release:

- Single-object and child-object endpoints
- Trash and publications behavior
- Public user and group access where documented
- Group metadata and membership management APIs
- All documented item and collection query variants
- Documented export representations and content negotiation
- Citation and bibliography output formats
- Remaining public key and permission management behavior
- Other endpoints confirmed as part of the public Zotero API inventory

The inventory in `checks/contracts`, not this summary, is the authoritative
checklist.

### Profile C: xotero ecosystem APIs

xotero-specific APIs use a separate namespace and never alter upstream paths:

```text
/xotero/capabilities
/xotero/admin/...
/xotero/agents/...
```

Potential Profile C features:

- Instance administration
- Agent-safe search and write workflows
- Device and agent pairing
- Health, readiness, and diagnostics
- Client capability discovery

## Client strategy

### Web Library

Pinned upstream `zotero/web-library` is the only supported client. It runs
same-origin through a session-bound gateway, with no custom Web client and no
hosted Zotero service dependency.

## Agent integration

Agents use the same public API as any other consumer. Provider credentials stay
inside native agent runtimes.

```text
Agent runtime -> xotero tool adapter -> xotero API
```

Initial safe tools:

- search library objects;
- retrieve item metadata;
- retrieve attachment text;
- list collections and related items;
- draft and create notes;
- propose and apply tags;
- create item relations;
- render citations when supported.

Read operations may be automatic. Writes require scoped credentials and an
explicit approval policy. Coding-agent filesystem and shell tools are not
implicitly exposed.

Common implementations may include a machine-readable `xoteroctl` CLI and agent
tool adapters.

## Release train

### Pre-alpha: server compatibility construction

Pre-alpha is for rapid server development and may break schema and configuration.
It is not a production-security claim.

Deliverables:

- Complete public API inventory and compatibility profiles
- Multi-user relational identity foundation and OIDC identity mapping
- User-owned and scoped API keys
- Personal libraries, private groups, memberships, and roles
- Profile A user and group endpoints
- Library-scoped PostgreSQL and S3 operations
- Packaged upstream Web Library and a real browser gate
- Initial backup and migration tooling

Exit criteria for alpha:

- Profile A inventory is complete and implemented.
- Two users have isolated personal libraries.
- Two users can collaborate in one private group library.
- Owner/admin/member behavior matches captured upstream contracts.
- Metadata, files, full text, conflicts, and deletions pass Web Library E2E tests.
- Cross-user and cross-library access tests fail closed.
- A documented migration exists from the single-user schema and storage.

### Alpha: API stabilization

Alpha starts when Profile A server behavior works end to end. APIs may still
change, but changes require compatibility notes and migrations.

Deliverables:

- Versioned Profile A contract suite
- Progressive Profile B implementation
- Agent tool protocol and `xoteroctl`
- Health and readiness endpoints
- Documented backup, restore, and key rotation
- NixOS deployment and initial OCI/Compose paths

Exit criteria for beta:

- Web Library passes the server contract suite.
- Supported alpha upgrades preserve metadata and files.
- Remaining multi-user risks have explicit beta hardening tests.

### Beta: multi-user hardening

Beta treats existing multi-user functionality as a production-bound security and
concurrency surface.

Deliverables:

- OIDC provisioning and account-linking hardening
- API-key creation, revocation, rotation, and audit behavior
- Group membership and role-transition hardening
- Concurrent write and version-conflict tests
- Cross-library object, file, and pre-signed URL isolation tests
- Abuse limits and bounded resource usage
- Larger realistic data and group workloads
- Backup and restore drills across multiple users and groups
- Continued Profile B completion

Stable-beta gate:

- No known cross-user or cross-library isolation failure.
- Role matrix and key-permission matrix have complete integration coverage.
- Multi-device and multi-user conflict behavior matches upstream.
- Migration and restore tests cover all supported beta releases.
- One deployment can be operated without undocumented manual database changes.

### Release candidates: client convergence

Release candidates freeze declared API profiles and stabilize all supported
client surfaces.

Deliverables:

- Web Library compatibility matrix
- Browser session and attachment CORS hardening
- Accessibility and localization pass
- NixOS, OCI, and Compose release artifacts
- Upgrade, backup, restore, and disaster-recovery documentation
- Security review and release threat model

Exit criteria for 1.0:

- Declared compatibility profiles are complete and versioned.
- Web Library passes release E2E suites.
- Supported upgrades preserve all user, group, metadata, full-text, and file
  data.
- Authentication, authorization, and browser boundaries have no known critical
  defects.
- Deployment and recovery can be reproduced from public documentation.

## Current work

Tasks 1 to 21 are merged. See `docs/TASK.md` for task order and dependencies.

### Wave D: browser API semantics

- [x] 19. Correct deleted-tag wire representation
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-sync -L` proves string tombstones and unchanged item deletion shapes.
- [x] 20. Resolve identity sequence without hard-coded name
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-key-auth -L`; generated IDs remain positive/collision-free.
- [x] 21. Serve pinned metadata and item templates
  - Acceptance: `nix build .#checks.x86_64-linux.api-contracts .#checks.x86_64-linux.nixos-sync -L`.
- [ ] 22. Complete listing envelopes, paging and query contracts
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-sync -L` compares paginated fixtures with full expected key sequence and response headers.
  - Each sub-task is done when its Task 22 inventory contracts leave `pending`
    and name a real `nixos-sync` subtest, for both user and group scopes.
  - [ ] 22a. Item, collection and search listings: `json`, `keys` and
    `versions` formats, `start`/`limit`/`sort`/`direction` paging, and the
    unsupported-format and invalid-sort errors. Headers `Total-Results`, `Link`
    and `Last-Modified-Version` match the fixtures exactly, and list bodies
    carry the upstream `library`, `links` and `meta` wrappers. Also add
    `/keys/sessions` and `/login` to the inventory, split contract data into
    `checks/contracts/data/`, and separate verified behavior from target
    support in `docs/API.md`.
  - [ ] 22b. Query filters (`q`/`qmode`, `tag` expressions, `itemType`,
    `itemKey`, `includeTrashed`, `annotationType`), tag listings with
    `itemQ`/`itemQMode`/`itemTag`, and refusal of remote export URLs.
  - [ ] 22c. Full-text index, versions, bulk and per-item reads and writes, and
    the global `/groups` listing.
- [ ] 23. Implement single-object conditional CRUD
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-sync -L`; pinned single-object request/response fixtures pass for user/group.
- [ ] 24. Add children, publications and collection hierarchy views
  - Includes the publications tag listing (`/publications/items/tags`).
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-sync -L` checks actual tree/details/publications fixtures.
- [ ] 25. Add individual-setting conditional operations
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-sync .#checks.x86_64-linux.nixos-key-auth -L`.
- [ ] 26. Add browser attachment URL and ranged read contracts
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-sync -L`; actual file-URL text resolves to correct bytes/range.
### Wave E: exports, Web packaging, deployment

- [ ] 27. Package pinned internal translation engine
  - Acceptance: `nix build .#packages.x86_64-linux.translation-server -L` succeeds in sandbox with complete pinned dependency closure.
  - Pin commit `672d4f3` (`package.json` 2.0.5). Upstream has not tagged a
    release since 2.0.3 in 2019, which predates the current submodule layout,
    so the commit is the version anchor.
  - The source revision and the four submodule revisions equal the inventory's
    `EXPORT` source. No runtime smoke check; Task 28 exercises the engine.
- [ ] 28. Implement all advertised export formats
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-web-library -L`; every advertised format has content/MIME fixture checked against same pinned real engine.
- [ ] 29. Package complete upstream Web Library assets
  - Acceptance: `nix build .#packages.x86_64-linux.web-library -L` creates HTML, JS/CSS, reader/editor/worker/font/locale/style assets from complete sandbox closure.
- [ ] 30. Connect Web UI through session-bound gateway
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-web-library -L` loads real packaged UI, maps current user and calls real authorized API.
- [ ] 31. Make Web the supported deployment surface
  - Acceptance: `nix build .#packages.x86_64-linux.xotero .#packages.x86_64-linux.web-library .#packages.x86_64-linux.translation-server -L`; targeted module evaluation passes with only OIDC secrets.
- [ ] 32. Add real browser contract integration gate
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-web-library -L` returns successful real rendered browser assertions and network trace.
### Wave F: operations and release gates

- [ ] 33. Add controlled explicit migration command
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-operations -L` fresh migration and populated v13->current upgrade succeed before serving.
  - `xotero migrate` applies pending migrations and exits. Serving still
    applies pending migrations at startup.
  - The NixOS module runs it as `ExecStartPre`, as single-service nixpkgs
    modules do.
  - v13 means migrations 0001 to 0013 applied and populated, as in the
    existing `nixos-key-auth` upgrade fixture. The upgrade keeps its data.
  - [x] Command, `ExecStartPre` and the `nixos-operations` check.
  - [ ] `xotero migrate` reads the full service configuration
    (`Config::from_env`), so a manual run needs the recovery keys, the login
    KDF key and S3 credentials. It should need only the database URL.
  - [ ] With `Restart=on-failure`, a failing `ExecStartPre` restarts the unit
    until the start limit. Decide whether a migration failure should stop
    retries, and assert the behavior in `nixos-operations`.
- [ ] 34. Enforce single active process before startup mutations
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-operations -L`; duplicate start/migrate cannot alter schema, identity or pending state.
- [ ] 35. Drain SIGTERM and bound runtime operations
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-operations -L`; actual systemd SIGTERM reaches clean bounded exit with durable state.
- [ ] 36. Add precise liveness and readiness
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-operations -L`; dependency transitions yield correct liveness/readiness.
- [ ] 37. Prove backup, restore and upgrade recovery
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-operations -L` restores separate DB/bucket/secret fixture and verifies full logical manifest plus Web login/file retrieval.
- [ ] 38. Wire focused release checks and web-only output guard
  - Acceptance: `nix build .#checks.x86_64-linux.web-only-surface .#checks.x86_64-linux.formatting -L`; `nix eval --json .#packages --apply builtins.attrNames` and targeted per-system attrs confirm intended surfaces.
### Wave G: Web journeys and handoff

- [ ] 39. Exercise complete first-class Web workflows
  - Acceptance: `nix build .#checks.x86_64-linux.nixos-web-library .#checks.x86_64-linux.nixos-admin -L` plus live browser exercise; rendered expected data and network responses agree.
- [ ] 40. Reconcile local guidance and release ledger
  - Acceptance: Direct agent prose review against actual commands/outputs; `git diff --cached --name-only` has no docs/plans/AGENTS, and read-only `git status --short` accounts for every path.
### Final audits

- [ ] F1. Plan compliance audit
- [ ] F2. Code quality review
- [ ] F3. Real manual QA
- [ ] F4. Ideal-state fidelity

## Technical debt

- **P0** blocks safe multi-user work or can violate data or security invariants.
- **P1** blocks an alpha-quality operational or compatibility claim.
- **P2** should be addressed before a stable release.

### P0: immediate cleanup

- [ ] Make README status text agree with the current multi-user server.

### P1: schema and migrations

- [ ] Document backup-before-upgrade and rollback-by-restore procedures.
- [x] Add an explicit `xotero migrate` operational path. Plan Task 33.
- [ ] Audit `IF NOT EXISTS` migration statements that can conceal schema drift.

### P1: HTTP and compatibility structure

- [ ] Centralize Zotero error, version-header, pagination, and conditional-write
  responses so handlers cannot silently omit contract details.
- [ ] Separate current verified behavior in `docs/API.md` from target support.
- [ ] Inventory API-version, schema-version, content-negotiation, conditional
  request, pagination, and output-format edge cases. Plan Task 22.
- [ ] Add a trusted-proxy configuration. The server now requires a loopback bind,
  but it has no separate proxy setting. Plan Task 31.

### P1: operations

- [ ] Handle `SIGTERM` as a graceful shutdown signal and verify in the NixOS
  service test. Only `ctrl_c` is handled today. Plan Task 35.
- [ ] Add liveness and readiness endpoints with documented PostgreSQL and object
  storage semantics. Plan Task 36.
- [ ] Configure database pool, request, S3, and shutdown timeouts. Upload
  timeouts exist. Pool and shutdown timeouts do not. Plan Task 35.
- [ ] Add request concurrency limits. Upload limits exist.
- [ ] Exercise backup and restore for metadata, full text, and attachment bytes.
  Plan Task 37.
- [ ] Bound retention of pending uploads with an unknown remote outcome. Each
  interrupted upload keeps a row forever, and cleanup retries its object
  deletion every minute. The bound must outlast any late remote write.

### P1: test and quality gates

- [ ] Add a real browser gate for upstream Web Library. Direct HTTP integration
  tests are not a client-compatibility substitute. Plan Task 32.
- [ ] Confirm two-user, two-library, same-object-key isolation coverage.
- [ ] Add backup and restore tests. Plan Task 37.
- [ ] Run dependency advisory/license checks in CI. Clippy, formatting, unit
  tests, and individual NixOS checks already run.

### P2: dependencies and abstractions

- [ ] Compare `rust-s3`, `aws-sdk-s3`, OpenDAL, and `object_store` against R2 and
  RustFS with presigning and streaming tests. `rust-s3 0.38` already removed the
  old Hyper 0.14 stack from the lockfile.
- [ ] Evaluate SQLx 0.9 in an isolated dependency change. Do not combine it with
  identity schema or authorization refactors.
- [ ] Introduce a narrow object-storage trait when attachment tests can define
  its required semantics; do not create a generic storage framework first.
- [ ] Keep pure deterministic domain logic portable, but add `wasm-bindgen` only
  after a custom client demonstrates enough shared logic to justify the boundary.
- [ ] Consider gRPC only for a future independently deployed native service with
  a concrete bidirectional-streaming or generated-client requirement.

## Decision log

| Decision                                                            | Status     | Reason                                                                 |
| ------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------- |
| Public Zotero API completeness is the final server target           | Accepted   | Enables standard clients and prevents product-specific protocol drift  |
| Deliver API compatibility through profiles                          | Accepted   | Keeps the large public surface measurable and releasable               |
| Use `dataserver` as behavior reference, not deployment architecture | Accepted   | Preserves semantics without MySQL/shard/cache infrastructure           |
| One deployment equals one tenant                                    | Accepted   | Multi-user/groups need no second tenancy layer                         |
| Implement multi-user/groups/roles during pre-alpha                  | Accepted   | They are foundational API semantics, not optional GUI features         |
| Keep flexible Zotero objects canonical in JSONB                     | Accepted   | Supports object-level sync and upstream schema evolution               |
| Normalize identities, keys, libraries, groups, and memberships      | Accepted   | Security invariants require relational constraints                     |
| Authenticate OIDC at a trusted reverse proxy                        | Accepted   | Keeps provider-specific protocol outside xotero                        |
| Map `(issuer, subject)` to local users                              | Accepted   | Email is not a stable identity key                                     |
| Use pinned upstream Web Library as the only client                  | Accepted   | See ADR 0002                                                           |
| Keep `/keys/sessions` and `/login` login sessions                   | Accepted   | See ADR 0002                                                           |
| Use patched official Zotero throughout pre-alpha                    | Superseded | Desktop support is removed                                             |
| Begin custom browser Web Library after stable beta                  | Superseded | Upstream Web Library is packaged instead                               |
| Begin custom agent-first client at alpha                            | Superseded | Web Library is the only client                                         |
| Harden multi-user behavior during beta                              | Accepted   | Functional support precedes production security/concurrency claims     |
| Keep agent provider credentials in native agent runtimes            | Accepted   | Enables subscriptions without credential extraction                    |
| Separate tool adapters from optional session adapters               | Superseded | No dedicated GUI needs session adapters                                |
| Use Pi as the first deep session adapter                            | Superseded | No dedicated GUI needs session adapters                                |
| Implement the server in Rust with Tokio and Axum                    | Accepted   | Existing behavior is proven and the stack exposes exact HTTP semantics |
| Keep the public API on Zotero-compatible HTTP/JSON                  | Accepted   | Standard clients cannot consume a replacement gRPC boundary            |
| Use Rust types and traits for in-process application boundaries     | Accepted   | Avoids premature serialization and distributed-system failure modes    |
| Reserve gRPC for a future independent native service if justified   | Accepted   | Browser and agent boundaries remain easier to operate over JSON        |
| Keep WASM out of the pre-alpha server critical path                 | Accepted   | It does not improve database, storage, or process durability           |
| Keep pure domain logic portable for optional client WASM later      | Accepted   | Complex deterministic logic may eventually be shared with browsers     |
| Use nixpkgs RustFS for integration tests                            | Accepted   | Removes a duplicate, unchecked package recipe from this repository     |
| Reproduce Zotero.org internal infrastructure                        | Rejected   | Not required for public API compatibility                              |
