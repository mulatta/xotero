# xotero design

This file describes the system as it exists. Plans belong in `ROADMAP.md`, the
wire contract belongs in `API.md`, and the reasons for accepted decisions belong
in `adr/`.

## Purpose

xotero is a self-hosted, multi-user server for the public Zotero Web API. It
follows Zotero's HTTP contract and keeps a smaller storage and deployment
architecture than Zotero's `dataserver`. `dataserver` is a behavioral reference,
not an architecture to reproduce.

## Deployment model

One deployment is one tenant, and it contains many users, personal libraries, and
group libraries. There is no application-level `tenant_id`. Isolation between
deployments comes from separate xotero, PostgreSQL, object storage, and identity
provider configuration.

```text
browser or API client
    -> trusted reverse proxy (OIDC)
    -> xotero on a loopback address
    -> PostgreSQL (metadata and state)
    -> S3-compatible object store (attachment bytes)
```

## Repository layout

| Path                  | Contents                                                 |
| --------------------- | -------------------------------------------------------- |
| `xotero/src/main.rs`  | process bootstrap                                        |
| `xotero/src/app.rs`   | router assembly                                          |
| `xotero/src/http/`    | middleware, request access, headers, validation          |
| `xotero/src/handlers/` | one module per API family                               |
| `xotero/src/store/`   | store facade and one module per persistence domain       |
| `xotero/src/upload.rs` | bounded attachment upload path                          |
| `xotero/migrations/`  | ordered SQL migrations                                   |
| `nix/`                | package, NixOS module, checks and VM test scripts        |
| `checks/`             | API contract inventory                                   |

## Identity and authentication

OIDC stays at the reverse proxy. The server maps verified `(issuer, subject)`
claims to a local user, and email is never an identity key. The server requires a
loopback bind address because the proxy is the only party allowed to set identity
headers.

Three paths issue or carry credentials:

- `Zotero-API-Key` carries a database-backed key that is hashed, owned by a user,
  scoped, and revocable. Recovery credentials come only from the `XOTERO_KEYS`
  manifest and are hashed and validated at startup.
- Web sessions use a server-side session with a CSRF header `x-xotero-csrf`.
  Mutations must present it.
- `/keys/sessions` and `/login` run a browser-approved login session. After OIDC
  approval, the server issues a user-owned API key derived with
  `loginKdfKeyFile`.

Instance administrators are explicit records, and bootstrap runs once.

Each request rechecks the live user and identity state. Disabling a user also
revokes every key the user owns and their web sessions, and unlinking an
identity revokes the web sessions bound to it, so re-enabling or relinking never
revives those credentials.

## Authorization

Every authenticated request resolves to one `RequestContext` before a handler
touches data. The context holds the principal, the library, and the permissions.
`/users/<id>/...` and `/groups/<id>/...` resolve to a library, and then share data
handlers. URL identifiers, object keys, and file keys never bypass this context.

Requests are routed first, so an unknown path is 404 whatever the key. Matched
requests are authorized before the server reads their bodies. Lookup failures
return an error and never fall back to a permissive default.

Group roles are owner, admin, and member. Group lifecycle, membership, and
ownership transitions live under `/xotero/...`.

## Data model

Items, collections, searches, and settings stay canonical JSONB objects. This
preserves unknown upstream fields and supports object-level sync. An indexed
projection must be derivable from canonical data or have a documented rebuild
path.

Security and ownership data is relational, so constraints and transactions
enforce it:

- identity: `users`, `external_identities`, `instance_admins`, `bootstrap_state`
- credentials: `api_keys`, `api_key_user_permissions`,
  `api_key_group_permissions`, `api_key_all_groups_permissions`
- libraries: `library`, `personal_libraries`, `groups`, `group_memberships`,
  `storage_policy`
- sessions: `login_sessions`, `web_sessions`, `web_challenges`
- audit: `audit_events`

## Attachments

Bytes live in object storage. `file` rows hold the current pointer, and
`pending_uploads` holds in-flight upload state in PostgreSQL so restarts do not
lose it. New blobs use `libraries/<library-id>/uploads/<upload-token>` keys. Blobs
from the original single-user library keep their legacy bare keys.

Registration rechecks the original upload authority inside the transaction.

Removed blobs enter `blob_retirements`, so issued pre-signed URLs can expire
before deletion. Uploads stream through bounded hashing with concurrency, size,
and time limits. An upload whose remote outcome is unknown keeps its pending row
as a cleanup identity, so a late remote write is still deleted.

## Schema metadata

The server embeds one `zotero-schema` commit at build time: the one that Web
Library 1.8.3 vendors, packaged as `packages.zotero-schema`. `/schema` returns
that file unchanged. The mapping routes (`/itemTypes`, `/itemFields`,
`/creatorFields`, `/itemTypeFields`, `/itemTypeCreatorTypes`) and the
`/items/new` templates derive from it, following dataserver's shapes, ordering,
locale fallback, and errors. They need no API key because they carry no library
data, but a presented key must be valid. A schema that lacks en-US strings,
repeats an item type, or gives a type other than one primary creator type fails
startup. Every response carries `Zotero-Schema-Version`.

## Migrations

- Every schema change is an ordered migration. Merged migrations are not edited.
- Tests start from realistic previous schemas and data.
- Performance normalization happens only from measured query or integrity needs.
- `xotero migrate` applies pending migrations and exits. It opens no listener,
  starts no background loop, and changes no identity or upload state. A failed
  migration exits 1. Unknown arguments print the usage and exit 2.
- The NixOS module runs `xotero migrate` as `ExecStartPre` with the service's
  environment and credentials, so a failed migration stops the unit before it
  listens.
- Serving still applies pending migrations at startup, so a process started
  without the separate step reaches the same schema.

## Not reproduced from upstream

Zotero.org internal administration, billing, MySQL sharding, Redis, Memcached,
Elasticsearch, SQS, SNS, StatsD, Scribe, TTS, translation services, and the
Zotero.org website. A public endpoint that depends on one of these still needs a
smaller local implementation.
