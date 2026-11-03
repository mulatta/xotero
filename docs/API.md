# xotero API

> Rewrite pending. This text predates multi-user support. It still says single
> user and omits `/groups/...` and `/xotero/...`. Use `checks/contracts` and the
> code until the rewrite lands.

## Support levels

Each behavior below is one of two levels:

- **Verified.** A NixOS subtest exercises it against real PostgreSQL and
  RustFS, and its inventory entry in `checks/contracts/data/web-api.json` has
  proof state `covered` naming that subtest.
- **Target.** The inventory records the upstream wire shape in a fixture, but
  the proof state is still `pending` or `partial`. The server may differ.

The inventory is authoritative. Sections that do not name a level describe
the sync subset this document was first written for.

Derived from the Zotero client sync code (`~/git/zotero/chrome/content/zotero/xpcom/sync/`,
`storage/zfs.js`), the official Web API v3 docs, and live testing against a real
Zotero 9 client. This is the contract the server must satisfy so a
(URL-redirected) stock client syncs against it. The server implements the entire
sync contract below; "out of scope" items remain unimplemented. The
"Read/query API (CLI-facing extension)" section is also implemented, but is a
xotero addition beyond the sync subset — it is not part of what the sync client
needs.

Client file references use `syncAPIClient.js` (the request layer), `syncEngine.js`
(sync flow), `zfs.js` (file storage).

Behaviours confirmed by live testing (each is a hard requirement):

- **Auth is the login-session flow, not credentials.** Zotero 9's "Login" calls
  `POST /keys/sessions`, opens the returned `loginURL` in a browser, then polls
  `GET /keys/sessions/<token>` until it reports `status: "completed"` with the
  API key. It does not use `POST /keys` with a username/password.
- **Write bodies are gzip-compressed** (`Content-Encoding: gzip`); the server
  must decode them.
- **Write `successful` must return the full canonical object** (with `itemType`
  etc.) — echoing a partial upload makes the client throw "Unknown item type".
- **Attachment `data` must emit `linkMode` before `filename`.** The client's
  `fromJSON` processes fields in order and errors ("Link mode must be set before
  setting attachment path") otherwise; jsonb sorts keys alphabetically, so the
  server reorders linkMode to the front.
- **File download is a `302`** carrying `Location` plus `Zotero-File-MD5` and
  `Zotero-File-Modification-Time`; the client reads those headers and fetches the
  bytes from `Location` separately (it does not auto-follow the redirect).
- Attachment uploads exceed common default request-body limits; do not cap them.
- Client-facing URLs (`loginURL`, the file upload `url`, the download `Location`)
  must be the public/reverse-proxy address, not the internal bind address.

## Scope (MVP)

- **Single user, single personal library.** `userID` is configured. Groups are
  out of scope: `GET /users/<id>/groups?format=versions` returns `{}` so the
  client syncs only the personal library.
- **S3-backed file storage.** Attachment bytes live in an S3-compatible bucket
  (Cloudflare R2). Uploads still pass through the server — it verifies the md5 and
  PUTs the object — but downloads redirect the client to a pre-signed GET URL it
  follows straight to the bucket, so the read path bypasses the server.
- **Out of scope:** group libraries, binary-diff file upload (`PATCH .../file` —
  an API-only capability the desktop client's `storage/zfs.js` never implements;
  it always uploads the full file, so the server never sees a partial upload),
  the streaming/websocket server (client falls back to polling), and `/schema`
  (the client uses its bundled `resource://zotero/schema/global/schema.json` and
  updates it from repo.zotero.org, not from the sync API).

## Auth

API key travels in the `Zotero-API-Key` header on every request except the key
endpoints. Reject unknown keys with 403.

### Access keys

Keys are provisioned out of band (the server never mints them) and held in
memory, loaded at boot from secret files — no key material in the store or
database. Each key carries an access level; the token bytes stay in the secret
while the level is declared in deployment config:

- **read/write** — full sync access (the Zotero app needs this).
- **read-only** — every read works, but `POST`/`PATCH`/`DELETE` are rejected
  with `403`. Intended for the CLI / an agent, so automation can't mutate the
  library.

`GET /keys/current` reports the requesting key's own access (`access.user.write`
reflects read-only); the login session (`/keys/sessions`) hands out a read/write
key, since the app that drives it needs to write. Config: `XOTERO_KEYS` is a
comma-separated list of `<role>:<path>` entries (`rw`/`ro`); each path is a
single-line token file. `XOTERO_API_KEY_FILE` and `XOTERO_API_KEY` are removed,
and setting either one fails startup.

### Enrollment & public exposure

The data API is safe to expose publicly: every request carries a strong bearer
token (`Zotero-API-Key`) over HTTPS, the same posture as any API-key service. The
one path that *hands out* a key is the login session, so that — and only that — is
gated. A session is created `pending` and yields no key; it is authorized only by
the `/login` step. `GET /login?session=<token>` just renders a consent page;
the **`POST`** from its Approve button authorizes the session. Splitting render
from action stops a prefetch or cross-site `GET …/login?session=…` from silently
authorizing (the attacker can create the session, so a GET-authorize would be a
confused-deputy key grant); the `POST` additionally rejects a foreign `Origin`.
The Zotero client opens `loginURL` in the user's browser, so `/login` is placed
behind an SSO gate (oauth2-proxy → an identity provider): the key is released only
once an authenticated human clicks Approve. The server binds to localhost and is
exposed only through that proxy, so `/login` cannot be reached unauthenticated.
When `login_authorized_user` is set, `POST /login` additionally requires the proxy
to forward a matching identity (`X-Auth-Request-Email`/`-User`), tying the approval
to a proven identity (defence-in-depth against a misconfigured/bypassed proxy).
(On a private network — WireGuard/ZeroTier — the network itself is the gate, and
the SSO step and this check can be dropped.)

| Endpoint | Notes |
|---|---|
| `GET /keys/current` | Return `{userID, username, displayName, access}` with full access (`access.user = {library:true, notes:true, write:true, files:true}`). Client reads `userID` + `access`. (syncAPIClient.js:53) |
| `POST /keys/sessions` | **The login flow Zotero 9 actually uses.** Mint a pending session; respond `201` `{sessionToken, loginURL}` where `loginURL` is `<public>/login?session=<token>`. (syncAPIClient.js:575) |
| `GET /keys/sessions/<token>` | Polled until done. `200` `{status:"pending"}` until the session is authorized (no key), then `{status:"completed", apiKey, userID, username}`. |
| `GET /login?session=<token>` | Renders the consent page for the session (the user reaches it from `loginURL` in their browser); does not authorize. `400` without `session`, `404` if unknown/expired. Gated by SSO in production — see Enrollment. |
| `POST /login` (form `session=<token>`) | Authorizes the session (the Approve button). Rejects a foreign `Origin` with `403`. |
| `DELETE /keys/sessions/<token>` | Cancel a pending session. `204`. |

## Required headers

**Request (all):** `Zotero-API-Version` (int, e.g. 3), `Zotero-Schema-Version`
(int), `Zotero-API-Key`. **Write requests also:** `If-Unmodified-Since-Version`,
`Content-Type: application/json` (or `application/x-www-form-urlencoded` for file
params), and `Content-Encoding: gzip` — the JSON body is gzipped and must be
decoded before parsing.

**Response (server must set):** `Last-Modified-Version` on every data response and
version-listing response. `Link` (`<url>; rel=next`) + `Total-Results` for
pagination. Optional `Backoff` / `Retry-After` (MVP can omit — no throttling).

## Version model

A monotonic **library version** counter. Every write that changes the library
bumps it; the new value is returned in `Last-Modified-Version`. Each object also
carries its own `version` (the library version at which it last changed).

- **Reads** with `since=<v>` return only objects with `version > v` — `200` with
  the (possibly empty `{}`) map plus `Last-Modified-Version`, **never `304`**. The
  client's `getVersions` sends no `If-Modified-Since-Version` header and treats a
  `304` as "no data", which then mismatches its library-version check and loops
  the sync. `304` is reserved for requests that *do* send the
  `If-Modified-Since-Version` header (settings), which the client handles.
- **Writes** send `If-Unmodified-Since-Version: <clientLibraryVersion>`. If the
  server's library version is greater → `412 Precondition Failed`. The client
  then restarts the sync from the top. (syncAPIClient.js:1019)
- Writes must be serialized per library so the counter and conditional checks
  are atomic.

## Data sync endpoints

`<prefix>` = `/users/<userID>`. Objects: `collections`, `searches`, `items`
(also `settings`, `tags` handled specially).

### Download

| Request | Response |
|---|---|
| `GET <prefix>/settings?since=<v>` (`If-Modified-Since-Version`) | `200` `{settingKey: {value: ...}}` or `304`. (syncAPIClient.js:118) |
| `GET <prefix>/deleted?since=<v>` | `200` `{collections:[keys], searches:[keys], items:[keys], tags:[{tag,type}]}`. `409` if `since` precedes the delete-log start. (syncAPIClient.js:151) |
| `GET <prefix>/{collections,searches,items}?format=versions&since=<v>` (items also `includeTrashed=1`, optional `?top` via `items/top`) | `200` `{key: version}` (empty `{}` if none) + `Last-Modified-Version`; **never `304`** (getVersions sends no header and loops on a 304). (syncAPIClient.js:213) |
| `GET <prefix>/{collections,searches,items}?{objectKey}=k1,k2,...&format=json` | `200` array of `{key, version, data}`. Client batches ≤100 keys/request. (syncAPIClient.js:269) |
| `GET <prefix>/fulltext?format=versions&since=<v>` | `200` `{itemKey: version}`. (syncAPIClient.js:462) |
| `GET <prefix>/items/<key>/fulltext` | `200` `{indexedChars, totalChars, indexedPages, totalPages, content}` or `404`. The `Last-Modified-Version` here **must equal** that item's value in the versions map above (it is the row's own version, not the current library version); otherwise the client re-downloads content it already holds every sync. (syncAPIClient.js:484, syncFullTextEngine.js:91) |

### Write

All writes return `Last-Modified-Version` and use `If-Unmodified-Since-Version`.

| Request | Response |
|---|---|
| `POST <prefix>/{collections,searches,items}` — body: JSON array (client batches ≤10, API allows ≤50) | `200` upload-result object (below) or `412`. **Create-or-update with merge:** for an existing key, the provided top-level fields are overlaid onto the stored object (omitted fields kept, empty value clears). The sync client uploads only an existing object's *changed* fields here — e.g. just `lastRead` after opening an attachment — so a full replace would drop `itemType`/`linkMode` and corrupt it. (syncAPIClient.js:393) |
| `PATCH <prefix>/{...}` | Same merge semantics as POST (explicit partial update). |
| `DELETE <prefix>/{collections,searches,items}?{objectKey}=k1,k2,...` (client batches ≤25); tags via `?tags=t1\|\|t2` | `204` or `412`. (syncAPIClient.js:430) |
| `POST <prefix>/settings` — body `{key: {value}}` (≤250/batch) | `200` result obj / `204` / `412`. (syncAPIClient.js:359) |
| `DELETE <prefix>/settings?settingKey=k1,k2` | `204` / `412`. (syncAPIClient.js:336) |
| `POST <prefix>/fulltext` — array `{key, content, indexedChars, totalChars, indexedPages, totalPages}` (≤10 items / 500KB) | `200` result obj / `412`. (syncAPIClient.js:506) |

**Upload-result object** (HTTP 200, parsed at syncEngine.js:1375). Keyed by the
object's index in the submitted batch; each value is the **full canonical
object** the client round-trips (a partial echo is rejected):
```json
{
  "successful": { "0": { "key": "...", "version": N, "data": { } } },
  "success":    {},
  "unchanged":  {},
  "failed":     {}
}
```
`failed` code `<500` = permanent (client drops), `>=500` = retry.

## File sync (ZFS-style, S3-backed)

Three-step upload, then download. Client code: `zfs.js`. The Zotero upload
contract is unchanged (the client still POSTs the bytes to the server); the
server forwards them to the bucket rather than to disk, and the download
redirects the client straight to the bucket.

1. **Authorization** — `POST <prefix>/items/<key>/file`,
   `Content-Type: application/x-www-form-urlencoded`, header `If-None-Match: *`
   (new) or `If-Match: <oldmd5>` (replace). Body:
   `md5, filename, filesize, mtime` (mtime in ms; multi-file attachments add
   `zipMD5, zipFilename`). Responses:
   - already present → `200` `{ "exists": 1 }` (+ `Last-Modified-Version`).
   - upload needed → `200` `{ url, contentType, prefix, suffix, uploadKey }`
     (point `url` at the server's own upload endpoint with empty `prefix`/`suffix`,
     so the client POSTs the raw bytes; `uploadKey` is an unguessable token).
   - `412` changed remotely, `413` over quota (+ `Zotero-Storage-Usage/Quota`),
     `428` missing precondition header. (zfs.js:326)
2. **Upload** — `POST` to `url` with body `prefix + filebytes + suffix`,
   `Content-Type: contentType`. (zfs.js:604) The server verifies the bytes
   against the authorized `md5`/`filesize`, PUTs the object to the bucket keyed by
   the item key, and responds `201`. A mismatch is `400` (the integrity check is
   here, where the bytes are in hand). Bytes never touch the server's disk.
3. **Registration** — `POST <prefix>/items/<key>/file`,
   form body `upload=<uploadKey>`, same `If-Match`/`If-None-Match`. Respond
   `204` + `Last-Modified-Version`; record the file metadata and **stamp
   `md5`/`mtime` into the attachment item's `data`** (the downloading client needs
   them to reconcile the file), bumping the library version. (zfs.js:703)

**Download** — `GET <prefix>/items/<key>/file`. Respond **`302`** (the client
reads metadata from it without following) with `Location` set to a **short-lived
pre-signed GET URL** pointing at the bucket, plus `Zotero-File-MD5`,
`Zotero-File-Modification-Time` and `Zotero-File-Compressed: No`. The client then
GETs `Location` directly from the bucket. The pre-signed URL is an unguessable,
expiring capability, so it needs no API key (mirroring how the client downloaded
from S3 against zotero.org). `404` if absent. (zfs.js:52, zfs.js:109)

## Listings

### Verified

`nixos-sync` subtests `personal listings match the 22a fixtures` and
`private-group listings match the 22a fixtures` seed
`checks/contracts/data/listing-seed.json` into a user and a group library,
then replay each Task 22a fixture and page every listing to its end.

Routes, under `/users/<id>` and `/groups/<id>`: `/items`, `/items/top`,
`/items/trash`, `/collections/<key>/items`, `/collections/<key>/items/top`,
`/collections`, `/searches`.

- `format` is `json` (default), `keys` or `versions`. Any other value,
  including `atom` and the export formats, answers `400`
  `{"error":"Unsupported API combination"}`.
- `sort` must be a dataserver sort field for the route, and `direction` must
  be `asc` or `desc`; otherwise the same `400`. Without `direction`, date
  fields sort descending and other fields ascending. Ties order by object
  version, then key, in the same direction.
- `limit` defaults to 25 (max 100) for `json`. `keys` and `versions` are
  unlimited unless `limit` is given. `start` offsets the page. `since` keeps
  objects whose version is greater.
- Every response carries `Last-Modified-Version` and `Total-Results`, the
  full match count.
- `Link` lists `first`, `prev`, `next` and `last` as dataserver builds them:
  only non-default parameters, sorted by name, and `first`/`last` only when
  they differ from the requested page. xotero has no website, so it never
  emits `rel="alternate"`. A single-page listing has no `Link`.
- `keys` is `text/plain`, one key per line with a trailing newline.
  `versions` is a `{key: version}` object.
- `/items` excludes trashed items in every format unless `includeTrashed` is
  set. `/items/trash` lists only trashed items.
- `json` entries are dataserver envelopes:
  - item: `{key, version, library, links, meta, data}`. `links.self`, and
    `links.up` for a child. `meta` holds `creatorSummary` and `parsedDate` for
    regular items, and `numChildren` for regular items, notes and PDF
    attachments.
  - collection: the same, with `links.up` for a subcollection and `meta`
    `{numCollections, numItems}`.
  - search: `{key, version, library, links, data}` with no `meta`.
  - `library` is `{type, id, name}`, named after the user's display name or
    the group.

### Target

- Group item `meta.createdByUser` and `meta.lastModifiedByUser`, and the
  `links.attachment` and `links.enclosure` file links, are not emitted.
- `itemKey`, `collectionKey` and `searchKey` batch reads still return bare
  `{key, version, data}` objects (Task 22b).
- Query filters and tag listings below are inventory targets for Task 22b.

## Read/query API (CLI-facing extension)

Beyond the sync subset above, these read endpoints exist so a token-holding CLI
or agent can find and fetch items without the Zotero app. They are query-only
(no styled bibliography/citation rendering, no schema endpoints — those stay
downstream, e.g. an agent or pandoc working from the raw JSON / CSL-JSON). A
read-only key (see Auth) is enough to drive all of them, so automation can read
without write access.

Item listings (`GET /users/<id>/items?format=json`) accept:

| Param | Meaning |
|---|---|
| `q` + `qmode` | Search term. `titleCreatorYear` (default) matches title/creators/date; `everything` also matches stored full-text content. |
| `itemType` | Filter by type (`book`; OR via `a \|\| b`; negate via `-note`). |
| `tag` | Filter by tag (repeat for AND, `\|\|` for OR). |
| `sort`, `direction`, `limit`, `start`, `since` | See Listings. |
| `includeTrashed` | Include trashed items (excluded by default). |

Convenience listings: `GET /users/<id>/items/top` (no `parentItem`),
`/items/trash` (`data.deleted`), `/tags` (distinct tags as `[{tag, numItems}]`,
trashed items excluded), `/collections/<key>/items` and
`/collections/<key>/items/top` (`data.collections` contains the key). The item
listings carry the same search/filter/sort/paginate params as `/items`;
`/items/top` also still answers the sync `format=versions`/`itemKey` reads the
client may send there.

Matching is case-insensitive substring (`ILIKE`). The default `titleCreatorYear`
search runs against an immutable `xotero_item_text(data)` expression (title, date
and creator names) carrying a `pg_trgm` GIN index (migration `0005`), so it is
index-backed rather than a sequential scan. Full-text search (`qmode=everything`)
additionally matches the `fulltext` table — also `pg_trgm`-indexed on `content`
(migration `0004`); because that mode ORs across the `fulltext` table it falls
back to a scan of the candidate items.

## Storage backend (PostgreSQL + S3)

Metadata in PostgreSQL; attachment bytes in an S3-compatible bucket (R2).

Tables (see `migrations/`):
- `library(id, version)` — the monotonic counter.
- `object(library_id, kind, key, version, data jsonb)` — items, collections,
  searches; `version`-indexed for `since` queries. Trashed state lives in
  `data.deleted`, not a column.
- `setting(library_id, key, value jsonb, version)`.
- `fulltext(library_id, item_key, content, indexed_chars, total_chars, indexed_pages, total_pages, version)`.
- `deletion(library_id, kind, key, version)` — the delete log for `/deleted`.
- `file(library_id, item_key, md5, filename, filesize, mtime, version)` — file
  **metadata** only; the bytes live in the bucket under the item key.

Not in the database: **attachment bytes** live in the S3 bucket (config via
`XOTERO_S3_*`; credentials loaded from secret files at boot). **API keys** are held
in memory, loaded from secret files at boot (see Auth → Access keys). **Pending
uploads** (between the file authorisation and registration steps) and **login
sessions** (between creation and authorization) are held in memory, keyed by
their respective unguessable tokens.

Writes run in a transaction that bumps `library.version` and stamps the affected
rows, so conditional version checks are atomic.

## Resolved by live testing

- `data` JSON shape: stored opaquely and round-tripped verbatim; only the
  discriminator field order matters — `linkMode` first for attachments,
  `annotationType` first for annotations (the server re-emits both first, since
  jsonb sorts keys alphabetically and the client's `fromJSON` requires them
  before the fields that depend on them).
- **Object keys** are 8 chars from a base32 alphabet (`23456789ABCDEFGHIJKLMNPQRSTUVWXYZ`
  — digits 2-9 and A-Z without `0`/`1`/`O`). The client rejects anything else
  ("key is not valid") and queues it, so the server rejects a malformed key on
  write with `400` rather than letting it sync. A keyless object on `POST` is
  assigned a fresh valid key. (Schema is *not* validated — only this stable
  structural invariant; item types/fields stay opaque for forward-compatibility.)
- `Zotero-Write-Token` is not required — the client never sends it; the
  `If-Unmodified-Since-Version` → 412 guard is sufficient.
- `mtime` is in milliseconds.
- `POST /keys` is unused by Zotero 9 (it uses the login session), so it is not
  implemented; the key is provisioned as a secret file out of band.
