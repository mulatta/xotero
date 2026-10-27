"""End-to-end coverage of the xotero sync API, driven over HTTP against the
nixosModule-deployed service. Grouped by flow rather than per endpoint, since
each run boots a VM."""

import shlex

base = "http://localhost:8189"
auth = "-H 'Zotero-API-Key: testtoken' -H 'Zotero-API-Version: 3'"
readonly = "-H 'Zotero-API-Key: readonlytoken' -H 'Zotero-API-Version: 3'"
oidc_issuer = "https://id.example.test"
oidc_subject = "owner-subject"
oidc = (
    f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}' "
    f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}'"
)


def http_code(args):
    return machine.succeed(f"curl -s -o /dev/null -w '%{{http_code}}' {args}").strip()


def psql(sql):
    escaped = sql.replace("'", "'\"'\"'")
    return machine.succeed(
        f"sudo -u xotero psql -v ON_ERROR_STOP=1 -At -d xotero -c '{escaped}'"
    ).strip()


def library_version():
    return machine.succeed(
        f"curl -sf -D - -o /dev/null '{base}/users/1/items?format=versions&since=0' {auth} "
        f"| grep -i last-modified-version | tr -d '\\r' | cut -d' ' -f2"
    ).strip()


def restart_xotero():
    machine.succeed("systemctl reset-failed xotero.service")
    machine.succeed("systemctl restart xotero.service")
    machine.wait_for_unit("xotero.service")
    machine.wait_for_open_port(8189)


def assert_attachment(item_key, expected_md5, expected_body, scratch):
    headers = f"/tmp/{scratch}.headers"
    machine.succeed(
        f"curl -sf -D {headers} -o /dev/null "
        f"{base}/users/1/items/{item_key}/file {auth}"
    )
    machine.succeed(f"grep -iq 'zotero-file-md5: {expected_md5}' {headers}")
    location = machine.succeed(
        f"grep -i '^location:' {headers} | tr -d '\\r' | awk '{{print $2}}'"
    ).strip()
    actual_body = machine.succeed(f"curl -sf '{location}'").strip()
    assert actual_body == expected_body, (expected_body, actual_body)


machine.wait_for_unit("postgresql.service")
machine.wait_for_unit("rustfs.service")
machine.wait_for_open_port(9000)
machine.wait_for_unit("xotero.service")
machine.wait_for_open_port(8189)

# Create the attachment bucket in the S3 store before any upload.
machine.succeed("mc alias set s3 http://localhost:9000 rustfsadmin rustfsadmin")
machine.succeed("mc mb s3/zotero")

with subtest("the module deploys a working service backed by postgres"):
    assert http_code(f"{base}/keys/current {auth}") == "200"
    machine.succeed(
        f"""curl -sf {base}/keys/current {auth} |
        jq -e '.access.groups == {{
          "all":{{"library":true,"write":true}}
        }}'"""
    )
    machine.succeed(
        f"""curl -sf {base}/keys/current {readonly} |
        jq -e '.access.groups == {{
          "all":{{"library":true,"write":false}}
        }}'"""
    )

with subtest("bootstrap OIDC identity owns the default personal library"):
    assert (
        psql(
            f"""select user_id = 1
                from external_identities
                where issuer = '{oidc_issuer}' and subject = '{oidc_subject}'"""
        )
        == "t"
    )
    assert (
        psql(
            """select count(*) = 1
               from external_identities
               where user_id = 1"""
        )
        == "t"
    )
    assert psql("select library_id from personal_libraries where user_id = 1") == "1"

with subtest("login session hands out the key only after authorization"):
    machine.succeed(f"curl -sf -X POST {base}/keys/sessions -d '{{}}' > /tmp/sess")
    token = machine.succeed("jq -r .sessionToken /tmp/sess").strip()
    login_url = machine.succeed("jq -r .loginURL /tmp/sess").strip()
    assert token and f"session={token}" in login_url, login_url
    # GET /login renders a consent page only — it does NOT authorize, so a
    # prefetch or cross-site GET can't silently grant the key.
    machine.succeed(f"curl -sf '{login_url}' | grep -qi 'Authorize'")
    machine.succeed(f"curl -sf {base}/keys/sessions/{token} | jq -e '.status == \"pending\"'")
    machine.succeed(f"curl -sf {base}/keys/sessions/{token} | jq -e '.apiKey == null'")
    restart_xotero()
    machine.succeed(f"curl -sf {base}/keys/sessions/{token} | jq -e '.status == \"pending\"'")
    # A cross-site form POST (foreign Origin) is refused even with a valid identity.
    assert (
        http_code(f"-X POST {base}/login -H 'Origin: https://evil.example' {oidc} -d 'session={token}'")
        == "403"
    )
    # Authorization requires both stable OIDC claims and their exact configured pair.
    rejected_identities = (
        "",
        f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}'",
        f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}'",
        (
            f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}' "
            f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}' "
            f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}'"
        ),
        (
            f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}' "
            f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}' "
            f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}'"
        ),
        "-H 'X-Auth-Request-Email: owner@mulatta.io'",
        (
            f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}' "
            "-H 'X-Xotero-OIDC-Subject: unknown-subject'"
        ),
        (
            "-H 'X-Xotero-OIDC-Issuer: https://other-id.example.test' "
            f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}'"
        ),
    )
    for identity_headers in rejected_identities:
        assert (
            http_code(
                f"-X POST {base}/login {identity_headers} -d 'session={token}'"
            )
            == "403"
        )
        machine.succeed(
            f"curl -sf {base}/keys/sessions/{token} "
            "| jq -e '.status == \"pending\" and .apiKey == null'"
        )

    # The consent POST (Approve) with the exact identity completes the flow.
    machine.succeed(f"curl -sf -X POST {base}/login {oidc} -d 'session={token}'")
    machine.succeed(f"curl -sf {base}/keys/sessions/{token} > /tmp/completed-session")
    login_key = machine.succeed("jq -r .apiKey /tmp/completed-session").strip()
    assert len(login_key) == 24
    assert set(login_key) <= set("23456789ABCDEFGHIJKLMNPQRSTUVWXYZ"), login_key
    assert login_key != "testtoken"
    machine.succeed(
        "jq -e '.status == \"completed\" and .userID == 1 and .username == \"xotero\"' "
        "/tmp/completed-session"
    )

    restart_xotero()
    machine.succeed(f"curl -sf {base}/keys/sessions/{token} > /tmp/restarted-session")
    assert machine.succeed("jq -r .apiKey /tmp/restarted-session").strip() == login_key
    machine.succeed(
        "jq -e '.status == \"completed\" and .userID == 1 and .username == \"xotero\"' "
        "/tmp/restarted-session"
    )
    machine.succeed(
        f"""curl -sf -H 'Zotero-API-Key: {login_key}' {base}/keys/current |
        jq -e '. == {{
          "key":"{login_key}",
          "userID":1,
          "username":"xotero",
          "displayName":"xotero",
          "access":{{
            "user":{{
              "library":true,"files":true,"notes":true,"write":true
            }},
            "groups":{{"all":{{"library":true,"write":true}}}}
          }}
        }}'"""
    )
    assert http_code(f"-X DELETE {base}/keys/sessions/{token}") == "409"

    machine.succeed(f"curl -sf -X POST {base}/keys/sessions -d '{{}}' > /tmp/cancel-session")
    cancel_token = machine.succeed("jq -r .sessionToken /tmp/cancel-session").strip()
    assert http_code(f"-X DELETE {base}/keys/sessions/{cancel_token}") == "204"
    machine.succeed(
        f"curl -sf {base}/keys/sessions/{cancel_token} | jq -e '.status == \"cancelled\"'"
    )
    assert http_code(f"-X DELETE {base}/keys/sessions/{cancel_token}") == "409"

with subtest("the login consent endpoint validates the session token"):
    assert http_code(f"{base}/login") == "400"  # missing ?session
    assert http_code(f"{base}/login?session=nope") == "404"  # unknown session
    assert http_code(f"-X POST {base}/login {oidc} -d 'session=nope'") == "404"
    assert http_code(f"{base}/keys/sessions/nope") == "404"

with subtest("groups endpoint returns empty upstream listing shapes"):
    machine.succeed(f"curl -sf {base}/users/1/groups {auth} | jq -e '. == []'")
    machine.succeed(
        f"curl -sf '{base}/users/1/groups?format=versions' {auth} | jq -e '. == {{}}'"
    )

with subtest("the api key is required off the bootstrap paths"):
    assert http_code(f"{base}/keys/current -H 'Zotero-API-Version: 3'") == "403"

with subtest("a read-only key reads but cannot write"):
    assert http_code(f"'{base}/users/1/items?format=versions&since=0' {readonly}") == "200"
    machine.succeed(f"curl -sf {base}/keys/current {readonly} | jq -e '.access.user.write == null'")
    machine.succeed(f"curl -sf {base}/keys/current {auth} | jq -e '.access.user.write == true'")
    assert (
        http_code(
            f"-X POST {base}/users/1/items {readonly} "
            f"-H 'If-Unmodified-Since-Version: 0' "
            f"-d '[{{\"key\":\"RDNLY222\",\"itemType\":\"book\"}}]'"
        )
        == "403"
    )
    assert http_code(f"-X DELETE '{base}/users/1/items?itemKey=ITEM2223' {readonly}") == "403"

with subtest("an item round-trips through write and read"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: 0' "
        f"-d '[{{\"key\":\"ITEM2223\",\"itemType\":\"book\",\"title\":\"t\"}}]' "
        f"| jq -e '.successful.\"0\".key == \"ITEM2223\"'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?format=versions&since=0' {auth} | jq -e '.ITEM2223'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=ITEM2223&format=json' {auth} "
        f"| jq -e '.[0].data.itemType == \"book\"'"
    )

with subtest("a stale write is rejected with 412"):
    assert (
        http_code(
            f"-X POST {base}/users/1/items {auth} "
            f"-H 'If-Unmodified-Since-Version: 0' "
            f"-d '[{{\"key\":\"ITEMSTAL\",\"itemType\":\"book\"}}]'"
        )
        == "412"
    )

with subtest("a write without If-Unmodified-Since-Version is rejected with 428"):
    # Without the precondition the version guard would be bypassed.
    assert (
        http_code(
            f"-X POST {base}/users/1/items {auth} "
            f"-d '[{{\"key\":\"NPRECN22\",\"itemType\":\"book\"}}]'"
        )
        == "428"
    )

with subtest("a malformed object key is rejected with 400"):
    # The client refuses keys outside the 8-char base32 alphabet (no 0/1/O),
    # queuing them with "key is not valid"; reject them at the API instead.
    for bad in ["HASOABC2", "HAS0ABC2", "SHORTKY", "TOOLONGKY", "lowercs2"]:
        v = library_version()
        assert (
            http_code(
                f"-X POST {base}/users/1/items {auth} "
                f"-H 'If-Unmodified-Since-Version: {v}' "
                f'-d \'[{{"key":"{bad}","itemType":"book"}}]\''
            )
            == "400"
        ), bad
    # The version did not move (nothing was written).
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=HASOABC2&format=json' {auth} | jq -e '. == []'"
    )

with subtest("an empty batch does not bump the library version"):
    before = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {before}' -d '[]' | jq -e .successful"
    )
    assert library_version() == before, library_version()

with subtest("attachment data is emitted with linkMode first"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f"-d '[{{\"key\":\"ATTACH22\",\"itemType\":\"attachment\","
        f"\"linkMode\":\"imported_file\",\"filename\":\"t.pdf\","
        f"\"contentType\":\"application/pdf\"}}]' | jq -e .successful"
    )
    first_key = machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=ATTACH22&format=json' {auth} "
        f"| jq -r '.[0].data | keys_unsorted[0]'"
    ).strip()
    assert first_key == "linkMode", first_key

with subtest("an attachment file uploads to S3 and downloads via a presigned URL"):
    # md5 of "hello"; the upload endpoint verifies the bytes against it.
    md5 = "5d41402abc4b2a76b9719d911017c592"
    # Authorization returns an unguessable upload token (not the item key).
    token = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-None-Match: *' "
        f"-d 'md5={md5}&filename=t.pdf&filesize=5&mtime=1700000000000' "
        f"| jq -r .uploadKey"
    ).strip()
    assert token and token != "ATTACH22", token
    # Bytes are POSTed to the token URL (xotero verifies them and PUTs to S3);
    # registration then commits via the token.
    machine.succeed(f"printf hello | curl -sf -X POST {base}/uploads/{token} --data-binary @-")
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-None-Match: *' -d 'upload={token}'"
    )
    assert http_code(f"{base}/users/1/items/ATTACH22/file {auth}") == "302"
    # The 302 carries the md5/mtime headers and a Location that is a pre-signed
    # GET URL pointing straight at the S3 store; follow it (no API key) to read
    # the bytes, the way the stock client downloads from a presigned URL.
    location = machine.succeed(
        f"curl -sf -D /tmp/dlhdr -o /dev/null {base}/users/1/items/ATTACH22/file {auth} "
        f"&& grep -i '^location:' /tmp/dlhdr | tr -d '\\r' | awk '{{print $2}}'"
    ).strip()
    machine.succeed(f"grep -iq 'zotero-file-md5: {md5}' /tmp/dlhdr")
    # The redirect targets the object store directly, not this server.
    assert location.split("/", 3)[2] == "127.0.0.1:9000", location
    assert machine.succeed(f"curl -sf '{location}'").strip() == "hello"

with subtest("a Zotero ZIP attachment preserves original metadata and compressed bytes"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        "-d '[{\"key\":\"ZIPATT22\",\"itemType\":\"attachment\","
        "\"linkMode\":\"imported_file\",\"contentType\":\"text/plain\"}]' "
        "| jq -e .successful"
    )
    machine.succeed(
        "printf 'compressed hello' >/tmp/zipped.txt "
        "&& zip -jq /tmp/ZIPATT22.zip /tmp/zipped.txt"
    )
    original_md5 = machine.succeed("md5sum /tmp/zipped.txt | cut -d' ' -f1").strip()
    zip_md5 = machine.succeed("md5sum /tmp/ZIPATT22.zip | cut -d' ' -f1").strip()
    zip_size = machine.succeed("stat -c %s /tmp/ZIPATT22.zip").strip()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ZIPATT22/file {auth} "
        f"-H 'If-None-Match: *' "
        f"-d 'md5={original_md5}&filename=zipped.txt&filesize={zip_size}"
        f"&mtime=1700000000004&zipMD5={zip_md5}&zipFilename=ZIPATT22.zip' "
        "> /tmp/zip-auth.json"
    )
    machine.succeed("jq -e '.contentType == \"application/zip\"' /tmp/zip-auth.json")
    zip_token = machine.succeed("jq -r .uploadKey /tmp/zip-auth.json").strip()
    machine.succeed(
        f"curl -s -X POST {base}/users/1/items/ZIPATT22/file {auth} "
        f"-H 'If-None-Match: *' "
        f"-d 'md5={original_md5}&filename=zipped.txt&filesize={zip_size}"
        f"&mtime=1700000000004&zipMD5={zip_md5}' "
        "-o /dev/null -w '%{http_code}' | grep -qx 400"
    )
    machine.succeed(
        f"curl -s -X POST {base}/users/1/items/ZIPATT22/file {auth} "
        f"-H 'If-None-Match: *' "
        f"-d 'md5={original_md5}&filename=zipped.txt&filesize={zip_size}"
        "&mtime=1700000000004&zipFilename=ZIPATT22.zip' "
        "-o /dev/null -w '%{http_code}' | grep -qx 400"
    )
    restart_xotero()
    machine.succeed(
        "cp /tmp/ZIPATT22.zip /tmp/corrupt.zip "
        "&& printf X | dd of=/tmp/corrupt.zip bs=1 seek=10 conv=notrunc"
    )
    machine.succeed(
        f"curl -s -X POST {base}/uploads/{zip_token} "
        "--data-binary @/tmp/corrupt.zip -o /dev/null -w '%{http_code}' "
        "| grep -qx 400"
    )
    machine.succeed(
        f"curl -sf -X POST {base}/uploads/{zip_token} --data-binary @/tmp/ZIPATT22.zip"
    )
    restart_xotero()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ZIPATT22/file {auth} "
        f"-H 'If-None-Match: *' -d 'upload={zip_token}'"
    )
    zip_location = machine.succeed(
        f"curl -sf -D /tmp/ziphdr -o /dev/null "
        f"{base}/users/1/items/ZIPATT22/file {auth} "
        "&& grep -i '^location:' /tmp/ziphdr | tr -d '\\r' | awk '{print $2}'"
    ).strip()
    machine.succeed(f"grep -iq 'zotero-file-md5: {zip_md5}' /tmp/ziphdr")
    machine.succeed(f"grep -iq 'zotero-file-size: {zip_size}' /tmp/ziphdr")
    machine.succeed("grep -iq 'zotero-file-compressed: Yes' /tmp/ziphdr")
    machine.succeed(
        f"curl -sf -D /tmp/zip-object-hdr '{zip_location}' -o /tmp/downloaded.zip"
    )
    machine.succeed("grep -iq '^content-type: application/zip' /tmp/zip-object-hdr")
    machine.fail("grep -iq '^content-encoding:' /tmp/zip-object-hdr")
    assert machine.succeed("unzip -p /tmp/downloaded.zip zipped.txt").strip() == (
        "compressed hello"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=ZIPATT22&format=json' {auth} "
        f"| jq -e '.[0].data.md5 == \"{original_md5}\" "
        "and .[0].data.filename == \"zipped.txt\"'"
    )
    assert (
        psql(
            """select md5 || ':' || blob_md5 || ':' || compressed::text
               from file where library_id = 1 and item_key = 'ZIPATT22'"""
        )
        == f"{original_md5}:{zip_md5}:true"
    )

with subtest("re-authorizing the same file returns exists:1 (dedup)"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-None-Match: *' "
        f"-d 'md5=5d41402abc4b2a76b9719d911017c592&filename=t.pdf&filesize=5&mtime=1700000000000' "
        f"| jq -e '.exists == 1'"
    )

with subtest("an unregistered replacement cannot change the live attachment"):
    old_md5 = "5d41402abc4b2a76b9719d911017c592"
    world_md5 = "7d793037a0760186574b0282f2f435e7"
    abandoned = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-Match: {old_md5}' "
        f"-d 'md5={world_md5}&filename=t.pdf&filesize=5&mtime=1700000000001' "
        f"| jq -r .uploadKey"
    ).strip()
    assert (
        psql(
            f"""select count(*) = 1
                       and bool_and(position('{abandoned}' in row_to_json(p)::text) = 0)
                from pending_uploads p
                where library_id = 1 and item_key = 'ATTACH22'
                  and state = 'authorized'"""
        )
        == "t"
    )

    # A crash after the atomic claim but before S3 completion restores the token
    # to authorized when the single service process restarts.
    psql(
        """update pending_uploads set state = 'uploading'
           where library_id = 1 and item_key = 'ATTACH22'"""
    )
    restart_xotero()
    assert (
        psql(
            """select state from pending_uploads
               where library_id = 1 and item_key = 'ATTACH22'"""
        )
        == "authorized"
    )
    machine.succeed(
        f"printf world | curl -sf -X POST {base}/uploads/{abandoned} --data-binary @-"
    )
    assert (
        http_code(
            f"-X POST {base}/uploads/{abandoned} --data-binary 'world'"
        )
        == "409"
    )

    # Uploaded bytes are an immutable candidate. Until registration commits its
    # DB pointer, readers must still receive the old metadata and old bytes.
    assert_attachment("ATTACH22", old_md5, "hello", "replacement-before-restart")

    # Uploaded candidate also survives restart so desktop can finish registration
    # without re-uploading bytes.
    restart_xotero()
    assert_attachment("ATTACH22", old_md5, "hello", "replacement-after-restart")
    assert (
        http_code(
            f"-X POST {base}/users/1/items/ATTACH22/file {auth} "
            f"-H 'If-Match: {old_md5}' -d 'upload={abandoned}'"
        )
        == "204"
    )
    assert (
        psql(
            """select count(*) from pending_uploads
               where library_id = 1 and item_key = 'ATTACH22'"""
        )
        == "0"
    )
    assert_attachment("ATTACH22", world_md5, "world", "replacement-registered")

with subtest("expired upload candidates are deleted before their rows"):
    world_md5 = "7d793037a0760186574b0282f2f435e7"
    trash_md5 = "30639096bfe4ec4b9f17696ef1d02b9f"
    expired_token = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-Match: {world_md5}' "
        f"-d 'md5={trash_md5}&filename=t.pdf&filesize=5&mtime=1700000000002' "
        f"| jq -r .uploadKey"
    ).strip()
    machine.succeed(
        f"printf trash | curl -sf -X POST {base}/uploads/{expired_token} --data-binary @-"
    )
    expired_blob = psql(
        """select blob_key from pending_uploads
           where library_id = 1 and item_key = 'ATTACH22' and state = 'uploaded'"""
    )
    machine.succeed(f"mc stat 's3/zotero/{expired_blob}'")
    psql(
        """update pending_uploads
           set created_at = now() - interval '2 hours',
               expires_at = now() - interval '1 hour'
           where library_id = 1 and item_key = 'ATTACH22' and state = 'uploaded'"""
    )
    restart_xotero()
    assert psql("select count(*) from pending_uploads where token_hash is not null") == "0"
    machine.fail(f"mc stat 's3/zotero/{expired_blob}'")
    assert_attachment("ATTACH22", world_md5, "world", "expired-candidate-cleanup")
    psql(
        """insert into pending_uploads (
               token_hash, library_id, authorizer_key_hash, bootstrap_user_id,
               item_key, blob_key, md5, upload_md5, filename, filesize, mtime,
               created_at, expires_at
           )
           select decode(lpad(to_hex(i), 64, '0'), 'hex'), 1,
                  decode(repeat('00', 32), 'hex'), 1,
                  'GC' || lpad(i::text, 6, '0'),
                  'libraries/1/uploads/gc-' || i,
                  '00000000000000000000000000000000',
                  '00000000000000000000000000000000', 'gc', 0, 0,
                  now() - interval '2 hours', now() - interval '1 hour'
           from generate_series(1, 33) as i"""
    )
    restart_xotero()
    assert psql("select count(*) from pending_uploads") == "0"

with subtest("concurrent replacements compare-and-swap the registered md5"):
    world_md5 = "7d793037a0760186574b0282f2f435e7"
    first_md5 = "8b04d5e3775d298e78455efc5ca404d5"
    other_md5 = "795f3202b17cb6bc3d4b771d8c6c9eaf"
    version_before = int(library_version())

    first_token = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-Match: {world_md5}' "
        f"-d 'md5={first_md5}&filename=t.pdf&filesize=5&mtime=1700000000002' "
        f"| jq -r .uploadKey"
    ).strip()
    other_token = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-Match: {world_md5}' "
        f"-d 'md5={other_md5}&filename=t.pdf&filesize=5&mtime=1700000000003' "
        f"| jq -r .uploadKey"
    ).strip()
    machine.succeed(
        f"printf first | curl -sf -X POST {base}/uploads/{first_token} --data-binary @-"
    )
    machine.succeed(
        f"printf other | curl -sf -X POST {base}/uploads/{other_token} --data-binary @-"
    )

    assert (
        http_code(
            f"-X POST {base}/users/1/items/ATTACH22/file {auth} "
            f"-H 'If-Match: {world_md5}' -d 'upload={first_token}'"
        )
        == "204"
    )
    version_after_first = int(library_version())
    assert version_after_first == version_before + 1

    stale_code = machine.succeed(
        f"curl -s -D /tmp/stale-registration.headers -o /dev/null "
        f"-w '%{{http_code}}' -X POST "
        f"{base}/users/1/items/ATTACH22/file {auth} "
        f"-H 'If-Match: {world_md5}' -d 'upload={other_token}'"
    ).strip()
    assert stale_code == "412", stale_code
    machine.succeed(
        "grep -i '^last-modified-version:' /tmp/stale-registration.headers "
        f"| tr -d '\\r' | awk '{{print $2}}' | grep -qx '{version_after_first}'"
    )
    assert int(library_version()) == version_after_first
    assert (
        http_code(
            f"-X POST {base}/users/1/items/ATTACH22/file {auth} "
            f"-H 'If-Match: {world_md5}' -d 'upload={other_token}'"
        )
        == "400"
    )
    assert int(library_version()) == version_after_first
    assert_attachment("ATTACH22", first_md5, "first", "replacement-race-winner")
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=ATTACH22&format=json' {auth} "
        f"| jq -e '.[0].data.md5 == \"{first_md5}\" "
        f"and .[0].data.version == {version_after_first}'"
    )

    # Registration tokens are single-use. Upstream returns 400 after removing
    # a completed upload key.
    assert (
        http_code(
            f"-X POST {base}/users/1/items/ATTACH22/file {auth} "
            f"-H 'If-Match: {world_md5}' -d 'upload={first_token}'"
        )
        == "400"
    )
    assert int(library_version()) == version_after_first

with subtest("a file authorization without a precondition header is 428"):
    assert (
        http_code(
            f"-X POST {base}/users/1/items/ATTACH22/file {auth} "
            f"-d 'md5=deadbeef&filename=t.pdf&filesize=5&mtime=1'"
        )
        == "428"
    )

with subtest("uploading bytes that do not match the declared md5 is rejected"):
    # Verification happens at the upload step now (the bytes go straight to S3),
    # so a mismatch is refused there rather than at registration.
    version = library_version()
    psql(
        f"""insert into object (library_id, kind, key, version, data)
            values (1, 'item', 'BADHASH2', {version},
                    '{{"key":"BADHASH2","version":{version},
                       "itemType":"attachment","linkMode":"imported_file",
                       "filename":"b"}}')"""
    )
    bad = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/BADHASH2/file {auth} "
        f"-H 'If-None-Match: *' -d 'md5=00000000000000000000000000000000&filename=b&filesize=5&mtime=1' "
        f"| jq -r .uploadKey"
    ).strip()
    code = machine.succeed(
        f"printf hello | curl -s -o /dev/null -w '%{{http_code}}' "
        f"-X POST {base}/uploads/{bad} --data-binary @-"
    ).strip()
    assert code == "400", code
    psql("delete from object where library_id = 1 and key = 'BADHASH2'")

with subtest("registering without a prior upload is rejected"):
    # Authorize but never PUT the bytes, then try to register: the object was
    # never stored, so registration must refuse rather than commit metadata.
    version = library_version()
    psql(
        f"""insert into object (library_id, kind, key, version, data)
            values (1, 'item', 'NQUPLQAD', {version},
                    '{{"key":"NQUPLQAD","version":{version},
                       "itemType":"attachment","linkMode":"imported_file",
                       "filename":"n"}}')"""
    )
    tok = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/NQUPLQAD/file {auth} "
        f"-H 'If-None-Match: *' -d 'md5=5d41402abc4b2a76b9719d911017c592&filename=n&filesize=5&mtime=1' "
        f"| jq -r .uploadKey"
    ).strip()
    assert (
        http_code(
            f"-X POST {base}/users/1/items/NQUPLQAD/file {auth} "
            f"-H 'If-None-Match: *' -d 'upload={tok}'"
        )
        == "400"
    )
    psql("delete from object where library_id = 1 and key = 'NQUPLQAD'")

with subtest("non-alphanumeric keys are rejected from the file endpoint"):
    # The item key becomes an object key in the bucket and a path component in
    # URLs, so a key with '.'/'/' (path traversal) must be refused.
    assert (
        http_code(
            f"-X POST {base}/users/1/items/bad..key/file {auth} "
            f"-H 'If-None-Match: *' -d 'md5=x&filename=t&filesize=1&mtime=1'"
        )
        == "400"
    )

with subtest("annotations round-trip as ordinary items"):
    # Highlights/notes are items (itemType annotation/note), so they sync through
    # the same opaque object path rather than any dedicated endpoint.
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f"-d '[{{\"key\":\"ANNQT223\",\"itemType\":\"annotation\","
        f"\"annotationType\":\"highlight\",\"annotationText\":\"marked\","
        f"\"parentItem\":\"ATTACH22\"}}]' "
        f"| jq -e '.successful.\"0\".data.annotationText == \"marked\"'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=ANNQT223&format=json' {auth} "
        f"| jq -e '.[0].data.annotationType == \"highlight\"'"
    )
    # Like linkMode, annotationType must be emitted first: the client's fromJSON
    # rejects an annotation ("annotationType must be set before other annotation
    # properties") if it sees other annotation* fields first.
    first_key = machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=ANNQT223&format=json' {auth} "
        f"| jq -r '.[0].data | keys_unsorted[0]'"
    ).strip()
    assert first_key == "annotationType", first_key

with subtest("full-text content uploads, lists versions, and downloads"):
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/fulltext {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f"-d '[{{\"key\":\"ATTACH22\",\"content\":\"hello world\","
        f"\"indexedChars\":11,\"totalChars\":11,\"indexedPages\":1,\"totalPages\":1}}]' "
        f"| jq -e '.successful.\"0\".key == \"ATTACH22\"'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/fulltext?format=versions&since=0' {auth} | jq -e '.ATTACH22'"
    )
    # The per-item version must equal the value in the versions map, else the
    # client re-downloads content it already holds every sync.
    item_v = machine.succeed(
        f"curl -sf -D - -o /dev/null '{base}/users/1/items/ATTACH22/fulltext' {auth} "
        f"| grep -i last-modified-version | tr -d '\\r' | cut -d' ' -f2"
    ).strip()
    list_v = machine.succeed(
        f"curl -sf '{base}/users/1/fulltext?format=versions&since=0' {auth} | jq -r '.ATTACH22'"
    ).strip()
    assert item_v == list_v, f"{item_v} != {list_v}"
    machine.succeed(
        f"curl -sf '{base}/users/1/items/ATTACH22/fulltext' {auth} "
        f"| jq -e '.content == \"hello world\" and .totalPages == 1'"
    )

with subtest("a stale full-text write is rejected with 412"):
    assert (
        http_code(
            f"-X POST {base}/users/1/fulltext {auth} "
            f"-H 'If-Unmodified-Since-Version: 0' "
            f"-d '[{{\"key\":\"ATTACH22\",\"content\":\"x\"}}]'"
        )
        == "412"
    )

with subtest("the query API filters, searches, sorts and paginates items"):
    # Seed a couple of distinct items to query over.
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f'-d \'[{{"key":"QBQQK223","itemType":"book","title":"Borrow Checker",'
        f'"creators":[{{"lastName":"Klabnik","firstName":"Steve"}}],'
        f'"tags":[{{"tag":"rustlang"}},{{"tag":"systems"}}]}},'
        f'{{"key":"QART2223","itemType":"journalArticle","title":"Unrelated",'
        f'"tags":[{{"tag":"rustlang"}}]}}]\' | jq -e .successful'
    )

    def keys(qs):
        return machine.succeed(
            f"curl -sf '{base}/users/1/items?{qs}' {auth} | jq -r '[.[].key]|sort|join(\",\")'"
        ).strip()

    # Title and creator search (titleCreatorYear, the default qmode).
    assert keys("q=borrow") == "QBQQK223", keys("q=borrow")
    assert keys("q=klabnik") == "QBQQK223", keys("q=klabnik")
    # Type filter, including negation.
    assert "QBQQK223" in keys("itemType=book")
    assert "QART2223" not in keys("itemType=book")
    assert "QART2223" in keys("itemType=-book")
    # Tags: repeated key is AND, only the book carries both.
    assert keys("tag=rustlang&tag=systems") == "QBQQK223"
    assert keys("tag=rustlang") == "QART2223,QBQQK223"
    # Full-text only matches under qmode=everything (ATTACH22 holds "hello world").
    assert keys("q=world") == ""
    assert keys("q=world&qmode=everything") == "ATTACH22"

with subtest("the query API reports Total-Results and a next-page Link"):
    # Header names come back lower-cased over HTTP/1.1, so match case-insensitively.
    headers = machine.succeed(
        f"curl -sf -D - -o /dev/null '{base}/users/1/items?limit=1&sort=title&direction=asc' {auth}"
    ).lower()
    assert "total-results:" in headers, headers
    assert 'rel="next"' in headers, headers
    # The Link points at the public URL, not the internal bind address.
    assert "localhost:8189" in headers, headers

with subtest("a read-only key can drive the query API"):
    assert (
        http_code(f"'{base}/users/1/items?q=borrow' {readonly}") == "200"
    )

with subtest("convenience listings: top, trash, collection items and tags"):
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f'-d \'[{{"key":"TQPITEM3","itemType":"book","title":"Shelf Book",'
        f'"collections":["CQLLXXXX"],"tags":[{{"tag":"shelf"}}]}},'
        f'{{"key":"CHILDNQ3","itemType":"note","note":"child","parentItem":"TQPITEM3"}},'
        f'{{"key":"TRASHED3","itemType":"book","title":"Gone","deleted":1}}]\' '
        f"| jq -e .successful"
    )

    def path_keys(p):
        return machine.succeed(
            f"curl -sf '{base}{p}' {auth} | jq -r '[.[].key]|sort|join(\",\")'"
        ).strip()

    # Top excludes children (have parentItem) and trashed items.
    top = path_keys("/users/1/items/top")
    assert "TQPITEM3" in top, top
    assert "CHILDNQ3" not in top, top
    assert "TRASHED3" not in top, top
    # Trash returns only trashed items.
    trash = path_keys("/users/1/items/trash")
    assert trash == "TRASHED3", trash
    # Collection membership.
    assert path_keys("/users/1/collections/CQLLXXXX/items") == "TQPITEM3"
    # Tags lists distinct tags with counts; the trashed item's tag is excluded.
    machine.succeed(
        f"curl -sf {base}/users/1/tags {auth} "
        f"| jq -e '.[] | select(.tag == \"shelf\") | .numItems == 1'"
    )

with subtest("top filtering covers parentItem:false and the versions view"):
    # A top-level item may carry parentItem:false rather than omitting it; the
    # /top versions view (the client's parent-first phase) must be top-filtered.
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f'-d \'[{{"key":"TQPFALS3","itemType":"book","title":"pf",'
        f'"parentItem":false}}]\' | jq -e .successful'
    )
    # parentItem:false is treated as top-level.
    top = machine.succeed(
        f"curl -sf '{base}/users/1/items/top' {auth} | jq -r '[.[].key]|join(\"\\n\")'"
    )
    assert "TQPFALS3" in top, top
    # /items/top?format=versions returns only top-level keys; the child CHILDNQ3
    # (from the previous subtest) appears in the full versions map but not here.
    top_v = machine.succeed(
        f"curl -sf '{base}/users/1/items/top?format=versions&since=0' {auth} | jq -e 'has(\"CHILDNQ3\")|not'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?format=versions&since=0' {auth} | jq -e '.CHILDNQ3'"
    )

with subtest("malformed (non-array) item data does not 500 the query API"):
    # data is stored opaquely, so an item can carry a scalar where an array is
    # expected; jsonb_array_elements must not crash the listing/tag endpoints.
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f'-d \'[{{"key":"MALFQRM3","itemType":"book","title":"weird",'
        f'"creators":"notarray","tags":"x","collections":"y"}}]\' | jq -e .successful'
    )
    assert http_code(f"{base}/users/1/tags {auth}") == "200"
    # q=zzz forces the creators sub-select to run on the malformed row.
    assert http_code(f"'{base}/users/1/items?q=zzz' {auth}") == "200"
    assert http_code(f"'{base}/users/1/items?q=zzz&qmode=everything' {auth}") == "200"
    assert http_code(f"'{base}/users/1/items?tag=zzz' {auth}") == "200"
    assert http_code(f"{base}/users/1/collections/y/items {auth}") == "200"
    # A tags array whose elements aren't {tag:...} objects must not put a NULL
    # into tag_names and crash /tags (migration 0007 filters them).
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f'-d \'[{{"key":"BADTAGS3","itemType":"book","title":"bt",'
        f'"tags":[{{"tag":"good"}},123,"junk"]}}]\' | jq -e .successful'
    )
    machine.succeed(
        f"curl -sf {base}/users/1/tags {auth} "
        f"| jq -e '.[] | select(.tag == \"good\") | .numItems == 1'"
    )

with subtest("Total-Results stays correct past the last page"):
    def total_results(qs):
        return machine.succeed(
            f"curl -sf -D - -o /dev/null '{base}/users/1/items?{qs}' {auth} "
            f"| grep -i total-results | tr -d '\\r' | cut -d' ' -f2"
        ).strip()

    total = total_results("limit=1")
    assert int(total) > 0, total
    # A page past the end still reports the true total, not zero.
    assert total_results("limit=1&start=100000") == total, total

with subtest("query API: OR filters, descending sort and includeTrashed"):
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f'-d \'[{{"key":"CQVRA223","itemType":"book","title":"Aaa","tags":[{{"tag":"aa"}}]}},'
        f'{{"key":"CQVRB223","itemType":"journalArticle","title":"Bbb","tags":[{{"tag":"bb"}}]}},'
        f'{{"key":"CQVRT223","itemType":"book","title":"Ccc","deleted":1,'
        f'"tags":[{{"tag":"aa"}}]}}]\' | jq -e .successful'
    )

    def first(qs):
        return machine.succeed(
            f"curl -sf '{base}/users/1/items?{qs}' {auth} | jq -r '.[0].key'"
        ).strip()

    def kset(qs):
        return machine.succeed(
            f"curl -sf '{base}/users/1/items?{qs}' {auth} | jq -r '[.[].key]|sort|join(\",\")'"
        ).strip()

    # `||` is OR for both tag and itemType.
    both = kset("tag=aa||bb&itemType=book||journalArticle")
    assert "CQVRA223" in both and "CQVRB223" in both, both
    # Descending title sort: Bbb before Aaa, trashed Ccc excluded by default.
    assert first("tag=aa||bb&sort=title&direction=desc") == "CQVRB223"
    # includeTrashed surfaces the trashed item (Ccc sorts first descending).
    assert first("tag=aa&sort=title&direction=desc&includeTrashed=1") == "CQVRT223"
    assert "CQVRT223" not in kset("tag=aa")

with subtest("sort=date orders by extracted year, not raw freeform text"):
    version = library_version()
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {version}' "
        f'-d \'[{{"key":"DATE2QLD","itemType":"book","title":"old","date":"circa 1850",'
        f'"tags":[{{"tag":"era"}}]}},'
        f'{{"key":"DATE2MID","itemType":"book","title":"mid","date":"January 1960",'
        f'"tags":[{{"tag":"era"}}]}},'
        f'{{"key":"DATE2NEW","itemType":"book","title":"new","date":"2020-05-01",'
        f'"tags":[{{"tag":"era"}}]}}]\' | jq -e .successful'
    )
    # Ascending by year: 1850 < 1960 < 2020, despite the leading-character order
    # ("2020" < "January" < "circa") a naive text sort would give.
    order = machine.succeed(
        f"curl -sf '{base}/users/1/items?tag=era&sort=date&direction=asc' {auth} "
        f"| jq -r '[.[].key]|join(\",\")'"
    ).strip()
    assert order == "DATE2QLD,DATE2MID,DATE2NEW", order

with subtest("collection top items are served as a plain-text key list"):
    # The sync client fetches collections/<key>/items/top?format=keys when
    # restoring a deleted collection, parsing the body as newline-split keys.
    # TQPITEM3 (top, in CQLLXXXX) was created by the convenience-listings subtest.
    body = machine.succeed(
        f"curl -sf '{base}/users/1/collections/CQLLXXXX/items/top?format=keys' {auth}"
    ).strip()
    assert body == "TQPITEM3", repr(body)
    headers = machine.succeed(
        f"curl -sf -D - -o /dev/null '{base}/users/1/collections/CQLLXXXX/items/top?format=keys' {auth}"
    ).lower()
    # Plain text (not JSON) plus a version header for the client's 304 handling.
    assert "content-type: text/plain" in headers, headers
    assert "last-modified-version:" in headers, headers

with subtest("a versions read with nothing newer returns 200 + empty map, not 304"):
    v = library_version()
    # format=versions reads must NOT 304: the client's getVersions sends no
    # If-Modified-Since-Version header and treats a 304 as "no data", which then
    # mismatches its library-version check and loops the sync forever. Return 200
    # with an empty {} map plus the version header instead.
    for path in [
        f"items?format=versions&since={v}",
        f"items/top?format=versions&since={v}",
        f"collections?format=versions&since={v}",
        f"searches?format=versions&since={v}",
        f"fulltext?format=versions&since={v}",
    ]:
        assert http_code(f"'{base}/users/1/{path}' {auth}") == "200", path
        machine.succeed(f"curl -sf '{base}/users/1/{path}' {auth} | jq -e '. == {{}}'")
    # The version header is still present so the client keeps tracking the library version.
    machine.succeed(
        f"curl -sf -D /tmp/empty-versions.headers -o /dev/null "
        f"'{base}/users/1/items?format=versions&since={v}' {auth}"
    )
    machine.succeed(f"grep -iq 'last-modified-version: {v}' /tmp/empty-versions.headers")
    # settings still 304s — getSettings sends the If-Modified-Since-Version header
    # and handles a 304 itself.
    assert (
        http_code(f"{base}/users/1/settings -H 'If-Modified-Since-Version: {v}' {auth}") == "304"
    )

with subtest("collections round-trip through write, read, versions and delete"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/collections {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'[{{"key":"CQLL2223","name":"Papers"}}]\' '
        f"| jq -e '.successful.\"0\".key == \"CQLL2223\"'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/collections?collectionKey=CQLL2223&format=json' {auth} "
        f"| jq -e '.[0].data.name == \"Papers\"'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/collections?format=versions&since=0' {auth} | jq -e '.CQLL2223'"
    )
    machine.succeed(f"curl -sf -X DELETE '{base}/users/1/collections?collectionKey=CQLL2223' {auth} "
                    f"-H 'If-Unmodified-Since-Version: {library_version()}'")
    machine.succeed(
        f"curl -sf '{base}/users/1/deleted?since=0' {auth} | jq -e '.collections | index(\"CQLL2223\")'"
    )

with subtest("saved searches round-trip through write, read and delete"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/searches {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'[{{"key":"SRCH2223","name":"Recent","conditions":[]}}]\' '
        f"| jq -e '.successful.\"0\".key == \"SRCH2223\"'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/searches?searchKey=SRCH2223&format=json' {auth} "
        f"| jq -e '.[0].data.name == \"Recent\"'"
    )
    machine.succeed(f"curl -sf -X DELETE '{base}/users/1/searches?searchKey=SRCH2223' {auth} "
                    f"-H 'If-Unmodified-Since-Version: {library_version()}'")
    machine.succeed(
        f"curl -sf '{base}/users/1/deleted?since=0' {auth} | jq -e '.searches | index(\"SRCH2223\")'"
    )

with subtest("settings round-trip through write, read and delete"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/settings {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'{{"tagColors":{{"value":[{{"name":"x","color":"#fff"}}]}}}}\' '
    )
    machine.succeed(
        f"curl -sf {base}/users/1/settings {auth} "
        f"| jq -e '.tagColors.value[0].name == \"x\" and (.tagColors.version | type == \"number\")'"
    )
    # A stale settings write is a 412.
    assert (
        http_code(
            f"-X POST {base}/users/1/settings {auth} "
            f"-H 'If-Unmodified-Since-Version: 0' -d '{{\"k\":{{\"value\":1}}}}'"
        )
        == "412"
    )
    # DELETE actually removes the setting (regression: it used to be a no-op).
    machine.succeed(
        f"curl -sf -X DELETE '{base}/users/1/settings?settingKey=tagColors' {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}'"
    )
    machine.succeed(f"curl -sf {base}/users/1/settings {auth} | jq -e '.tagColors == null'")
    machine.succeed(
        f"curl -sf '{base}/users/1/deleted?since=0' {auth} | jq -e '.settings | index(\"tagColors\")'"
    )

with subtest("a gzip-compressed write body is decoded"):
    # The real client gzips write bodies; exercise the decompression middleware.
    machine.succeed(
        f"printf '%s' '[{{\"key\":\"GZIP2223\",\"itemType\":\"book\",\"title\":\"zipped\"}}]' "
        f"| gzip | curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f"-H 'Content-Encoding: gzip' --data-binary @- | jq -e .successful"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=GZIP2223&format=json' {auth} "
        f"| jq -e '.[0].data.title == \"zipped\"'"
    )

with subtest("PATCH updates items and is gated by the read-only key"):
    machine.succeed(
        f"curl -sf -X PATCH {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'[{{"key":"GZIP2223","itemType":"book","title":"patched"}}]\' '
        f"| jq -e '.successful.\"0\".data.title == \"patched\"'"
    )
    assert (
        http_code(
            f"-X PATCH {base}/users/1/items {readonly} "
            f"-H 'If-Unmodified-Since-Version: 0' -d '[{{\"key\":\"X\",\"itemType\":\"book\"}}]'"
        )
        == "403"
    )

with subtest("PATCH merges: a partial update keeps unspecified fields"):
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'[{{"key":"MERGEIT2","itemType":"book","title":"orig","tags":[{{"tag":"keep"}}]}}]\' '
        f"| jq -e .successful"
    )
    # PATCH only the title; itemType and tags must survive.
    machine.succeed(
        f"curl -sf -X PATCH {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'[{{"key":"MERGEIT2","title":"new"}}]\''
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=MERGEIT2&format=json' {auth} "
        f"| jq -e '.[0].data.title==\"new\" and .[0].data.itemType==\"book\" "
        f"and .[0].data.tags[0].tag==\"keep\"'"
    )

with subtest("POST also merges: a partial upload keeps unspecified fields"):
    # The sync client uploads only an existing object's changed fields via POST
    # (e.g. just lastRead after opening an attachment). A full replace would drop
    # itemType/linkMode and corrupt the attachment, so POST must merge too.
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'[{{"key":"PMERGEAT","itemType":"attachment","linkMode":"imported_file",'
        f'"filename":"f.pdf","contentType":"application/pdf"}}]\' | jq -e .successful'
    )
    # POST a partial object: only key + a changed field (mimics lastRead sync).
    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f'-d \'[{{"key":"PMERGEAT","lastRead":1700000000,"tags":[]}}]\''
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/items?itemKey=PMERGEAT&format=json' {auth} "
        f"| jq -e '.[0].data.itemType==\"attachment\" and .[0].data.linkMode==\"imported_file\" "
        f"and .[0].data.filename==\"f.pdf\" and .[0].data.lastRead==1700000000'"
    )

with subtest("deletes are recorded in the deletion log"):
    machine.succeed(
        f"curl -sf -X DELETE '{base}/users/1/items?itemKey=ITEM2223' {auth} "
        f"-H 'If-Unmodified-Since-Version: {library_version()}'"
    )
    machine.succeed(
        f"curl -sf '{base}/users/1/deleted?since=0' {auth} | jq -e '.items | index(\"ITEM2223\")'"
    )

with subtest("request journal keeps routing evidence without secrets or content"):
    form_marker = "XOTERO_JOURNAL_FORM_SECRET_9A6C1D"
    upload_marker = "XOTERO_JOURNAL_UPLOAD_SECRET_7F3C9A"
    json_marker = "XOTERO_JOURNAL_JSON_SECRET_4D8E2B"

    machine.succeed(f"curl -sf -X POST {base}/keys/sessions -d '{{}}' > /tmp/journal-session")
    session_token = machine.succeed("jq -r .sessionToken /tmp/journal-session").strip()
    login_url = machine.succeed("jq -r .loginURL /tmp/journal-session").strip()
    machine.succeed(f"curl -sf -o /dev/null '{login_url}'")
    machine.succeed(
        f"curl -sf -o /dev/null -X POST {base}/login {oidc} "
        f"--data-urlencode 'session={session_token}' "
        f"--data-urlencode 'marker={form_marker}'"
    )
    machine.succeed(
        f"curl -sf {base}/keys/sessions/{session_token} | jq -e '.status == \"completed\"'"
    )

    version = library_version()
    psql(
        f"""insert into object (library_id, kind, key, version, data)
            values (1, 'item', 'LOGSEC22', {version},
                    '{{"key":"LOGSEC22","version":{version},
                       "itemType":"attachment","linkMode":"imported_file",
                       "filename":"journal.bin"}}')"""
    )
    upload_token = machine.succeed(
        f"curl -sf -X POST {base}/users/1/items/LOGSEC22/file {auth} "
        f"-H 'If-None-Match: *' "
        f"-d 'md5=3978e97fe9bc4ee5211880f2f0c103db"
        f"&filename=journal.bin&filesize=35&mtime=1700000000010' "
        f"| jq -r .uploadKey"
    ).strip()
    machine.succeed(
        f"printf '%s' '{upload_marker}' | "
        f"curl -sf -X POST {base}/uploads/{upload_token} --data-binary @-"
    )

    machine.succeed(
        f"curl -sf -X POST {base}/users/1/items {auth} "
        f"-H 'Content-Type: application/json' "
        f"-H 'If-Unmodified-Since-Version: {library_version()}' "
        f"--data '[{{\"key\":\"LGSEC223\",\"itemType\":\"book\","
        f"\"title\":\"{json_marker}\"}}]' | jq -e .successful"
    )

    machine.succeed("journalctl --sync")
    journal = machine.succeed("journalctl -u xotero.service --no-pager")
    leaked = [
        label
        for label, secret in (
            ("session token", session_token),
            ("upload token", upload_token),
            ("login form", form_marker),
            ("attachment body", upload_marker),
            ("JSON body", json_marker),
            ("API key", "testtoken"),
            ("login API key", login_key),
        )
        if secret in journal
    ]
    assert not leaked, leaked
    leaked_fields = [field for field in ("want_md5", "got_md5") if field in journal]
    assert not leaked_fields, leaked_fields
    journal_lines = journal.splitlines()
    assert any(
        "request" in line
        and "method=POST" in line
        and "path=/users/1/items/LOGSEC22/file" in line
        for line in journal_lines
    )
    assert any(
        "request" in line
        and "method=GET" in line
        and "path=/keys/sessions/{token}" in line
        for line in journal_lines
    )
    assert any(
        "request" in line
        and "method=POST" in line
        and "path=/uploads/{token}" in line
        for line in journal_lines
    )

with subtest("storage SDK round-trips small and multipart encoded keys"):
    machine.succeed("printf 'sdk-small' >/tmp/sdk-small")
    machine.succeed("dd if=/dev/zero of=/tmp/sdk-large bs=1M count=9 status=none")
    for item, payload, blob in (
        ("SDKSMALL", "/tmp/sdk-small", "libraries/1/uploads/sdk space+%?#/small"),
        ("SDKLARGE", "/tmp/sdk-large", "libraries/1/uploads/sdk space+%?#/large"),
    ):
        machine.succeed(
            f"curl -sf -X POST {base}/users/1/items {auth} "
            f"-H 'If-Unmodified-Since-Version: {library_version()}' "
            f'-d \'[{{"key":"{item}","itemType":"attachment",'
            '"linkMode":"imported_file","filename":"sdk.bin"}]\' | jq -e .successful'
        )
        digest = machine.succeed(f"md5sum {payload} | cut -d' ' -f1").strip()
        size = machine.succeed(f"stat -c %s {payload}").strip()
        token = machine.succeed(
            f"curl -sf -X POST {base}/users/1/items/{item}/file {auth} "
            "-H 'If-None-Match: *' "
            f"-d 'md5={digest}&filename=sdk.bin&filesize={size}&mtime=1' "
            "| jq -r .uploadKey"
        ).strip()
        psql(f"update pending_uploads set blob_key = '{blob}' where item_key = '{item}'")
        upload_response = machine.succeed(
            f"curl -sS --max-time 60 -i -X POST {base}/uploads/{token} "
            f"--data-binary @{payload} -w '\\n%{{http_code}}'"
        )
        assert upload_response.rsplit("\n", 1)[-1] == "201", upload_response
        assert psql(f"select state from pending_uploads where item_key = '{item}'") == "uploaded"
        registration = machine.succeed(
            f"curl -sS --max-time 60 -i -X POST {base}/users/1/items/{item}/file {auth} "
            f"-H 'If-None-Match: *' -d 'upload={token}'"
        )
        assert registration.startswith("HTTP/1.1 204"), registration
        location = machine.succeed(
            f"curl -sf -D /tmp/sdk.headers -o /dev/null "
            f"{base}/users/1/items/{item}/file {auth} "
            "&& grep -i '^location:' /tmp/sdk.headers | tr -d '\\r' | awk '{print $2}'"
        ).strip()
        machine.succeed(f"curl -sf --max-time 60 '{location}' -o /tmp/sdk-download")
        machine.succeed(f"cmp {payload} /tmp/sdk-download")
        print(f"SDK roundtrip {item} size={size} md5={digest} blob={blob}")
        print(upload_response, registration)
        # Exercise Storage.delete, not mc's independent delete implementation.
        # A new abandoned candidate uses an encoded key and the same payload size.
        cleanup_token = machine.succeed(
            f"curl -sf -X POST {base}/users/1/items/{item}/file {auth} "
            f"-H 'If-Match: {digest}' "
            f"-d 'md5=00000000000000000000000000000000"
            f"&filename=cleanup.bin&filesize={size}&mtime=2' | jq -r .uploadKey"
        ).strip()
        cleanup_blob = blob + "-cleanup"
        psql(
            f"update pending_uploads set blob_key = '{cleanup_blob}', upload_md5 = '{digest}' "
            f"where item_key = '{item}'"
        )
        machine.succeed(
            f"curl -sf --max-time 60 -X POST {base}/uploads/{cleanup_token} "
            f"--data-binary @{payload}"
        )
        machine.succeed(f"mc stat 's3/zotero/{cleanup_blob}'")
        psql(
            "update pending_uploads set created_at = now() - interval '2 hours', "
            "expires_at = now() - interval '1 hour' "
            f"where item_key = '{item}'"
        )
        restart_xotero()
        assert psql(f"select count(*) from pending_uploads where item_key = '{item}'") == "0"
        machine.fail(f"mc stat 's3/zotero/{cleanup_blob}'")

with subtest("provider failures never publish or mark uploads complete"):
    # Run actual Storage through the live upload/registration handlers. This
    # provider controls only wire replies that RustFS cannot deliberately emit.
    provider = r"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote

class Provider(BaseHTTPRequestHandler):
    def reply(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        mode = Path("/tmp/sdk-provider-mode").read_text()
        status = int(mode) if mode.isdigit() else 200
        body = b""
        if status == 200 and self.command == "POST":
            if self.path.endswith("?uploads"):
                key = unquote(self.path.split("?")[0].removeprefix("/zotero/"))
                body = (
                    "<InitiateMultipartUploadResult><Bucket>zotero</Bucket>"
                    f"<Key>{key}</Key><UploadId>sdk-upload</UploadId>"
                    "</InitiateMultipartUploadResult>"
                ).encode()
            else:
                body = b"<Error><Code>InternalError</Code>"
        if self.command == "DELETE":
            status = 204
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"sdk-part"')
        self.end_headers()
        self.wfile.write(body)
        print(self.command, self.path, status, repr(body), flush=True)
    do_POST = reply
    do_PUT = reply
    do_DELETE = reply

HTTPServer(("127.0.0.1", 9000), Provider).serve_forever()
"""
    machine.succeed("systemctl stop rustfs.service")
    try:
        machine.succeed("printf 403 >/tmp/sdk-provider-mode")
        machine.succeed(
            "systemd-run --unit=xotero-sdk-provider "
            "--property=RuntimeMaxSec=180 python3 -u -c " + shlex.quote(provider)
        )
        machine.wait_for_open_port(9000)
        digest = machine.succeed("md5sum /tmp/sdk-large | cut -d' ' -f1").strip()
        for mode in ("403", "503", "malformed"):
            machine.succeed(f"printf %s {mode} >/tmp/sdk-provider-mode")
            token = machine.succeed(
                f"curl -sf -X POST {base}/users/1/items/SDKLARGE/file {auth} "
                f"-H 'If-Match: {digest}' "
                f"-d 'md5={digest}&filename=failed.bin&filesize=9437184&mtime=3' "
                "| jq -r .uploadKey"
            ).strip()
            before = library_version()
            response = machine.succeed(
                f"curl -sS --max-time 60 -i -X POST {base}/uploads/{token} "
                "--data-binary @/tmp/sdk-large -w '\\n%{http_code}'"
            )
            assert response.rsplit("\n", 1)[-1] == "500", (mode, response)
            states = psql("select string_agg(distinct state, ',') from pending_uploads where item_key = 'SDKLARGE'")
            assert states == "authorized", (mode, states)
            registration = machine.succeed(
                f"curl -sS --max-time 60 -i -X POST {base}/users/1/items/SDKLARGE/file {auth} "
                f"-H 'If-Match: {digest}' -d 'upload={token}'"
            )
            assert registration.startswith("HTTP/1.1 400"), (mode, registration)
            assert library_version() == before
            print(f"SDK provider mode={mode} state={states} version={before}")
            print(response, registration)
        wire = machine.succeed("journalctl -u xotero-sdk-provider --no-pager")
        assert "POST /zotero/" in wire and "InternalError" in wire, wire
        print(wire)
    finally:
        machine.succeed("systemctl stop xotero-sdk-provider.service")
        machine.succeed("systemctl start rustfs.service")
        machine.wait_for_open_port(9000)
