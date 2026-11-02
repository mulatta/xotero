"""DB-backed API-key contract and populated-v7 migration coverage."""

import hashlib
import json
import shlex


base = "http://localhost:8189"
recovery = "recoverytoken"
alice = "AliceKey23456789AbCdEfGh"
bob = "BobKeyAB23456789CdEfGhJk"
bob_ro = "BobROAB23456789CdEfGhJKL"
bob_full = "BobFllAB23456789CdEfGhJK"
bob_notes_write = "BobNwrtAB23456789CdEfGh"
bob_group_rw = "BobGrpRW23456789AbCdEfGh"
revoked = "RevokedK23456789AbCdEfGh"
api_headers = "-H 'Zotero-API-Version: 3' -H 'Zotero-Schema-Version: 42'"
oidc_issuer = "https://id.example.test"
oidc_subject = "alice-subject"
oidc_bob_subject = "bob-subject"
oidc = (
    f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}' "
    f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}'"
)
oidc_bob = (
    f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}' "
    f"-H 'X-Xotero-OIDC-Subject: {oidc_bob_subject}'"
)


def psql(sql):
    escaped = sql.replace("'", "'\"'\"'")
    return machine.succeed(
        f"sudo -u xotero psql -v ON_ERROR_STOP=1 -At -d xotero -c '{escaped}'"
    ).strip()


def http_code(path, token=None, method="GET", body=None, version=None):
    auth = f"-H 'Zotero-API-Key: {token}'" if token else ""
    data = ""
    if body is not None:
        data = f"-H 'Content-Type: application/json' --data '{body}'"
    if version is not None:
        data += f" -H 'If-Unmodified-Since-Version: {version}'"
    return machine.succeed(
        f"curl -s -o /dev/null -w '%{{http_code}}' -X {method} "
        f"{api_headers} {auth} {data} {base}{path}"
    ).strip()


def attachment_route_receipt(path, token, method="GET", path_as_is=False):
    path_option = "--path-as-is " if path_as_is else ""
    raw = machine.succeed(
        f"curl -sS --max-time 10 {path_option}-D - -o /dev/null -X {method} "
        f"-H 'Content-Length: 0' {api_headers} "
        f"-H 'Host: localhost:8189' -H 'User-Agent: xotero-task5-route-probe' "
        f"-H 'Accept: */*' -H 'Zotero-API-Key: {token}' {base}{path}"
    ).replace("\r\n", "\n")
    lines = raw.splitlines()
    status = int(lines[0].split()[1])
    headers = []
    for line in lines[1:]:
        if line.lower().startswith("location:"):
            headers.append("Location: <redacted>")
        elif line:
            headers.append(line)
    receipt = {
        "request": {
            "method": method,
            "path": path,
            "url": base + path,
            "curl_options": ["--path-as-is"] if path_as_is else [],
            "headers": [
                "Content-Length: 0",
                "Host: localhost:8189",
                "User-Agent: xotero-task5-route-probe",
                "Accept: */*",
                "Zotero-API-Version: 3",
                "Zotero-Schema-Version: 42",
                "Zotero-API-Key: <redacted>",
            ],
        },
        "response": {
            "status": status,
            "headers": headers,
            "redirect_followed": False,
            "body_captured": False,
        },
    }
    print("ATTACHMENT-ROUTE " + json.dumps(receipt, sort_keys=True))
    return status, headers


def incomplete_body_status(path, token=None, method="POST", chunked=False):
    """Keep write side open: final denial must not require body bytes or EOF."""
    script = f"""
import json
import socket
headers = [
    {method!r} + " " + {path!r} + " HTTP/1.1",
    "Host: localhost:8189",
    "Connection: close",
    "Content-Encoding: gzip",
    "Transfer-Encoding: chunked" if {chunked!r} else "Content-Length: 1048576",
]
if {token!r} is not None:
    headers.append("Zotero-API-Key: " + {token!r})
with socket.create_connection(("127.0.0.1", 8189), timeout=3) as connection:
    connection.settimeout(3)
    connection.sendall(("\\r\\n".join(headers) + "\\r\\n\\r\\n").encode("ascii"))
    response = b""
    while b"\\r\\n\\r\\n" not in response:
        data = connection.recv(4096)
        assert data, response
        response += data
    status = int(response.split(b" ", 2)[1])
    assert status >= 200, response
    print(json.dumps({{"status": status, "sent_body_bytes": 0, "sent_eof": False,
                      "framing": "chunked" if {chunked!r} else "content-length"}}))
"""
    result = machine.succeed(f"python3 -c {shlex.quote(script)}")
    print(f"incomplete-body {method} {path.split('/uploads/')[0]}: {result.strip()}")
    return str(json.loads(result)["status"])


def body_admission_snapshot():
    return psql(
        """select json_build_array(
               (select json_agg(l order by id) from library l),
               (select json_agg(f order by library_id, item_key) from file f),
               (select count(*) from object),
               (select json_agg(p order by token_hash) from pending_uploads p)
           )"""
    )


def gzip_body_status(path, size, token=None, corruption="", version=None):
    script = f"""
import http.client
import json
import zlib
prefix = b"padding=" if {path!r} == "/login" else b'[{{"key":"BNDRY222","itemType":"book"}}]'
padding = b"x" if {path!r} == "/login" else b" "
compressor = zlib.compressobj(wbits=31)
chunks = [compressor.compress(prefix)]
remaining = {size} - len(prefix)
while remaining:
    count = min(remaining, 65536)
    chunks.append(compressor.compress(padding * count))
    remaining -= count
chunks.append(compressor.flush())
payload = b"".join(chunks)
if {corruption!r} == "truncated":
    payload = payload[:-4]
if {corruption!r} == "crc":
    payload = payload[:-8] + bytes([payload[-8] ^ 1]) + payload[-7:]
headers = {{"Content-Encoding": "gzip", "Content-Type": "application/x-www-form-urlencoded"
           if {path!r} == "/login" else "application/json"}}
if {token!r} is not None:
    headers["Zotero-API-Key"] = {token!r}
if {version!r} is not None:
    headers["If-Unmodified-Since-Version"] = str({version!r})
connection = http.client.HTTPConnection("127.0.0.1", 8189, timeout=30)
try:
    connection.request("POST", {path!r}, payload, headers)
    response = connection.getresponse()
    response.read()
    print(json.dumps({{"status": response.status, "decoded_bytes": {size},
                      "encoded_bytes": len(payload), "corruption": {corruption!r}}}))
finally:
    connection.close()
"""
    result = machine.succeed(f"python3 -c {shlex.quote(script)}")
    print(f"gzip-body {path}: {result.strip()}")
    return str(json.loads(result)["status"])


def restart_xotero():
    machine.succeed("systemctl reset-failed xotero.service")
    machine.succeed("systemctl restart xotero.service")
    machine.wait_for_unit("xotero.service")
    machine.wait_for_open_port(8189)


def get_json(path, token):
    return json.loads(
        machine.succeed(
            f"curl -sf {api_headers} -H 'Zotero-API-Key: {token}' '{base}{path}'"
        )
    )


def response_header(raw_headers, name):
    prefix = f"{name.lower()}:"
    values = [
        line.split(":", 1)[1].strip()
        for line in raw_headers.splitlines()
        if line.lower().startswith(prefix)
    ]
    assert len(values) == 1, (name, values, raw_headers)
    return values[0]


def assert_group_entry(entry, is_admin):
    assert set(entry) == {"id", "version", "links", "meta", "data"}
    assert entry["id"] == 303 and entry["version"] == 4
    assert entry["links"]["self"] == {
        "href": f"{base}/groups/303",
        "type": "application/json",
    }
    assert entry["links"]["alternate"]["href"].endswith("/groups/303")
    assert entry["links"]["alternate"]["type"] == "text/html"
    assert entry["meta"] == {
        "created": "2024-01-02T03:04:05Z",
        "lastModified": "2024-02-03T04:05:06Z",
        "numItems": 2,
        "isAdmin": is_admin,
    }
    assert entry["data"] == {
        "id": 303,
        "version": 4,
        "name": "Alice Research Group",
        "owner": 101,
        "type": "Private",
        "description": "Private collaboration fixture",
        "url": "https://groups.example.test/alice-research",
        "libraryEditing": "admins",
        "libraryReading": "members",
        "fileEditing": "admins",
        "members": [202],
    }


def sha256_hex(value):
    return hashlib.sha256(value.encode()).hexdigest()


def create_login_session():
    return json.loads(
        machine.succeed(f"curl -sf -X POST {base}/keys/sessions -d '{{}}'")
    )["sessionToken"]


def approve_login_session(token, identity_headers=None):
    headers = oidc if identity_headers is None else identity_headers
    return machine.succeed(
        f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
        f"{base}/login {headers} -d 'session={token}'"
    ).strip()


def poll_login_session(token):
    return json.loads(machine.succeed(f"curl -sf {base}/keys/sessions/{token}"))


with subtest("keyless OIDC starts without an implicit recovery credential"):
    keyless.wait_for_unit("xotero.service")
    keyless.wait_for_open_port(8189)
    keyless.succeed(
        "! systemctl show xotero.service -p Environment | "
        "grep -q XOTERO_KEYS="
    )
    keyless_script = """
import http.client
import json
import pathlib
import urllib.parse

def request(method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("localhost", 8189, timeout=10)
    try:
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        data = response.read()
        return response.status, data
    finally:
        connection.close()

for token in ("", "xotero-dev-key", "recoverytoken", "unknown-token"):
    status, _ = request("GET", "/keys/current", headers={"Zotero-API-Key": token})
    assert status == 403
status, data = request("POST", "/keys/sessions")
assert status == 201
session = json.loads(data)["sessionToken"]
status, _ = request("POST", "/login", urllib.parse.urlencode({"session": session}), {
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Xotero-OIDC-Issuer": "https://id.example.test",
    "X-Xotero-OIDC-Subject": "alice-subject",
})
assert status == 200
status, data = request("GET", "/keys/sessions/" + session)
result = json.loads(data)
assert status == 200 and result["status"] == "completed" and result["userID"] == 1
key = result["apiKey"]
status, data = request("GET", "/keys/current", headers={"Zotero-API-Key": key})
assert status == 200 and json.loads(data)["userID"] == 1
pathlib.Path("/run/keyless-replay.json").write_text(json.dumps([session, key]))
print("keyless login, poll, DB-key authentication and dev-key denial passed")
"""
    keyless.succeed(f"python3 -c {shlex.quote(keyless_script)}")
    keyless.succeed("systemctl restart xotero.service")
    keyless.wait_for_unit("xotero.service")
    keyless.wait_for_open_port(8189)
    replay_script = """
import http.client
import json
import pathlib
session, expected = json.loads(pathlib.Path("/run/keyless-replay.json").read_text())
connection = http.client.HTTPConnection("localhost", 8189, timeout=10)
try:
    connection.request("GET", "/keys/sessions/" + session)
    response = connection.getresponse()
    assert response.status == 200
    assert json.loads(response.read())["apiKey"] == expected
finally:
    connection.close()
pathlib.Path("/run/keyless-replay.json").unlink()
print("keyless stable-KDF replay passed")
"""
    keyless.succeed(f"python3 -c {shlex.quote(replay_script)}")


machine.wait_for_unit("postgresql.service")
machine.wait_for_unit("rustfs.service")
machine.succeed("aws s3 mb s3://zotero")

with subtest("checkpoint11 populated v13 shared bare upgrade"):
    # Independent supported history, real storage and real HTTP downloads.
    upgrade_script = r'''
import hashlib
import http.server
import io
import json
import os
import selectors
import subprocess
import threading
import time
import zipfile

database = "checkpoint11_upgrade"
print("CHECKPOINT11_FIXTURE_PID=" + str(os.getpid()), flush=True)
subprocess.run(["sudo", "-u", "postgres", "createdb", "-O", "xotero", database], check=True)
url = "postgresql://xotero@localhost/" + database + "?host=/run/postgresql"
def sql(statement):
    return subprocess.check_output(
        ["sudo", "-u", "xotero", "psql", "-v", "ON_ERROR_STOP=1", "-At",
         "-d", database, "-c", statement], text=True).strip()
subprocess.run(["sudo", "-u", "xotero", "env", "DATABASE_URL=" + url,
                "sqlx", "migrate", "run", "--source", "/etc/xotero-test/v13-migrations"], check=True)
payload = b"checkpoint11 shared bare bytes"
digest = hashlib.md5(payload).hexdigest()
sql("insert into library (id, version, kind) values (22, 17, 'personal'), (23, 19, 'personal')")
sql("insert into users (id, username, display_name) values (202, 'historical22', 'Historical22'), (203, 'historical23', 'Historical23')")
sql("insert into personal_libraries (user_id, library_id) values (202, 22), (203, 23)")
sql("insert into users (id,username,display_name) values (101,'alice','Alice'); insert into personal_libraries (user_id,library_id) values (101,1)")
for library, user in [(22, 202), (23, 203)]:
    token = "checkpoint11key" + str(user)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    sql(f"""with inserted as (
            insert into api_keys (token_hash, user_id, name)
            values (decode('{token_hash}', 'hex'), {user}, 'historical') returning id)
            insert into api_key_user_permissions (api_key_id, library, notes, write, files)
            select id, true, true, true, true from inserted""")
    sql(f"""insert into object (library_id, kind, key, version, data)
            values ({library}, 'item', 'SHAREB22', 11,
                    '{{"key":"SHAREB22","version":11,"itemType":"attachment","linkMode":"imported_file","filename":"shared.bin","title":"preserved"}}');
            insert into file (library_id,item_key,md5,blob_md5,blob_key,filename,filesize,mtime,version)
            values ({library},'SHAREB22','{digest}','{digest}','libraries/{library}/SHAREB22','shared.bin',{len(payload)},1700000000011,11)""")
subprocess.run(["aws", "s3", "cp", "-", "s3://zotero/SHAREB22"], input=payload, check=True)
for key, pointer in [
    ("PREFXK22", "libraries/22/PREFXK22"),
    ("WRNGFX22", "libraries/22/WRNGFX22"),
    ("CANDBL22", "libraries/22/uploads/checkpoint11"),
    ("BAREKY22", "BAREKY22"),
    ("CUSTMK22", "checkpoint11/custom"),
    ("uploads/checkpoint11", "libraries/22/uploads/checkpoint11-collision"),
]:
    if key.startswith("uploads/"):
        pointer = "libraries/22/" + key
    sql(f"""insert into object (library_id,kind,key,version,data)
            values (22,'item','{key}',11,
                    '{{"key":"{key}","version":11,"itemType":"attachment","linkMode":"imported_file","filename":"preserved.bin"}}');
            insert into file (library_id,item_key,md5,blob_md5,blob_key,filename,filesize,mtime,version)
            values (22,'{key}','{digest}','{digest}','{pointer}','preserved.bin',{len(payload)},1700000000011,11)""")
for key in ["PREFXK22", "WRNGFX22"]:
    subprocess.run(["aws", "s3", "cp", "-", "s3://zotero/" + key], input=payload, check=True)
    subprocess.run(["aws", "s3", "cp", "-", "s3://zotero/libraries/22/" + key],
                   input=payload if key == "PREFXK22" else b"x" * len(payload), check=True)
# More than one descriptor page exercises whole-pass lock acquisition, rather
# than accidentally proving only a single-page ordering.
page_keys = ["PAGE" + "".join("23456789"[(index // (8 ** power)) % 8]
                            for power in [3,2,1,0]) for index in range(33)]
for key in page_keys:
    sql(f"""insert into object (library_id,kind,key,version,data)
            values (22,'item','{key}',11,
                    '{{"key":"{key}","version":11,"itemType":"attachment","linkMode":"imported_file","filename":"page.bin"}}');
            insert into file (library_id,item_key,md5,blob_md5,blob_key,filename,filesize,mtime,version)
            values (22,'{key}','{digest}','{digest}','libraries/22/{key}','page.bin',{len(payload)},1700000000011,11)""")
    subprocess.run(["aws", "s3", "cp", "-", "s3://zotero/libraries/22/"+key],input=payload,check=True)
archive = io.BytesIO()
with zipfile.ZipFile(archive,"w",compression=zipfile.ZIP_DEFLATED) as zipped:
    member = zipfile.ZipInfo("shared.bin",date_time=(2026,1,1,0,0,0))
    member.compress_type = zipfile.ZIP_DEFLATED
    zipped.writestr(member,payload)
compressed_bytes = archive.getvalue()
compressed_hash = hashlib.md5(compressed_bytes).hexdigest().upper()
sql(f"""insert into object (library_id,kind,key,version,data)
        values (22,'item','CMPRSS22',11,
                '{{"key":"CMPRSS22","version":11,"itemType":"attachment","linkMode":"imported_file","filename":"shared.bin"}}');
        insert into file (library_id,item_key,md5,blob_md5,blob_key,filename,filesize,mtime,version,compressed)
        values (22,'CMPRSS22','{digest}','{compressed_hash}','libraries/22/CMPRSS22','shared.bin',{len(compressed_bytes)},1700000000011,11,true)""")
subprocess.run(["aws", "s3", "cp", "-", "s3://zotero/CMPRSS22"],input=compressed_bytes,check=True)
# Untouched compressed candidate has distinct logical and byte integrity domains.
sql("update file set md5 = repeat('a',32), compressed = true where item_key = 'CANDBL22'")
sql("""insert into setting (library_id,key,version,value) values (22,'historical',13,'{"preserved":true}');
       insert into deletion (library_id,kind,key,version) values (22,'item','DELETED2',12);
       insert into fulltext (library_id,item_key,content,indexed_chars,total_chars,indexed_pages,total_pages,version)
       values (22,'SHAREB22','preserved text',14,14,1,1,11);
       insert into login_sessions (token_hash,client_type,expires_at)
       values (decode(repeat('ab',32),'hex'),'linux','2100-01-01');
       insert into library (id,version,kind) values (33,23,'group');
       begin;
       insert into groups (id,library_id,owner_user_id,name,version)
       values (303,33,202,'Historical Group',7);
       insert into group_memberships (group_id,user_id,role) values (303,202,'owner');
       commit;
       insert into api_key_group_permissions (api_key_id,user_id,group_id,library,write)
       select id,202,303,true,true from api_keys where user_id = 202;
       insert into pending_uploads
       (token_hash,library_id,authorizer_key_hash,item_key,blob_key,md5,upload_md5,filename,filesize,mtime,state,expires_at)
       select decode(repeat('cd',32),'hex'),22,token_hash,'CANDBL22','libraries/22/uploads/checkpoint11-pending',
              repeat('a',32),repeat('b',32),'pending.zip',23,1700000000011,'authorized','2100-01-01'
       from api_keys where user_id = 202""")
tables = ["library", "object", "setting", "deletion", "fulltext", "users",
          "personal_libraries", "api_keys", "api_key_user_permissions", "groups",
          "group_memberships", "api_key_group_permissions", "login_sessions", "pending_uploads"]
def durable_snapshot():
    families = {}
    for table in tables:
        # Compare every historical column; the forward policy ceiling is
        # asserted separately rather than treated as lost historical data.
        row = "to_jsonb(t)-'policy_limited'" if table == "api_key_group_permissions" else "to_jsonb(t)"
        families[table] = sql(f"select coalesce(jsonb_agg({row} order by ({row})::text), '[]') from {table} t")
    families["file_metadata"] = sql("""select jsonb_agg(to_jsonb(f) - 'blob_key' order by library_id,item_key) from file f""")
    families["old_checksums"] = sql("select jsonb_agg(row(version,checksum) order by version) from _sqlx_migrations where version <= 13")
    return families
snapshot = durable_snapshot()
subprocess.run(["sudo", "-u", "postgres", "createdb", "-O", "xotero",
                "-T", database, "checkpoint11_template"], check=True)
subprocess.run(["sudo", "-u", "xotero", "env", "DATABASE_URL=" + url,
                "sqlx", "migrate", "run", "--source", "/etc/xotero-test/current-migrations"], check=True)
assert sql("select bool_and(not policy_limited) from api_key_group_permissions") == "t"
# An unrelated bare tombstone cannot invalidate a proven current prefix.
sql("""insert into blob_retirements (blob_key,not_before,state,deleted_at)
       values ('PREFXK22',clock_timestamp(),'deleted',clock_timestamp())""")
assert sql("select count(*) from legacy_blob_reconciliation") == "38"
assert sql("select count(*) from legacy_blob_reconciliation where item_key in ('CANDBL22','BAREKY22','CUSTMK22','uploads/checkpoint11')") == "0"
environment = os.environ | {
    "XOTERO_DATABASE_URL": url, "XOTERO_BIND": "127.0.0.1:8191",
    "XOTERO_USER_ID": "101", "XOTERO_USERNAME": "alice", "XOTERO_DISPLAY_NAME": "Alice",
    "XOTERO_PUBLIC_URL": "http://localhost:8191",
    "XOTERO_LOGIN_KDF_KEY_FILE": "/etc/xotero-test/checkpoint11-kdf",
    "XOTERO_S3_ENDPOINT": "http://localhost:9000",
    "XOTERO_S3_REGION": "us-east-1", "XOTERO_S3_BUCKET": "zotero",
    "XOTERO_S3_ACCESS_KEY": "rustfsadmin", "XOTERO_S3_SECRET_KEY": "rustfsadmin",
    "XOTERO_UPLOAD_TIMEOUT": "10",
}
process = subprocess.Popen(["sudo", "-u", "xotero", "env",
                           *[key + "=" + value for key, value in environment.items()
                             if key.startswith("XOTERO_")], "xotero"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=False)
print("CHECKPOINT11_SERVER_PID=" + str(process.pid), flush=True)
try:
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + 30
    output = b""
    while b"xotero listening" not in output:
        ready = selector.select(max(0, deadline - time.monotonic()))
        assert ready, ("startup deadline", output.decode())
        chunk = os.read(process.stdout.fileno(), 4096)
        assert chunk, ("startup exited", output.decode())
        output += chunk
    selector.close()
    for user in [202, 203]:
        initial = subprocess.check_output(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
             "-H", "Zotero-API-Key: checkpoint11key" + str(user),
             "http://localhost:8191/users/" + str(user) + "/items/SHAREB22/file"], text=True)
        assert initial == "302", initial
        result = subprocess.run(
            ["curl", "-sSfL", "--max-time", "10", "-H", "Zotero-API-Key: checkpoint11key" + str(user),
             "http://localhost:8191/users/" + str(user) + "/items/SHAREB22/file"],
            capture_output=True)
        assert result.returncode == 0 and result.stdout == payload, (
            "checkpoint11 actual shared bare resolution failed", user,
            result.returncode, result.stderr.decode(), result.stdout)
    assert sql("select string_agg(blob_key, ',' order by library_id) from file where item_key='SHAREB22'") == "SHAREB22,SHAREB22"
    assert sql("select blob_key from file where item_key='PREFXK22'") == "libraries/22/PREFXK22"
    assert sql("select blob_key from file where item_key='WRNGFX22'") == "WRNGFX22"
    assert sql("select count(*) from file where item_key like 'PAGE%' and blob_key='libraries/22/'||item_key") == "33"
    assert sql("select blob_key from file where item_key='CMPRSS22'") == "CMPRSS22"
    compressed_download = subprocess.check_output(
        ["curl","-sSfL","--max-time","10","-H","Zotero-API-Key: checkpoint11key202",
         "http://localhost:8191/users/202/items/CMPRSS22/file"])
    assert compressed_download == compressed_bytes
    compressed_headers = subprocess.check_output(
        ["curl","-sS","-D","-","-o","/dev/null","--max-time","10","-H",
         "Zotero-API-Key: checkpoint11key202","http://localhost:8191/users/202/items/CMPRSS22/file"],text=True)
    assert "zotero-file-compressed: Yes" in compressed_headers
    assert "zotero-file-md5: "+compressed_hash in compressed_headers
    for key, pointer in [("CANDBL22","libraries/22/uploads/checkpoint11"),
                         ("BAREKY22","BAREKY22"), ("CUSTMK22","checkpoint11/custom"),
                         ("uploads/checkpoint11","libraries/22/uploads/checkpoint11")]:
        assert sql(f"select blob_key from file where item_key='{key}'") == pointer
    assert durable_snapshot() == snapshot
    assert sql("select count(*) from legacy_blob_reconciliation") == "0"
    assert sql("select count(*) from blob_retirements where blob_key='libraries/22/PREFXK22'") == "0"
    assert sql("select count(*) from blob_retirements where blob_key='libraries/22/WRNGFX22' and state='queued' and not_before > clock_timestamp()") == "1"
    assert subprocess.check_output(["aws", "s3", "cp", "s3://zotero/libraries/22/WRNGFX22", "-"]) == b"x" * len(payload)
    assert subprocess.check_output(["aws", "s3", "cp", "s3://zotero/SHAREB22", "-"]) == payload
    print("CHECKPOINT11_SHARED_BARE_HTTP=" + json.dumps({"libraries": [22,23], "bytes": len(payload), "md5": digest}), flush=True)
    print("CHECKPOINT11_PRESERVATION=" + json.dumps({"families": sorted(snapshot), "initial_status":302, "prefixed_kept":True, "wrong_prefix_retired_not_deleted":True, "untouched_classes":4, "candidate_rows":38, "descriptor_pages":2, "valid_prefix_with_bare_tombstone":True, "compressed_blob_md5_not_logical":True}), flush=True)
finally:
    process.terminate()
    process.wait(timeout=10)
    process.stdout.close()
# Restart is a no-op: no markers remain and no retirement grace is shortened.
restart_before = sql("select jsonb_agg(b order by blob_key) from blob_retirements b")
restart = subprocess.Popen(["sudo","-u","xotero","env",
    *[key+"="+value for key,value in environment.items() if key.startswith("XOTERO_")],
    "xotero"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print("CHECKPOINT11_RESTART_PID=" + str(restart.pid), flush=True)
try:
    with selectors.DefaultSelector() as selector:
        selector.register(restart.stdout, selectors.EVENT_READ)
        deadline = time.monotonic()+30
        output = b""
        while b"xotero listening" not in output:
            assert selector.select(max(0,deadline-time.monotonic())), output
            chunk = os.read(restart.stdout.fileno(),4096)
            assert chunk, output
            output += chunk
    assert durable_snapshot() == snapshot
    assert sql("select jsonb_agg(b order by blob_key) from blob_retirements b") == restart_before
finally:
    restart.terminate()
    restart.wait(timeout=10)
    restart.stdout.close()
print("CHECKPOINT11_RESTART=no-op", flush=True)

for label in ["wrong-hash", "missing", "wrong-size", "malformed-hash", "negative-size", "malformed-key",
              "provider403", "provider404-bucket", "unsupported-schema",
              "provider404-malformed", "provider404-proxy", "provider500", "provider-truncated-body",
              "claimed-target", "deleted-target", "claimed-current",
              "stale-pointer", "stale-hash", "stale-size", "stale-compression",
              "candidate-limit"]:
    database = "checkpoint11_" + label.replace("-", "_")
    subprocess.run(["sudo","-u","postgres","createdb","-O","xotero",
                    "-T","checkpoint11_template",database],check=True)
    match label:
        case "wrong-hash":
            sql("update file set blob_md5 = repeat('e',32) where library_id=23 and item_key='SHAREB22'")
        case "missing":
            sql("update file set item_key='MISSNG22',blob_key='libraries/'||library_id||'/MISSNG22' where item_key='SHAREB22'")
        case "wrong-size":
            sql("update file set filesize=1 where item_key='SHAREB22'")
        case "malformed-hash":
            sql("update file set blob_md5='not-md5' where item_key='SHAREB22'")
        case "negative-size":
            sql("update file set filesize=-1 where item_key='SHAREB22'")
        case "malformed-key":
            sql("update file set item_key='',blob_key='libraries/'||library_id||'/' where item_key='SHAREB22'")
        case "provider403" | "provider404-bucket" | "provider404-malformed" | "provider404-proxy" | "provider500" | "provider-truncated-body":
            pass
        case "unsupported-schema":
            sql("alter table file drop column blob_md5")
        case "claimed-target" | "deleted-target" | "claimed-current" | "stale-pointer" | "stale-hash" | "stale-size" | "stale-compression" | "candidate-limit":
            case_url = "postgresql://xotero@localhost/"+database+"?host=/run/postgresql"
            subprocess.run(["sudo","-u","xotero","env","DATABASE_URL="+case_url,
                            "sqlx","migrate","run","--source","/etc/xotero-test/current-migrations"],check=True)
            if label in ["claimed-target", "deleted-target", "claimed-current"]:
                state = "deleted" if label == "deleted-target" else "claimed"
                pointer = "libraries/22/SHAREB22" if label == "claimed-current" else "SHAREB22"
                deleted = "clock_timestamp()" if state == "deleted" else "null"
                sql(f"""insert into blob_retirements (blob_key,not_before,state,deleted_at)
                        values ('{pointer}',clock_timestamp(),'{state}',{deleted})""")
            if label.startswith("stale-"):
                column, value = {
                    "stale-pointer": ("blob_key", "'checkpoint11/replaced'"),
                    "stale-hash": ("blob_md5", "repeat('f',32)"),
                    "stale-size": ("filesize", "99"),
                    "stale-compression": ("compressed", "true"),
                }[label]
                sql(f"update file set {column}={value} where library_id=23 and item_key='SHAREB22'")
            if label == "candidate-limit":
                sql("""insert into legacy_blob_reconciliation
                       (library_id,item_key,blob_key,blob_md5,filesize,compressed)
                       select 22,'limit-'||n,'limit-'||n,repeat('a',32),1,false
                       from generate_series(1,4097) n""")
        case _:
            raise AssertionError(label)
    before = sql("select jsonb_agg(f order by library_id,item_key) from file f")
    before_objects = sql("select jsonb_agg(o order by library_id,kind,key) from object o")
    case_environment = environment | {"XOTERO_DATABASE_URL":
        "postgresql://xotero@localhost/"+database+"?host=/run/postgresql"}
    if label == "provider403":
        case_environment["XOTERO_S3_SECRET_KEY"] = "incorrect-checkpoint11-secret"
    if label == "provider404-bucket":
        case_environment["XOTERO_S3_BUCKET"] = "checkpoint11-no-such-bucket"
    fault_server = None
    fault_thread = None
    requests = []
    if label in ["provider404-malformed", "provider404-proxy", "provider500", "provider-truncated-body"]:
        class FaultProvider(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.command,self.path))
                if not self.path.startswith("/zotero/libraries/"):
                    self.send_response(200)
                    self.send_header("Content-Length",str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                status, body, declared = {
                    "provider404-malformed": (404,b"<Error><Code>NoSuchKey</Code><Message></Error>",None),
                    "provider404-proxy": (404,b"not found",None),
                    "provider500": (500,b"unavailable",None),
                    "provider-truncated-body": (200,b"he",len(payload)),
                }[label]
                self.send_response(status)
                self.send_header("Content-Length",str(len(body) if declared is None else declared))
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
            do_POST = do_GET
            do_PUT = do_GET
            do_DELETE = do_GET
            def log_message(self, format, *args):
                return
        fault_server = http.server.HTTPServer(("127.0.0.1",0),FaultProvider)
        print("CHECKPOINT11_FAULT_PROVIDER="+json.dumps({"pid":os.getpid(),"port":fault_server.server_port,"case":label}),flush=True)
        fault_thread = threading.Thread(target=fault_server.serve_forever)
        fault_thread.start()
        case_environment["XOTERO_S3_ENDPOINT"] = "http://127.0.0.1:"+str(fault_server.server_port)
    try:
        result = subprocess.run(["sudo","-u","xotero","env",
            *[key+"="+value for key,value in case_environment.items() if key.startswith("XOTERO_")],
            "xotero"],capture_output=True,timeout=30)
    finally:
        if fault_server is not None:
            fault_server.shutdown()
            fault_thread.join(timeout=10)
            assert not fault_thread.is_alive()
            fault_server.server_close()
    assert result.returncode != 0, label
    assert b"xotero listening" not in result.stdout, (label,result.stdout)
    expected_error = {
        "wrong-hash": "neither current nor bare object verifies",
        "missing": "neither current nor bare object verifies",
        "wrong-size": "neither current nor bare object verifies",
        "malformed-hash": "invalid recorded byte size or blob MD5",
        "negative-size": "invalid recorded byte size or blob MD5",
        "malformed-key": "unsupported recorded legacy item key",
        "provider403": "403",
        "provider404-bucket": "not a complete NoSuchKey error document",
        "provider404-malformed": "not a complete NoSuchKey error document",
        "provider404-proxy": "not a complete NoSuchKey error document",
        "provider500": "500",
        "provider-truncated-body": "legacy reconciliation storage",
        "unsupported-schema": "blob_md5",
        "claimed-target": "bare object is claimed or deleted",
        "deleted-target": "bare object is claimed or deleted",
        "claimed-current": "current object is claimed or deleted",
        "stale-pointer": "recorded file descriptor changed",
        "stale-hash": "recorded file descriptor changed",
        "stale-size": "recorded file descriptor changed",
        "stale-compression": "recorded file descriptor changed",
        "candidate-limit": "candidate count exceeds bounded startup limit",
    }[label]
    failure_output = (result.stdout + result.stderr).decode()
    assert expected_error in failure_output, (label,failure_output)
    if label == "unsupported-schema":
        assert "does not exist" in failure_output, failure_output
    assert sql("select jsonb_agg(f order by library_id,item_key) from file f") == before, label
    assert sql("select jsonb_agg(o order by library_id,kind,key) from object o") == before_objects, label
    if fault_server is not None:
        assert requests and all(method=="GET" and path.startswith("/zotero/libraries/")
                                for method,path in requests), (label,requests)
    print("CHECKPOINT11_FAILURE="+json.dumps({"case":label,"exit":result.returncode,
          "pointers_unchanged":True,"objects_unchanged":True,"listener_started":False,
          "fault_requests":requests,
          "error":failure_output.strip()}),flush=True)

# Subscribe to exact PostgreSQL lock state before releasing a competing writer.
database = "checkpoint11_lock_race"
subprocess.run(["sudo","-u","postgres","createdb","-O","xotero",
                "-T","checkpoint11_template",database],check=True)
case_url = "postgresql://xotero@localhost/"+database+"?host=/run/postgresql"
subprocess.run(["sudo","-u","xotero","env","DATABASE_URL="+case_url,
                "sqlx","migrate","run","--source","/etc/xotero-test/current-migrations"],check=True)
blocker = subprocess.Popen(["sudo","-u","xotero","psql","-v","ON_ERROR_STOP=1","-At","-d",database],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
print("CHECKPOINT11_LOCK_WRITER_PID="+str(blocker.pid),flush=True)
race = None
try:
    blocker.stdin.write(b"begin; select id from library where id=23 for update;\n\\echo CHECKPOINT11_LOCKED\n")
    blocker.stdin.flush()
    with selectors.DefaultSelector() as selector:
        selector.register(blocker.stdout,selectors.EVENT_READ)
        output = b""
        deadline = time.monotonic()+10
        while b"CHECKPOINT11_LOCKED" not in output:
            assert selector.select(max(0,deadline-time.monotonic())),output
            chunk = os.read(blocker.stdout.fileno(),4096)
            assert chunk,output
            output += chunk
    race_environment = environment | {"XOTERO_DATABASE_URL":case_url+"&application_name=checkpoint11_race"}
    race = subprocess.Popen(["sudo","-u","xotero","env",
        *[key+"="+value for key,value in race_environment.items() if key.startswith("XOTERO_")],
        "xotero"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    print("CHECKPOINT11_RACE_SERVER_PID="+str(race.pid),flush=True)
    sql("""set statement_timeout='10s'; do $$ begin loop
           perform pg_stat_clear_snapshot();
           exit when exists (select 1 from pg_stat_activity
             where application_name='checkpoint11_race' and wait_event_type='Lock'
             and query like 'select l.id from library l where exists%');
           end loop; end $$""")
    assert sql("""select count(*) from pg_locks l join pg_stat_activity a using(pid)
                  where a.application_name='checkpoint11_race'
                  and l.locktype='advisory' and l.classid=1481593922""") == "0"
    blocker.stdin.write(b"update file set blob_md5=repeat('d',32) where library_id=23 and item_key='SHAREB22'; commit;\n\\q\n")
    blocker.stdin.flush()
    blocker.wait(timeout=10)
    assert blocker.returncode == 0
    before = sql("select jsonb_agg(f order by library_id,item_key) from file f")
    output,_ = race.communicate(timeout=30)
    assert race.returncode != 0 and b"recorded file descriptor changed" in output,output
    assert b"xotero listening" not in output,output
    assert sql("select jsonb_agg(f order by library_id,item_key) from file f") == before
    print("CHECKPOINT11_LOCK_RACE="+json.dumps({"observed_library_wait":True,
          "blob_locks_before_all_libraries":0,"fresh_descriptor_rejected":True,
          "whole_pass_rollback":True}),flush=True)
finally:
    if blocker.poll() is None:
        blocker.terminate()
        blocker.wait(timeout=10)
    blocker.stdin.close()
    blocker.stdout.close()
    if race is not None:
        if race.poll() is None:
            race.terminate()
            race.wait(timeout=10)
        race.stdout.close()
'''
    machine.succeed(
        "printf 0123456789abcdef0123456789abcdef "
        "> /etc/xotero-test/checkpoint11-kdf"
    )
    machine.succeed(f"python3 -c {shlex.quote(upgrade_script)}")

# Recreate the exact pre-identity schema and populate every durable data family.
machine.succeed(
    "sudo -u xotero env "
    "'DATABASE_URL=postgresql://xotero@localhost/xotero?host=/run/postgresql' "
    "sqlx migrate run --source /etc/xotero-test/migrations"
)
assert (
    psql("select string_agg(version::text, ',' order by version) from _sqlx_migrations")
    == "1,2,3,4,5,6,7"
)
psql("update library set version = 7 where id = 1")
psql(
    """insert into object (library_id, kind, key, version, data)
       values (1, 'item', 'LEGACY22', 7,
               '{"key":"LEGACY22","version":7,"itemType":"attachment",
                 "linkMode":"imported_file","filename":"legacy.pdf",
                 "contentType":"application/pdf","title":"preserved"}')"""
)
psql(
    """insert into setting (library_id, key, version, value)
       values (1, 'legacySetting', 7, '{"enabled":true}')"""
)
psql(
    """insert into deletion (library_id, kind, key, version)
       values (1, 'item', 'DELETED2', 6)"""
)
psql(
    """insert into file
       (library_id, item_key, md5, filename, filesize, mtime, version)
       values (1, 'LEGACY22', '5d41402abc4b2a76b9719d911017c592',
               'legacy.pdf', 5, 1700000000000, 7)"""
)
psql("insert into library (id, version) values (22, 0)")
psql(
    """insert into object (library_id, kind, key, version, data)
       values (22, 'item', 'OLDLIB22', 0,
               '{"key":"OLDLIB22","version":0,"itemType":"attachment",
                 "linkMode":"imported_file","filename":"old.pdf",
                 "contentType":"application/pdf"}')"""
)
psql(
    """insert into file
       (library_id, item_key, md5, filename, filesize, mtime, version)
       values (22, 'OLDLIB22', '27b525e7d8fdb7db5b821c3a0bf7c60e',
               'old.pdf', 5, 1700000000001, 0)"""
)
machine.succeed("printf old22 | aws s3 cp - s3://zotero/libraries/22/OLDLIB22")
psql(
    """insert into fulltext
       (library_id, item_key, content, indexed_chars, total_chars,
        indexed_pages, total_pages, version)
       values (1, 'LEGACY22', 'legacy text', 11, 11, 1, 1, 7)"""
)

# Apply schema before startup so the actual identity sequence can be renamed
# before bootstrap and provisioning exercise it.
machine.succeed(
    "sudo -u xotero env "
    "'DATABASE_URL=postgresql://xotero@localhost/xotero?host=/run/postgresql' "
    "sqlx migrate run --source /etc/xotero-test/current-migrations"
)
machine.succeed(
    "sudo -u postgres psql -v ON_ERROR_STOP=1 -d xotero "
    "-c 'alter sequence users_id_seq rename to users_id_checkpoint20'"
)
machine.start_job("xotero.service")
machine.wait_for_unit("xotero.service")
machine.wait_for_open_port(8189)

with subtest("populated v7 data survives the identity migration"):
    assert (
        psql("select string_agg(version::text, ',' order by version) from _sqlx_migrations")
          == "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21"
    )
    assert psql("select count(*) from pending_uploads") == "0"
    assert psql("select bool_and(not compressed) from file") == "t"
    assert psql("select bool_and(blob_md5 = md5) from file") == "t"
    assert psql("select (id, version) = (1, 7) from library where id = 1") == "t"
    assert (
        psql(
            """select library_id = 1 and kind = 'item' and version = 7
                      and data = '{"key":"LEGACY22","version":7,
                        "itemType":"attachment","linkMode":"imported_file",
                        "filename":"legacy.pdf","contentType":"application/pdf",
                        "title":"preserved"}'::jsonb
               from object where key = 'LEGACY22'"""
        )
        == "t"
    )
    assert (
        psql(
            """select library_id = 1 and version = 7
                      and value = '{"enabled":true}'::jsonb
               from setting where key = 'legacySetting'"""
        )
        == "t"
    )
    assert (
        psql(
            """select library_id = 1 and kind = 'item' and version = 6
               from deletion where key = 'DELETED2'"""
        )
        == "t"
    )
    assert (
        psql(
            """select library_id = 1
                      and md5 = '5d41402abc4b2a76b9719d911017c592'
                      and filename = 'legacy.pdf' and filesize = 5
                      and mtime = 1700000000000 and version = 7
                      and blob_key = 'LEGACY22'
               from file where item_key = 'LEGACY22'"""
        )
        == "t"
    )
    assert (
        psql(
            """select library_id = 1 and content = 'legacy text'
                      and indexed_chars = 11 and total_chars = 11
                      and indexed_pages = 1 and total_pages = 1 and version = 7
               from fulltext where item_key = 'LEGACY22'"""
        )
        == "t"
    )

with subtest("bootstrap identity owns the legacy personal library"):
    assert psql("select username from users where id = 101") == "alice"
    assert psql("select display_name from users where id = 101") == "Alice"
    assert psql("select library_id from personal_libraries where user_id = 101") == "1"
    assert psql("select kind from library where id = 1") == "personal"
    assert (
        psql(
            f"""select user_id = 101
                from external_identities
                where issuer = '{oidc_issuer}' and subject = '{oidc_subject}'"""
        )
        == "t"
    )
    assert (
        psql(
            """select count(*) = 1
               from external_identities
               where user_id = 101"""
        )
        == "t"
    )
    assert psql("select pg_get_serial_sequence('users', 'id')") == (
        "public.users_id_checkpoint20"
    )
    assert psql(
        "select last_value from users_id_checkpoint20"
    ) == "101"

with subtest("bootstrap OIDC identity remains unique across restarts"):
    restart_xotero()
    assert (
        psql(
            f"""select count(*) = 1 and min(user_id) = 101
                from external_identities
                where issuer = '{oidc_issuer}' and subject = '{oidc_subject}'"""
        )
        == "t"
    )

# Seed two DB-owned keys. Only SHA-256 digests enter PostgreSQL.
psql(
    """insert into users (id, username, display_name)
       values (202, 'bob', 'Bob')"""
)
psql(
    """insert into users (id, username, display_name, disabled_at)
       values (404, 'disabled-member', 'Disabled Member', now())"""
)
psql("insert into personal_libraries (user_id, library_id) values (202, 22)")
psql(
    f"""insert into external_identities (issuer, subject, user_id)
        values ('{oidc_issuer}', '{oidc_bob_subject}', 202)"""
)
psql("update library set version = 3 where id = 22")
psql("insert into library (id, version, kind) values (33, 17, 'group')")
psql(
    """begin;
       insert into groups
       (id, library_id, owner_user_id, name, description, url, type,
        library_reading, library_editing, file_editing, version,
        created_at, updated_at)
       values
       (303, 33, 101, 'Alice Research Group', 'Private collaboration fixture',
        'https://groups.example.test/alice-research', 'Private',
        'members', 'admins', 'admins', 4,
        '2024-01-02 03:04:05+00', '2024-02-03 04:05:06+00');
       insert into group_memberships (group_id, user_id, role)
       values
       (303, 101, 'owner'),
       (303, 202, 'member'),
       (303, 404, 'member');
       commit"""
)
psql(
    """insert into object (library_id, kind, key, version, data)
       values
       (33, 'item', 'GRPBKK22', 17,
        '{"key":"GRPBKK22","version":17,"itemType":"book",
          "title":"Group fixture item"}'),
       (33, 'item', 'GRPTRS22', 17,
        '{"key":"GRPTRS22","version":17,"itemType":"book",
          "title":"Trashed group fixture item","deleted":true}')"""
)
psql(
    """insert into object (library_id, kind, key, version, data)
       values
       (1, 'item', 'GRPBKK22', 7,
        '{"key":"GRPBKK22","version":7,"itemType":"book",
          "title":"Personal collision fixture"}')"""
)
psql(
    """insert into setting (library_id, key, version, value)
       values (33, 'groupSetting', 17, '"shared"')"""
)
psql(
    """insert into object (library_id, kind, key, version, data)
       values (22, 'item', 'LEGACY22', 3,
               '{"key":"LEGACY22","version":3,"itemType":"book",
                 "title":"Bob private item",
                 "collections":["COLL2222"],
                 "tags":[{"tag":"shared-tag"},{"tag":"book-only"}]}'),
              (22, 'item', 'PRIVNTE2', 3,
               '{"key":"PRIVNTE2","version":3,"itemType":"note",
                 "note":"Bob private note",
                 "collections":["COLL2222"],
                 "tags":[{"tag":"shared-tag"},{"tag":"note-only"}]}'),
              (22, 'item', 'PRIVATCH', 3,
               '{"key":"PRIVATCH","version":3,"itemType":"attachment",
                 "linkMode":"imported_file","filename":"private.pdf",
                 "contentType":"application/pdf","title":"Bob attachment",
                 "collections":["COLL2222"]}'),
              (22, 'item', 'PRIVANN2', 3,
               '{"key":"PRIVANN2","version":3,"itemType":"annotation",
                 "parentItem":"PRIVATCH","annotationType":"highlight",
                 "annotationText":"Visible annotation",
                 "tags":[{"tag":"annotation-only"}]}'),
              (22, 'item', 'TRSHNTE2', 3,
               '{"key":"TRSHNTE2","version":3,"itemType":"note",
                 "note":"Trashed private note","deleted":true}'),
              (22, 'item', 'TRSHANN2', 3,
               '{"key":"TRSHANN2","version":3,"itemType":"annotation",
                 "parentItem":"PRIVATCH","annotationType":"highlight",
                 "annotationText":"Trashed annotation","deleted":true}')"""
)
psql(
    """insert into object (library_id, kind, key, version, data)
       values (22, 'collection', 'COLL2222', 3,
               '{"key":"COLL2222","version":3,"name":"Private collection",
                 "parentCollection":false}')"""
)
psql(
    """insert into api_keys (id, user_id, name, token_hash)
       values
       (1001, 101, 'Alice desktop',
        decode('30946709724859f7e30069553145fcc7b4610e4fa1e42015c02c7546c52730f7', 'hex')),
       (1002, 202, 'Bob reader',
        decode('1601245df15c0f91020aaed3b59109703c77e1254eab802548d921b1e5253774', 'hex')),
       (1006, 202, 'Bob read only',
        decode('3f3f0b28d688250ab4da083a59d4a0b55fcd95d531a9849dd3f5116e98d95e14', 'hex')),
       (1005, 202, 'Bob desktop',
        decode('d777b9d2f600ae973eaea591e10ff1020d0f154c13c18be0b317bce4f652b30d', 'hex')),
       (1007, 202, 'Bob no-notes writer',
        decode('54299e610a6b8388e97182c0280ec5c998c48cab5c6618f782aefbcaa8abfa97', 'hex')),
       (1003, 202, 'Revoked',
        decode('e6dc6348b6d83af6db9a10d7224b6b0da3c340da34b76e66afd7bbf1e0ab30a8', 'hex'))"""
)
psql(
    """insert into api_key_user_permissions
       (api_key_id, library, notes, write, files)
       values
       (1001, true, true, true, true),
       (1002, true, false, false, true),
       (1006, true, true, false, true),
       (1005, true, true, true, true),
       (1007, true, false, true, true),
       (1003, true, true, true, true)"""
)
psql(
    """insert into api_key_all_groups_permissions (api_key_id, library, write)
       values (1001, true, true)"""
)
psql(
    """insert into api_key_group_permissions
       (api_key_id, user_id, group_id, library, write)
       values (1002, 202, 303, true, false)"""
)
psql("update api_keys set revoked_at = now() where id = 1003")

with subtest("file permissions cover legacy and percent-decoded route keys"):
    snapshot_before = body_admission_snapshot()
    assert (
        psql(
            """select bool_and(files) from api_key_user_permissions
               where api_key_id in (1001, 1002)"""
        )
        == "t"
    )
    psql(
        """update api_key_user_permissions set files = false
           where api_key_id in (1001, 1002)"""
    )
    try:
        legacy_status, legacy_headers = attachment_route_receipt(
            "/users/202/items/OLDLIB22/file", bob
        )
        plain_status, plain_headers = attachment_route_receipt(
            "/users/101/items/LEGACY22/file", alice
        )
        encoded_status, encoded_headers = attachment_route_receipt(
            "/users/101/items/%4CEGACY22/file", alice, path_as_is=True
        )
    finally:
        psql(
            """update api_key_user_permissions set files = true
               where api_key_id in (1001, 1002)"""
        )
    assert (
        psql(
            """select bool_and(files) from api_key_user_permissions
               where api_key_id in (1001, 1002)"""
        )
        == "t"
    )
    assert body_admission_snapshot() == snapshot_before
    print("ATTACHMENT-ROUTE legacy-path fixture restored; snapshots unchanged")

    assert legacy_status == 403, ("legacy key file read", legacy_status)
    assert not any(line.lower().startswith("location:") for line in legacy_headers)
    assert plain_status == 403, ("plain valid key file read", plain_status)
    assert not any(line.lower().startswith("location:") for line in plain_headers)
    assert encoded_status == 403, ("encoded valid key file read", encoded_status)
    assert not any(line.lower().startswith("location:") for line in encoded_headers)

with subtest("attachment permission routes require exact paths and scoped grants"):
    snapshot_before = body_admission_snapshot()
    assert psql(
        "select files from api_key_user_permissions where api_key_id = 1002"
    ) == "t"
    psql("update api_key_user_permissions set files = false where api_key_id = 1002")
    try:
        for path, method, expected in (
            ("/users/202/items/PRIVATCH/file", "GET", 403),
            ("/users/202/items/PRIVATCH/file/view/url", "GET", 403),
            ("/users/202/items/PRIVATCH/filesuffix", "GET", 404),
            ("/users/202/items/PRIVATCH/file/view", "GET", 404),
            ("/users/202/items/PRIVATCH/file/view/url/extra", "GET", 404),
            ("/users/202/items/PRIVATCH/file/", "GET", 404),
            ("/users/202/items/PRIVATCH/file", "PUT", 403),
            ("/groups/303/items/GRPBKK22/file", "GET", 404),
            ("/groups/303/items/GRPBKK22/file", "PUT", 403),
        ):
            status, response_headers = attachment_route_receipt(path, bob, method)
            assert status == expected, (path, method, status, expected)
            if expected == 403:
                assert not any(
                    line.lower().startswith("location:")
                    for line in response_headers
                )

        allowed_status, allowed_headers = attachment_route_receipt(
            "/users/101/items/LEGACY22/file", alice
        )
        assert allowed_status == 302
        assert any(line.lower().startswith("location:") for line in allowed_headers)
        url_status, _ = attachment_route_receipt(
            "/users/101/items/LEGACY22/file/view/url", alice
        )
        assert url_status == 404
    finally:
        psql("update api_key_user_permissions set files = true where api_key_id = 1002")
    assert body_admission_snapshot() == snapshot_before
    print("ATTACHMENT-ROUTE storage-and-version-snapshot=unchanged")

with subtest("non-default legacy attachment path survives the blob-key migration"):
    assert (
        psql("select blob_key from file where library_id = 22 and item_key = 'OLDLIB22'")
        == "libraries/22/OLDLIB22"
    )
    old_location = machine.succeed(
        f"curl -sf -D /tmp/old-library-file -o /dev/null "
        f"{base}/users/202/items/OLDLIB22/file {api_headers} "
        f"-H 'Zotero-API-Key: {bob_full}' "
        "&& grep -i '^location:' /tmp/old-library-file | tr -d '\\r' | awk '{print $2}'"
    ).strip()
    machine.succeed(
        "grep -iq 'zotero-file-md5: 27b525e7d8fdb7db5b821c3a0bf7c60e' "
        "/tmp/old-library-file"
    )
    assert machine.succeed(f"curl -sf '{old_location}'").strip() == "old22"
    psql("delete from object where library_id = 22 and key = 'OLDLIB22'")

with subtest("current-key introspection returns the authenticated DB owner"):
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {alice}' {base}/keys/current |
        jq -e '. == {{
          "key":"{alice}",
          "userID":101,
          "username":"alice",
          "displayName":"Alice",
          "access":{{
            "user":{{
              "library":true,"files":true,"notes":true,"write":true
            }},
            "groups":{{"all":{{"library":true,"write":true}}}}
          }}
        }}'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' {base}/keys/current |
        jq -e '. == {{
          "key":"{bob}",
          "userID":202,
          "username":"bob",
          "displayName":"Bob",
          "access":{{
            "user":{{"library":true,"files":true}},
            "groups":{{"303":{{"library":true,"write":false}}}}
          }}
        }}'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob_full}' {base}/keys/current |
        jq -e '. == {{
          "key":"{bob_full}",
          "userID":202,
          "username":"bob",
          "displayName":"Bob",
          "access":{{"user":{{
            "library":true,"files":true,"notes":true,"write":true
          }}}}
        }}'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob_ro}' {base}/keys/current |
        jq -e '. == {{
          "key":"{bob_ro}",
          "userID":202,
          "username":"bob",
          "displayName":"Bob",
          "access":{{"user":{{
            "library":true,"files":true,"notes":true
          }}}}
        }}'"""
    )

with subtest("library version lookup failures return 500 without version headers"):
    # Given: warmed real queries and ordinary service-role column privileges.
    acl_sql = """select json_build_array(
        current_user, (select rolsuper from pg_roles where rolname = current_user),
        (select pg_get_userbyid(relowner) from pg_class where oid = 'library'::regclass),
        has_table_privilege('library', 'SELECT'),
        has_column_privilege('library', 'id', 'SELECT'),
        has_column_privilege('library', 'kind', 'SELECT'),
        has_column_privilege('library', 'version', 'SELECT'),
        (select count(*) from pg_attribute a, lateral aclexplode(a.attacl)
         where attrelid = 'library'::regclass),
        (select coalesce(json_agg(a order by a::text), '[]'::json)
         from (select grantee, privilege_type, is_grantable
               from pg_class c, lateral aclexplode(c.relacl)
               where c.oid = 'library'::regclass and grantee <> c.relowner) a)
    )"""
    acl_before = json.loads(psql(acl_sql))
    assert acl_before[:8] == ["xotero", False, "xotero", True, True, True, True, 0], acl_before
    print("VERSION-FAULT engine=" + psql("select version()") + " acl=" + json.dumps(acl_before))
    snapshot_sql = " union all ".join(
        f"select '{table}', md5(coalesce(string_agg(row_to_json(t)::text, "
        f"'' order by row_to_json(t)::text), '')) from {table} t"
        for table in (
            "library", "object", "file", "setting", "fulltext", "deletion",
            "pending_uploads", "users", "personal_libraries", "api_keys",
            "api_key_user_permissions", "api_key_group_permissions",
            "api_key_all_groups_permissions", "groups", "group_memberships",
        )
    )
    snapshot_before = psql(snapshot_sql)
    versions_before = psql("select id, version from library order by id")
    failures = []

    def version_response(
        path: str, expected: int, phase: str, extra: str = "",
        method: str = "GET", token: str = alice,
    ) -> tuple[int, list[str], str]:
        command = (
            f"curl --max-time 10 -sS -i -X {method} {api_headers} "
            f"-H 'Zotero-API-Key: {token}' {extra} {shlex.quote(base + path)}"
        )
        raw = machine.succeed(command).replace("\r\n", "\n")
        headers, _, body = raw.partition("\n\n")
        status = int(headers.splitlines()[0].split()[1])
        version_headers = [
            line.split(":", 1)[1].strip()
            for line in headers.splitlines()
            if line.lower().startswith("last-modified-version:")
        ]
        receipt = dict(phase=phase, command=command, status=status,
                       versions=version_headers, headers=headers, body=body)
        print("VERSION-FAULT " + json.dumps(receipt))
        if status != expected or (phase == "fault" and version_headers):
            failures.append(receipt)
        return status, version_headers, body

    requests = []
    for scope, library_id, item_key in (
        ("/users/101", 1, "LEGACY22"), ("/groups/303", 33, "GRPBKK22"),
    ):
        current = int(psql(f"select version from library where id = {library_id}"))
        requests.extend([
            (f"{scope}/settings?since=0", 200, "", "GET", current),
            (f"{scope}/settings", 304, f"-H 'If-Modified-Since-Version: {current}'", "GET", current),
            (f"{scope}/settings?since={current}", 304, "", "GET", current),
            (f"{scope}/items?itemKey={item_key}&format=json", 200, "", "GET", current),
            (f"{scope}/collections?collectionKey=MISS2222&format=json", 200, "", "GET", current),
            (f"{scope}/searches?searchKey=MISS2222&format=json", 200, "", "GET", current),
            (f"{scope}/items?limit=1", 200, "", "GET", current),
            (f"{scope}/items?format=keys", 200, "", "GET", current),
            (f"{scope}/tags", 200, "", "GET", current),
            (f"{scope}/deleted?since=0", 200, "", "GET", current),
        ])
        for endpoint in ("items", "items/top", "collections", "searches", "fulltext"):
            for since in (0, current):
                requests.append((f"{scope}/{endpoint}?format=versions&since={since}", 200, "", "GET", current))
        for endpoint, method, body, status in (
            ("items", "POST", "[]", 200), ("settings", "POST", "{}", 204),
            ("settings?settingKey=", "DELETE", None, 204),
            ("tags?tags=", "DELETE", None, 204),
            ("fulltext", "POST", "[]", 200),
            ("items?itemKey=", "DELETE", None, 204),
            ("items", "POST", '[{"key":"FAULT222","itemType":"book"}]', 412),
        ):
            expected_version = current - 1 if status == 412 else current
            extra = f"-H 'If-Unmodified-Since-Version: {expected_version}'"
            if body is not None:
                extra += f" -H 'Content-Type: application/json' --data {shlex.quote(body)}"
            requests.append((f"{scope}/{endpoint}", status, extra, method, current))
    file_form = "filename=legacy.pdf&filesize=5&mtime=1700000000000&md5="
    for precondition, md5, status in (
        ("If-None-Match: *", "5d41402abc4b2a76b9719d911017c592", 200),
        ("If-None-Match: *", "00000000000000000000000000000000", 412),
        ("If-Match: 00000000000000000000000000000000", "5d41402abc4b2a76b9719d911017c592", 412),
    ):
        requests.append(("/users/101/items/LEGACY22/file", status,
                         f"-H '{precondition}' --data '{file_form}{md5}'", "POST",
                         int(psql("select version from library where id = 1"))))

    def version_controls(phase: str) -> None:
        for token, owner in ((alice, 101), (bob, 202), (recovery, 101)):
            assert get_json("/keys/current", token)["userID"] == owner
        for path, token, method, extra, status in (
            ("/keys/current", "invalidkey", "GET", "", 403),
            ("/users/101/settings", bob, "GET", "", 403),
            ("/groups/303/items?format=versions", bob_full, "GET", "", 403),
            ("/groups/999/items?format=versions", alice, "GET", "", 404),
            ("/users/101/items/bad!/file", alice, "POST", "-H 'If-None-Match: *' --data md5=0", 400),
            ("/users/101/items", alice, "POST", "--data invalid-json", 400),
            ("/users/101/items", alice, "POST", "--data '[]'", 428),
        ):
            assert version_response(path, status, phase + "-control", extra, method, token)[0] == status
        assert get_json("/users/101/groups?format=versions", alice) == {"303": 4}
        print("VERSION-FAULT controls=" + phase + " owners=101,202,101 invalid=403 group-discovery=200")

    for path, status, extra, method, current in requests:
        actual, headers, body = version_response(path, status, "warm", extra, method)
        assert actual == status and headers == [str(current)], (path, actual, headers)
        if "format=versions&since=" in path and path.endswith(f"since={current}"):
            assert json.loads(body) == {}
    version_controls("warm")

    # When: deny only library-version SELECT, leaving live authentication intact.
    try:
        print("VERSION-FAULT SQL: BEGIN; REVOKE SELECT ON TABLE public.library FROM xotero; GRANT SELECT (id, kind) ON TABLE public.library TO xotero; COMMIT;")
        psql("begin; revoke select on table public.library from xotero; grant select (id, kind) on table public.library to xotero; commit")
        acl_fault = json.loads(psql(acl_sql))
        assert acl_fault[:7] == ["xotero", False, "xotero", False, True, True, False], acl_fault
        assert psql("select id, kind from library where id = 1") == "1|personal"
        denied, denial = machine.execute(
            "sudo -u xotero psql -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -At "
            "-d xotero -c 'select version from library where id = 1' 2>&1"
        )
        print("VERSION-FAULT SQLSTATE receipt: " + denial)
        assert denied != 0 and "42501" in denial, (denied, denial)
        version_controls("fault")
        # Then: all version-dependent paths fail without a fabricated header.
        for path, _, extra, method, _ in requests:
            version_response(path, 500, "fault", extra, method)
    finally:
        print("VERSION-FAULT SQL: BEGIN; REVOKE SELECT (id, kind) ON TABLE public.library FROM xotero; GRANT SELECT ON TABLE public.library TO xotero; COMMIT;")
        psql("begin; revoke select (id, kind) on table public.library from xotero; grant select on table public.library to xotero; commit")
        assert json.loads(psql(acl_sql)) == acl_before
        assert psql(snapshot_sql) == snapshot_before
        assert psql("select id, version from library order by id") == versions_before
        print("VERSION-FAULT restore=effective-privileges-equal snapshots=unchanged versions=" + versions_before)
        version_controls("restored")
        for path, status, extra, method, current in requests:
            actual, headers, body = version_response(path, status, "restored", extra, method)
            assert actual == status and headers == [str(current)], (path, actual, headers)
            if "format=versions&since=" in path and path.endswith(f"since={current}"):
                assert json.loads(body) == {}
        assert psql(snapshot_sql) == snapshot_before
    assert not failures, json.dumps(failures)

with subtest("group listings intersect user membership with key grants"):
    assert (
        psql(
            """select g.library_id = 33 and g.version = 4
                      and l.version = 17 and g.owner_user_id = 101
               from groups g join library l on l.id = g.library_id
               where g.id = 303"""
        )
        == "t"
    )
    for user_id, token, is_admin in (
        (101, alice, True),
        (202, bob, False),
    ):
        headers = machine.succeed(
            f"curl -sf -D - -o /tmp/groups-{user_id}.json "
            f"{api_headers} -H 'Zotero-API-Key: {token}' "
            f"'{base}/users/{user_id}/groups'"
        )
        assert response_header(headers, "Total-Results") == "1"
        listing = json.loads(machine.succeed(f"cat /tmp/groups-{user_id}.json"))
        assert len(listing) == 1
        assert_group_entry(listing[0], is_admin)
        assert get_json(f"/users/{user_id}/groups?format=versions", token) == {
            "303": 4
        }

    assert get_json("/users/202/groups", bob_ro) == []
    assert get_json("/users/202/groups?format=versions", bob_ro) == {}
    assert http_code("/groups/303", bob_ro) == "404"
    alice_cross_listing = get_json("/users/202/groups", alice)
    assert len(alice_cross_listing) == 1
    assert_group_entry(alice_cross_listing[0], True)
    bob_cross_listing = get_json("/users/101/groups", bob)
    assert len(bob_cross_listing) == 1
    assert_group_entry(bob_cross_listing[0], False)
    assert http_code("/users/404/groups", alice) == "404"
    assert http_code("/users/999/groups", alice) == "404"

    list_head = machine.succeed(
        f"curl -sfI {api_headers} -H 'Zotero-API-Key: {alice}' "
        f"{base}/users/101/groups"
    )
    assert response_header(list_head, "Total-Results") == "1"
    assert 'rel="alternate"' in response_header(list_head, "Link")
    assert not any(
        line.lower().startswith("last-modified-version:")
        for line in list_head.splitlines()
    )
    versions_headers = machine.succeed(
        f"curl -sf -D - -o /tmp/group-versions.json "
        f"{api_headers} -H 'Zotero-API-Key: {alice}' "
        f"'{base}/users/101/groups?format=versions'"
    )
    assert response_header(versions_headers, "Total-Results") == "1"
    assert 'rel="alternate"' in response_header(versions_headers, "Link")
    assert not any(
        line.lower().startswith("last-modified-version:")
        for line in versions_headers.splitlines()
    )
    assert json.loads(machine.succeed("cat /tmp/group-versions.json")) == {"303": 4}

with subtest("group metadata and HEAD use upstream wrapper and version"):
    for label, token, is_admin in (
        ("owner", alice, True),
        ("member", bob, False),
    ):
        get_headers = machine.succeed(
            f"curl -sf -D - -o /tmp/group-{label}.json "
            f"{api_headers} -H 'Zotero-API-Key: {token}' "
            f"{base}/groups/303"
        )
        assert response_header(get_headers, "Last-Modified-Version") == "4"
        entry = json.loads(machine.succeed(f"cat /tmp/group-{label}.json"))
        assert_group_entry(entry, is_admin)

        head_headers = machine.succeed(
            f"curl -sfI {api_headers} -H 'Zotero-API-Key: {token}' "
            f"{base}/groups/303"
        )
        assert response_header(head_headers, "Last-Modified-Version") == "4"
        assert not any(
            line.lower().startswith("total-results:")
            for line in head_headers.splitlines()
        )

with subtest("group admins receive isAdmin and admin membership metadata"):
    psql(
        """update group_memberships set role = 'admin'
           where group_id = 303 and user_id = 202"""
    )
    admin_entry = get_json("/groups/303", bob)
    assert admin_entry["meta"]["isAdmin"] is True
    assert admin_entry["data"]["admins"] == [202]
    assert "members" not in admin_entry["data"]
    psql(
        """update group_memberships set role = 'member'
           where group_id = 303 and user_id = 202"""
    )
    assert_group_entry(get_json("/groups/303", bob), False)

with subtest("membership removal immediately revokes explicit group discovery"):
    psql("delete from group_memberships where group_id = 303 and user_id = 202")
    assert (
        psql(
            """select count(*) = 0
               from api_key_group_permissions
               where api_key_id = 1002 and user_id = 202 and group_id = 303"""
        )
        == "t"
    )
    assert get_json("/users/202/groups?format=versions", bob) == {}
    assert http_code("/groups/303", bob) == "404"
    assert http_code("/groups/303/items?format=versions", bob) == "403"
    assert get_json("/users/202/groups?format=versions", alice) == {}
    assert get_json("/users/101/groups?format=versions", bob) == {}
    assert get_json("/users/101/groups?format=versions", alice) == {"303": 4}
    assert http_code("/groups/303", alice) == "200"

    psql(
        """insert into group_memberships (group_id, user_id, role)
           values (303, 202, 'member')"""
    )
    psql(
        """insert into api_key_group_permissions
           (api_key_id, user_id, group_id, library, write)
           values (1002, 202, 303, true, false)"""
    )

with subtest("a disabled private-group owner hides the group from members"):
    psql("update users set disabled_at = now() where id = 101")
    assert get_json("/users/202/groups?format=versions", bob) == {}
    assert http_code("/groups/303", bob) == "404"
    psql("update users set disabled_at = null where id = 101")
    assert get_json("/users/202/groups?format=versions", bob) == {"303": 4}
    assert http_code("/groups/303", bob) == "200"

with subtest("group data routes resolve the authorized group library"):
    expected_group_versions = {
        "GRPBKK22": 17,
        "GRPTRS22": 17,
    }
    assert (
        get_json("/groups/303/items?format=versions&since=0", bob)
        == expected_group_versions
    )
    assert (
        get_json("/groups/303/items?format=versions&since=0", alice)
        == expected_group_versions
    )
    assert (
        get_json("/groups/303/items?format=versions&since=0", recovery)
        == expected_group_versions
    )
    group_items = get_json(
        "/groups/303/items?itemKey=GRPBKK22,GRPTRS22&format=json", bob
    )
    assert {entry["key"] for entry in group_items} == {"GRPBKK22", "GRPTRS22"}
    assert next(
        entry for entry in group_items if entry["key"] == "GRPBKK22"
    )["data"]["title"] == "Group fixture item"
    assert get_json("/groups/303/settings", bob)["groupSetting"]["value"] == "shared"
    assert get_json("/groups/303/collections?format=versions", bob) == {}
    assert get_json("/groups/303/searches?format=versions", bob) == {}
    assert get_json("/groups/303/fulltext?format=versions", bob) == {}
    assert get_json("/groups/303/tags", bob) == []
    deleted = get_json("/groups/303/deleted?since=0", bob)
    assert all(not values for values in deleted.values())
    assert http_code("/groups/303/items?format=versions", bob_full) == "403"
    assert http_code("/groups/999/items?format=versions", alice) == "404"

with subtest("group mutations enforce key grants, role policy and file policy"):
    assert (
        http_code(
            "/groups/303/items",
            bob,
            method="POST",
            body='[{"key":"DENIED22","itemType":"book"}]',
            version=17,
        )
        == "403"
    )
    psql(
        f"""insert into api_keys (id, user_id, name, token_hash)
            values
            (1008, 202, 'Bob explicit group writer',
             decode('{sha256_hex(bob_group_rw)}', 'hex'))"""
    )
    psql(
        """insert into api_key_user_permissions
           (api_key_id, library, notes, write, files)
           values (1008, false, false, false, false)"""
    )
    psql(
        """insert into api_key_group_permissions
           (api_key_id, user_id, group_id, library, write)
           values (1008, 202, 303, true, true)"""
    )
    group_snapshot = body_admission_snapshot()
    group_file_status, _ = attachment_route_receipt(
        "/groups/303/items/GRPBKK22/file", bob_group_rw
    )
    assert group_file_status == 404
    group_put_status, group_put_headers = attachment_route_receipt(
        "/groups/303/items/GRPBKK22/file", bob_group_rw, "PUT"
    )
    assert group_put_status == 403
    assert not any(
        line.lower().startswith("location:") for line in group_put_headers
    )
    assert body_admission_snapshot() == group_snapshot
    print(
        "ATTACHMENT-ROUTE group-grant=allowed personal-files=false "
        "group-write-policy=denied storage-and-version-snapshot=unchanged"
    )
    assert (
        http_code(
            "/groups/303/items",
            bob_group_rw,
            method="POST",
            body='[{"key":"EXPRW222","itemType":"book","title":"explicit write"}]',
            version=17,
        )
        == "200"
    )
    psql(
        """insert into object (library_id, kind, key, version, data)
           values
           (33, 'item', 'XLDATT22', 18,
            '{"key":"XLDATT22","version":18,"itemType":"attachment",
              "linkMode":"imported_file","filename":"existing.pdf"}')"""
    )
    assert (
        http_code(
            "/groups/303/items",
            bob_group_rw,
            method="POST",
            body=(
                '[{"key":"GRPATT22","itemType":"attachment",'
                '"linkMode":"imported_file","filename":"private.pdf"}]'
            ),
            version=18,
        )
        == "403"
    )
    assert (
        http_code(
            "/groups/303/items",
            bob_group_rw,
            method="POST",
            body=(
                '[{"key":"RLLBCK22","itemType":"book"},'
                '{"key":"XLDATT22","itemType":"book"}]'
            ),
            version=18,
        )
        == "403"
    )
    assert (
        get_json("/groups/303/items?itemKey=RLLBCK22&format=json", bob_group_rw)
        == []
    )
    assert (
        http_code(
            "/groups/303/items?itemKey=XLDATT22",
            bob_group_rw,
            method="DELETE",
            version=18,
        )
        == "403"
    )
    assert (
        get_json("/groups/303/items?itemKey=XLDATT22&format=json", bob_group_rw)[0][
            "data"
        ]["itemType"]
        == "attachment"
    )
    assert psql("select version from library where id = 33") == "18"
    assert (
        http_code(
            "/groups/303/settings",
            bob_group_rw,
            method="POST",
            body='{"attachmentRenameTemplate":{"value":"{{ title }}"}}',
            version=18,
        )
        == "403"
    )
    assert (
        http_code(
            "/groups/303/settings",
            bob_group_rw,
            method="POST",
            body='{"memberSetting":{"value":"allowed"}}',
            version=18,
        )
        == "204"
    )
    assert (
        http_code(
            "/groups/303/settings",
            alice,
            method="POST",
            body='{"attachmentRenameTemplate":{"value":"{{ title }}"}}',
            version=19,
        )
        == "204"
    )
    assert (
        http_code(
            "/groups/303/settings?settingKey=attachmentRenameTemplate",
            bob_group_rw,
            method="DELETE",
            version=20,
        )
        == "403"
    )

    psql(
        """insert into api_key_all_groups_permissions (api_key_id, library, write)
           values (1005, true, true)"""
    )
    assert (
        http_code(
            "/groups/303/items",
            bob_full,
            method="POST",
            body='[{"key":"ALLRW222","itemType":"book"}]',
            version=20,
        )
        == "403"
    )
    psql("update groups set library_editing = 'members' where id = 303")
    assert (
        http_code(
            "/groups/303/items",
            bob_full,
            method="POST",
            body='[{"key":"ALLRW222","itemType":"book"}]',
            version=20,
        )
        == "200"
    )
    psql("update groups set library_editing = 'admins' where id = 303")
    psql("delete from api_key_all_groups_permissions where api_key_id = 1005")

with subtest("group files revalidate policy and grants across upload steps"):
    file_form = (
        "md5=5d41402abc4b2a76b9719d911017c592"
        "&filename=group.pdf&filesize=5&mtime=1700000000000"
    )
    psql(
        """insert into object (library_id, kind, key, version, data)
           values
           (33, 'item', 'STALAT22', 21,
            '{"key":"STALAT22","version":21,"itemType":"attachment",
              "linkMode":"imported_file","filename":"stale.pdf"}')"""
    )
    stale_item = machine.succeed(
        f"curl -sf -X POST {base}/groups/303/items/STALAT22/file {api_headers} "
        f"-H 'Zotero-API-Key: {alice}' -H 'If-None-Match: *' "
        f"-d '{file_form}' | jq -r .uploadKey"
    ).strip()
    assert http_code(f"/uploads/{stale_item}", method="POST", body="hello") == "201"
    psql(
        """update object
           set data = data || '{"itemType":"book"}'
           where library_id = 33 and kind = 'item' and key = 'STALAT22'"""
    )
    assert (
        machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
            f"{base}/groups/303/items/STALAT22/file {api_headers} "
            f"-H 'Zotero-API-Key: {alice}' -d 'upload={stale_item}'"
        ).strip()
        == "409"
    )
    assert (
        psql(
            """select count(*) from file
               where library_id = 33 and item_key = 'STALAT22'"""
        )
        == "0"
    )
    assert (
        psql(
            """select count(*) from pending_uploads
               where library_id = 33 and item_key = 'STALAT22'"""
        )
        == "0"
    )
    psql(
        """delete from object
           where library_id = 33 and kind = 'item' and key = 'STALAT22'"""
    )
    assert (
        machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
            f"{base}/groups/303/items/XLDATT22/file {api_headers} "
            f"-H 'Zotero-API-Key: {bob_group_rw}' -H 'If-None-Match: *' "
            f"-d '{file_form}'"
        ).strip()
        == "403"
    )

    psql("update groups set file_editing = 'members' where id = 303")
    revoked_before_put = machine.succeed(
        f"curl -sf -X POST {base}/groups/303/items/XLDATT22/file {api_headers} "
        f"-H 'Zotero-API-Key: {bob_group_rw}' -H 'If-None-Match: *' "
        f"-d '{file_form}' | jq -r .uploadKey"
    ).strip()
    psql("delete from api_key_group_permissions where api_key_id = 1008")
    assert (
        http_code(f"/uploads/{revoked_before_put}", method="POST", body="hello")
        == "403"
    )
    psql(
        """insert into api_key_group_permissions
           (api_key_id, user_id, group_id, library, write)
           values (1008, 202, 303, true, true)"""
    )

    revoked_before_register = machine.succeed(
        f"curl -sf -X POST {base}/groups/303/items/XLDATT22/file {api_headers} "
        f"-H 'Zotero-API-Key: {bob_group_rw}' -H 'If-None-Match: *' "
        f"-d '{file_form}' | jq -r .uploadKey"
    ).strip()
    assert (
        http_code(f"/uploads/{revoked_before_register}", method="POST", body="hello")
        == "201"
    )
    restart_xotero()
    psql("delete from api_key_group_permissions where api_key_id = 1008")
    assert (
        machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
            f"{base}/groups/303/items/XLDATT22/file {api_headers} "
            f"-H 'Zotero-API-Key: {bob_group_rw}' "
            f"-d 'upload={revoked_before_register}'"
        ).strip()
        == "403"
    )
    assert (
        psql(
            """select count(*) from file
               where library_id = 33 and item_key = 'XLDATT22'"""
        )
        == "0"
    )
    psql(
        """insert into api_key_group_permissions
           (api_key_id, user_id, group_id, library, write)
           values (1008, 202, 303, true, true)"""
    )
    psql("update groups set file_editing = 'admins' where id = 303")

    owner_upload = machine.succeed(
        f"curl -sf -X POST {base}/groups/303/items/XLDATT22/file {api_headers} "
        f"-H 'Zotero-API-Key: {alice}' -H 'If-None-Match: *' "
        f"-d '{file_form}' | jq -r .uploadKey"
    ).strip()
    assert http_code(f"/uploads/{owner_upload}", method="POST", body="hello") == "201"
    assert (
        machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
            f"{base}/groups/303/items/XLDATT22/file {api_headers} "
            f"-H 'Zotero-API-Key: {alice}' -d 'upload={owner_upload}'"
        ).strip()
        == "204"
    )
    assert http_code("/groups/303/items/XLDATT22/file", bob) == "302"
    assert psql(
        """select blob_key from file
           where library_id = 33 and item_key = 'XLDATT22'"""
    ).startswith("libraries/33/uploads/")

    group_version = int(psql("select version from library where id = 33"))
    assert (
        http_code(
            "/groups/303/items",
            alice,
            method="POST",
            body='[{"key":"XLDATT22","itemType":"book"}]',
            version=group_version,
        )
        == "200"
    )
    assert (
        psql(
            """select count(*) from file
               where library_id = 33 and item_key = 'XLDATT22'"""
        )
        == "0"
    )
    assert http_code("/groups/303/items/XLDATT22/file", bob) == "404"

    group_version = int(psql("select version from library where id = 33"))
    assert (
        http_code(
            "/groups/303/items",
            alice,
            method="POST",
            body='[{"key":"XLDATT22","itemType":"attachment"}]',
            version=group_version,
        )
        == "200"
    )
    assert http_code("/groups/303/items/XLDATT22/file", bob) == "404"
    replacement_upload = machine.succeed(
        f"curl -sf -X POST {base}/groups/303/items/XLDATT22/file {api_headers} "
        f"-H 'Zotero-API-Key: {alice}' -H 'If-None-Match: *' "
        f"-d '{file_form}' | jq -r .uploadKey"
    ).strip()
    assert (
        http_code(f"/uploads/{replacement_upload}", method="POST", body="hello")
        == "201"
    )
    assert (
        machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
            f"{base}/groups/303/items/XLDATT22/file {api_headers} "
            f"-H 'Zotero-API-Key: {alice}' -d 'upload={replacement_upload}'"
        ).strip()
        == "204"
    )

    group_version = int(psql("select version from library where id = 33"))
    assert (
        http_code(
            "/groups/303/items?itemKey=XLDATT22",
            alice,
            method="DELETE",
            version=group_version,
        )
        == "204"
    )
    assert (
        psql(
            """select count(*) from file
               where library_id = 33 and item_key = 'XLDATT22'"""
        )
        == "0"
    )
    assert http_code("/groups/303/items/XLDATT22/file", bob) == "404"
    psql("delete from api_keys where id = 1008")

with subtest("static recovery key remains bound to the bootstrap user"):
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {recovery}' {base}/keys/current |
        jq -e '. == {{
          "key":"{recovery}",
          "userID":101,
          "username":"alice",
          "displayName":"Alice",
          "access":{{
            "user":{{
              "library":true,"files":true,"notes":true,"write":true
            }},
            "groups":{{"all":{{"library":true,"write":true}}}}
          }}
        }}'"""
    )

with subtest("OIDC approval requires the exact bootstrap identity"):
    rejected_session = create_login_session()
    rejected_hash = sha256_hex(rejected_session)
    alice_keys_before_rejection = psql(
        "select count(*) from api_keys where user_id = 101"
    )
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
        (
            f"-H 'X-Xotero-OIDC-Issuer: {oidc_issuer}/' "
            f"-H 'X-Xotero-OIDC-Subject: {oidc_subject}'"
        ),
    )
    for identity_headers in rejected_identities:
        assert approve_login_session(rejected_session, identity_headers) == "403"

    rejected_result = poll_login_session(rejected_session)
    assert rejected_result["status"] == "pending"
    assert "apiKey" not in rejected_result or rejected_result["apiKey"] is None
    assert (
        psql("select count(*) from api_keys where user_id = 101")
        == alice_keys_before_rejection
    )
    assert (
        psql(
            f"""select status = 'pending' and api_key_id is null
                from login_sessions
                where token_hash = decode('{rejected_hash}', 'hex')"""
        )
        == "t"
    )

with subtest("browser login mints distinct hashed full-access keys for Alice"):
    initial_alice_keys = int(psql("select count(*) from api_keys where user_id = 101"))
    first_session = create_login_session()
    second_session = create_login_session()
    assert first_session != second_session

    for session in (first_session, second_session):
        session_hash = sha256_hex(session)
        assert (
            psql(
                f"""select status = 'pending'
                           and api_key_id is null
                           and encode(token_hash, 'hex') = '{session_hash}'
                    from login_sessions
                    where token_hash = decode('{session_hash}', 'hex')"""
            )
            == "t"
        )
        assert (
            psql(
                f"""select position('{session}' in row_to_json(login_sessions)::text) = 0
                    from login_sessions
                    where token_hash = decode('{session_hash}', 'hex')"""
            )
            == "t"
        )

    assert approve_login_session(first_session) == "200"
    first_result = poll_login_session(first_session)
    assert first_result["status"] == "completed"
    assert first_result["userID"] == 101 and first_result["username"] == "alice"
    first_key = first_result["apiKey"]
    assert len(first_key) == 24
    assert set(first_key) <= set("23456789ABCDEFGHIJKLMNPQRSTUVWXYZ"), first_key
    assert first_key != recovery
    assert int(psql("select count(*) from api_keys where user_id = 101")) == initial_alice_keys + 1
    first_api_key_id = psql(
        f"""select api_key_id from login_sessions
            where token_hash = decode('{sha256_hex(first_session)}', 'hex')"""
    )
    assert first_api_key_id

    # Approval is a one-way state transition. A replay cannot mint another key.
    assert approve_login_session(first_session) == "409"
    assert int(psql("select count(*) from api_keys where user_id = 101")) == initial_alice_keys + 1
    assert (
        psql(
            f"""select api_key_id from login_sessions
                where token_hash = decode('{sha256_hex(first_session)}', 'hex')"""
        )
        == first_api_key_id
    )

    assert approve_login_session(second_session) == "200"
    second_result = poll_login_session(second_session)
    assert second_result["status"] == "completed"
    assert second_result["userID"] == 101 and second_result["username"] == "alice"
    second_key = second_result["apiKey"]
    assert len(second_key) == 24
    assert set(second_key) <= set("23456789ABCDEFGHIJKLMNPQRSTUVWXYZ"), second_key
    assert second_key not in (first_key, recovery)
    assert int(psql("select count(*) from api_keys where user_id = 101")) == initial_alice_keys + 2

    for session, key in ((first_session, first_key), (second_session, second_key)):
        session_hash = sha256_hex(session)
        key_hash = sha256_hex(key)
        assert (
            psql(
                f"""select ls.status = 'completed'
                           and ls.user_id = 101
                           and ls.api_key_id = k.id
                           and k.user_id = 101
                           and encode(ls.token_hash, 'hex') = '{session_hash}'
                           and encode(k.token_hash, 'hex') = '{key_hash}'
                           and octet_length(ls.token_hash) = 32
                           and octet_length(k.token_hash) = 32
                           and p.library and p.notes and p.write and p.files
                           and gp.library and gp.write
                    from login_sessions ls
                    join api_keys k on k.id = ls.api_key_id
                    join api_key_user_permissions p on p.api_key_id = k.id
                    join api_key_all_groups_permissions gp on gp.api_key_id = k.id
                    where ls.token_hash = decode('{session_hash}', 'hex')"""
            )
            == "t"
        )
        assert (
            psql(
                f"""select position('{session}' in row_to_json(ls)::text) = 0
                           and position('{key}' in row_to_json(ls)::text) = 0
                           and position('{session}' in row_to_json(k)::text) = 0
                           and position('{key}' in row_to_json(k)::text) = 0
                    from login_sessions ls
                    join api_keys k on k.id = ls.api_key_id
                    where ls.token_hash = decode('{session_hash}', 'hex')"""
            )
            == "t"
        )
        machine.succeed(
            f"""curl -sf {api_headers} -H 'Zotero-API-Key: {key}' {base}/keys/current |
            jq -e '.userID == 101
              and .username == "alice"
              and .displayName == "Alice"
              and .access.user == {{
                "library":true,"files":true,"notes":true,"write":true
              }}
              and .access.groups == {{
                "all":{{"library":true,"write":true}}
              }}'"""
        )

    # Recovery remains a configured credential, never a login-minted DB row.
    assert (
        psql(
            f"""select count(*) from api_keys
                where token_hash = decode('{sha256_hex(recovery)}', 'hex')"""
        )
        == "0"
    )
    assert http_code("/keys/current", recovery) == "200"

with subtest("invalid recovery configuration fails before database or listener"):
    config_script = r"""
import os
import pathlib
import shutil
import subprocess
import tempfile

binary = shutil.which("xotero")
assert binary is not None
with tempfile.TemporaryDirectory(prefix="xotero-config-") as directory:
    root = pathlib.Path(directory)
    contents = {
        "rw": b"RECOVERY_RW_MARKER_417\n",
        "ro": b"RECOVERY_RO_MARKER_628\n",
        "same": b"RECOVERY_RW_MARKER_417\n",
        "empty": b"",
        "blank": b" \t\r\n",
        "multiline": b"alpha\nbeta\n",
        "bad-utf8": b"\xff",
        "kdf": b"KDF_SECRET_MARKER_32_BYTES_12345678\r\n",
    }
    for name, content in contents.items():
        (root / name).write_bytes(content)
    rw = str(root / "rw")
    ro = str(root / "ro")
    valid = {
        "XOTERO_LOGIN_KDF_KEY_FILE": str(root / "kdf"),
        "XOTERO_DATABASE_URL": "postgres://localhost:1/not-reached",
        "XOTERO_BIND": "127.0.0.1:18194",
    }
    manifests = [
        "", ",", f",rw:{rw}", f"rw:{rw},", f"rw:{rw},,ro:{ro}",
        "rw", "rw:", f":{rw}", f"admin:{rw}", f"RW:{rw}", f"read:{rw}",
        "MANIFEST_SECRET_MARKER_83",
        f"rw:{rw},ro:{root / 'same'}", f"ro:{root / 'same'},rw:{rw}",
    ] + [f"rw:{root / name}" for name in (
        "empty", "blank", "multiline", "bad-utf8", "missing"
    )]
    cases = [("manifest-" + str(index), {"XOTERO_KEYS": value})
             for index, value in enumerate(manifests)]
    # Removed single-key sources fail even when their value would be valid.
    cases += [("removed-file", {"XOTERO_API_KEY_FILE": rw}),
              ("removed-token", {"XOTERO_API_KEY": "LOWER_SOURCE_SECRET_MARKER_59"}),
              ("removed-beside-manifest", {"XOTERO_KEYS": f"ro:{ro}",
                                           "XOTERO_API_KEY": "LOWER_SOURCE_SECRET_MARKER_59"})]
    cases += [("unicode-XOTERO_KEYS", {"XOTERO_KEYS": "\udcff"})]
    secrets = list(contents.values()) + [
        b"LOWER_SOURCE_SECRET_MARKER_59", b"MANIFEST_SECRET_MARKER_83",
    ]
    for label, selected in cases:
        result = subprocess.run([binary], env=valid | selected,
                                capture_output=True, timeout=10)
        output = result.stdout + result.stderr
        assert result.returncode != 0, label
        assert b"connect to database" not in output, label
        assert b"xotero listening" not in output, label
        assert all(not secret.strip() or secret.strip() not in output
                   for secret in secrets), label + ": secret leaked"
        print("config-rejection " + label + " exit=" + str(result.returncode))
    for name in ("missing", "empty", "short"):
        (root / "short").write_bytes(b"KDF_SHORT_SECRET_31_BYTES_1234567"[:31])
        env = dict(valid)
        if name == "missing":
            del env["XOTERO_LOGIN_KDF_KEY_FILE"]
        else:
            env["XOTERO_LOGIN_KDF_KEY_FILE"] = str(root / name)
        result = subprocess.run([binary], env=env, capture_output=True, timeout=10)
        assert result.returncode != 0 and b"connect to database" not in result.stderr
        print("keyless-kdf-rejection " + name + " exit=" + str(result.returncode))
"""
    machine.succeed(f"python3 -c {shlex.quote(config_script)}")

with subtest("mapped non-bootstrap OIDC identity mints a key for Bob"):
    initial_bob_keys = int(psql("select count(*) from api_keys where user_id = 202"))
    bob_session = create_login_session()
    assert approve_login_session(bob_session, oidc_bob) == "200"
    bob_result = poll_login_session(bob_session)
    assert bob_result["status"] == "completed"
    assert bob_result["userID"] == 202 and bob_result["username"] == "bob"
    bob_login_key = bob_result["apiKey"]
    assert len(bob_login_key) == 24
    assert set(bob_login_key) <= set("23456789ABCDEFGHIJKLMNPQRSTUVWXYZ")
    assert int(psql("select count(*) from api_keys where user_id = 202")) == initial_bob_keys + 1
    assert (
        psql(
            f"""select ls.status = 'completed'
                       and ls.user_id = 202
                       and ls.api_key_id = k.id
                       and k.user_id = 202
                       and encode(k.token_hash, 'hex') = '{sha256_hex(bob_login_key)}'
                       and p.library and p.notes and p.write and p.files
                       and gp.library and gp.write
                from login_sessions ls
                join api_keys k on k.id = ls.api_key_id
                join api_key_user_permissions p on p.api_key_id = k.id
                join api_key_all_groups_permissions gp on gp.api_key_id = k.id
                where ls.token_hash = decode('{sha256_hex(bob_session)}', 'hex')"""
        )
        == "t"
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob_login_key}' {base}/keys/current |
        jq -e '. == {{
          "key":"{bob_login_key}",
          "userID":202,
          "username":"bob",
          "displayName":"Bob",
          "access":{{
            "user":{{
              "library":true,"files":true,"notes":true,"write":true
            }},
            "groups":{{"all":{{"library":true,"write":true}}}}
          }}
        }}'"""
    )

with subtest("expired login sessions are terminal without minting a key"):
    expired_session = create_login_session()
    expired_hash = sha256_hex(expired_session)
    alice_keys_before_expiry = psql("select count(*) from api_keys where user_id = 101")
    psql(
        f"""update login_sessions
            set created_at = now() - interval '1 hour',
                expires_at = now() - interval '1 second'
            where token_hash = decode('{expired_hash}', 'hex')
              and status = 'pending'"""
    )
    assert (
        psql(
            f"""select expires_at < now() and status = 'pending' and api_key_id is null
                from login_sessions
                where token_hash = decode('{expired_hash}', 'hex')"""
        )
        == "t"
    )
    assert http_code(f"/keys/sessions/{expired_session}") == "410"
    assert http_code(f"/keys/sessions/{expired_session}", method="DELETE") == "409"
    assert psql("select count(*) from api_keys where user_id = 101") == alice_keys_before_expiry

with subtest("disabled bootstrap user cannot approve a login session"):
    disabled_session = create_login_session()
    disabled_hash = sha256_hex(disabled_session)
    alice_keys_before_disable = psql("select count(*) from api_keys where user_id = 101")
    psql("update users set disabled_at = now() where id = 101")
    assert approve_login_session(disabled_session) == "403"
    assert psql("select count(*) from api_keys where user_id = 101") == alice_keys_before_disable
    assert (
        psql(
            f"""select status = 'pending' and api_key_id is null
                from login_sessions
                where token_hash = decode('{disabled_hash}', 'hex')"""
        )
        == "t"
    )
    psql("update users set disabled_at = null where id = 101")
    assert http_code("/keys/current", recovery) == "200"

with subtest("unknown and revoked keys fail closed"):
    assert http_code("/keys/current", "unknown-token") == "403"
    assert http_code("/keys/current", revoked) == "403"

with subtest("authorization denies incomplete bodies without continuation"):
    before = body_admission_snapshot()
    for token in (None, "unknown-token", revoked):
        assert incomplete_body_status("/users/202/items", token) == "403"
    assert incomplete_body_status("/users/202/items", None, chunked=True) == "403"
    assert incomplete_body_status("/users/202/items", alice) == "403"
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert incomplete_body_status("/users/202/items", bob_ro, method) == "403"
    assert incomplete_body_status("/uploads/unknown-capability") == "400"
    for path in ("/uploadsuffix/token", "/uploads/token/extra", "/keys/sessionssuffix"):
        assert incomplete_body_status(path) == "403"
    assert body_admission_snapshot() == before

with subtest("disabled users fail closed for DB and recovery keys"):
    psql("update users set disabled_at = now() where id = 202")
    before = body_admission_snapshot()
    assert incomplete_body_status("/users/202/items", bob_full) == "403"
    assert body_admission_snapshot() == before
    assert http_code("/keys/current", bob_ro) == "403"
    psql("update users set disabled_at = null where id = 202")
    psql("update users set disabled_at = now() where id = 101")
    before = body_admission_snapshot()
    assert incomplete_body_status("/users/101/items", recovery) == "403"
    assert body_admission_snapshot() == before
    assert http_code("/keys/current", recovery) == "403"
    psql("update users set disabled_at = null where id = 101")

with subtest("file permissions deny incomplete body before decoding"):
    psql("update api_key_user_permissions set files = false where api_key_id = 1005")
    try:
        before = body_admission_snapshot()
        assert incomplete_body_status("/users/202/items/PRIVATCH/file", bob_full) == "403"
        assert body_admission_snapshot() == before
    finally:
        psql("update api_key_user_permissions set files = true where api_key_id = 1005")

with subtest("DB permissions allow full keys and gate read-only mutations"):
    assert (
        http_code(
            "/users/101/items",
            alice,
            method="POST",
            body='[{"key":"AUTHW222","itemType":"book"}]',
            version=7,
        )
        == "200"
    )
    current = psql("select version from library where id = 22")
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob_ro}' \
        '{base}/users/202/items?itemKey=LEGACY22&format=json' |
        jq -e 'length == 1 and .[0].data.title == "Bob private item"'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {alice}' \
        '{base}/users/101/items?itemKey=LEGACY22&format=json' |
        jq -e 'length == 1 and .[0].data.title == "preserved"'"""
    )
    assert http_code("/users/202/items?format=versions&since=0", alice) == "403"
    assert http_code("/users/101/items?format=versions&since=0", bob_ro) == "403"
    assert http_code("/users/202/items?format=versions&since=0", bob) == "200"
    assert (
        http_code(
            "/users/202/items",
            bob_ro,
            method="POST",
            body='[{"key":"RDNLY222","itemType":"book"}]',
            version=current,
        )
        == "403"
    )

with subtest("notes permission filters notes without hiding library or annotations"):
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob_full}' \
        '{base}/users/202/items?format=versions&since=0' |
        jq -e '. == {{
          "LEGACY22":3,
          "PRIVANN2":3,
          "PRIVATCH":3,
          "PRIVNTE2":3,
          "TRSHANN2":3,
          "TRSHNTE2":3
        }}'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items?format=versions&since=0' |
        jq -e '. == {{
          "LEGACY22":3,
          "PRIVANN2":3,
          "PRIVATCH":3,
          "TRSHANN2":3
        }}'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items?itemKey=LEGACY22,PRIVNTE2,PRIVATCH,PRIVANN2' |
        jq -e '
          map(.key) | sort
          == ["LEGACY22","PRIVANN2","PRIVATCH"]
        '"""
    )
    machine.succeed(
        f"""curl -sf -D /tmp/note-list-headers {api_headers} \
        -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items?limit=2' |
        jq -e '
          length == 2
          and all(.[]; .data.itemType != "note")
        '"""
    )
    machine.succeed(
        "grep -i '^total-results: 3' /tmp/note-list-headers"
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items?format=keys' |
        sort |
        diff -u - <(printf '%s\\n' LEGACY22 PRIVANN2 PRIVATCH | sort)"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items/top?format=versions&since=0' |
        jq -e '. == {{"LEGACY22":3,"PRIVATCH":3}}'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items/top' |
        jq -e '
          map(.key) | sort
          == ["LEGACY22","PRIVATCH"]
        '"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items/top?format=keys' |
        sort |
        diff -u - <(printf '%s\\n' LEGACY22 PRIVATCH | sort)"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items/trash' |
        jq -e 'map(.key) == ["TRSHANN2"]'"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/items/trash?format=keys' |
        grep -Fx TRSHANN2"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/collections/COLL2222/items' |
        jq -e '
          map(.key) | sort
          == ["LEGACY22","PRIVATCH"]
        '"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/collections/COLL2222/items?format=keys' |
        sort |
        diff -u - <(printf '%s\\n' LEGACY22 PRIVATCH | sort)"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/collections/COLL2222/items/top' |
        jq -e '
          map(.key) | sort
          == ["LEGACY22","PRIVATCH"]
        '"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/collections/COLL2222/items/top?format=keys' |
        sort |
        diff -u - <(printf '%s\\n' LEGACY22 PRIVATCH | sort)"""
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob}' \
        '{base}/users/202/tags' |
        jq -e '. == [
          {{"tag":"annotation-only","numItems":1}},
          {{"tag":"book-only","numItems":1}},
          {{"tag":"note-only","numItems":1}},
          {{"tag":"shared-tag","numItems":2}}
        ]'"""
    )

with subtest("no-notes writers retain upstream batch mutation behavior"):
    before = psql("select version from library where id = 22")
    machine.succeed(
        f"""curl -sf -X POST {api_headers} \
        -H 'Zotero-API-Key: {bob_notes_write}' \
        -H 'Content-Type: application/json' \
        -H 'If-Unmodified-Since-Version: {before}' \
        --data '[
          {{"key":"WRITNTE2","itemType":"note","note":"Writable note"}},
          {{"key":"WRITANN2","itemType":"annotation",
            "parentItem":"PRIVATCH","annotationType":"highlight",
            "annotationText":"Writable annotation"}}
        ]' \
        '{base}/users/202/items' |
        jq -e '
          .successful."0".data.note == "Writable note"
          and .successful."1".data.annotationText == "Writable annotation"
        '"""
    )
    after_create = psql("select version from library where id = 22")
    machine.succeed(
        f"""curl -sf -X PATCH {api_headers} \
        -H 'Zotero-API-Key: {bob_notes_write}' \
        -H 'Content-Type: application/json' \
        -H 'If-Unmodified-Since-Version: {after_create}' \
        --data '[{{"key":"WRITNTE2","note":"Updated hidden note"}}]' \
        '{base}/users/202/items' |
        jq -e '.successful."0".data.note == "Updated hidden note"'"""
    )
    after_patch = psql("select version from library where id = 22")
    assert (
        http_code(
            "/users/202/items?itemKey=WRITNTE2,WRITANN2",
            bob_notes_write,
            method="DELETE",
            version=after_patch,
        )
        == "204"
    )
    machine.succeed(
        f"""curl -sf {api_headers} -H 'Zotero-API-Key: {bob_notes_write}' \
        '{base}/users/202/deleted?since={before}' |
        jq -e '
          (.items | index("WRITNTE2"))
          and (.items | index("WRITANN2"))
        '"""
    )

with subtest("same attachment key stays isolated across personal libraries"):
    psql(
        """insert into object (library_id, kind, key, version, data)
           select id, 'item', 'SHARED22', version,
                  jsonb_build_object(
                    'key', 'SHARED22', 'version', version,
                    'itemType', 'attachment', 'linkMode', 'imported_file',
                    'filename', 'shared.pdf')
           from library where id in (1, 22)"""
    )
    alice_token = machine.succeed(
        f"curl -sf -X POST {base}/users/101/items/SHARED22/file {api_headers} "
        f"-H 'Zotero-API-Key: {alice}' -H 'If-None-Match: *' "
        "-d 'md5=5d41402abc4b2a76b9719d911017c592&filename=alice.pdf&filesize=5&mtime=1' "
        "| jq -r .uploadKey"
    ).strip()
    machine.succeed(f"printf hello | curl -sf -X POST {base}/uploads/{alice_token} --data-binary @-")
    machine.succeed(
        f"curl -sf -X POST {base}/users/101/items/SHARED22/file {api_headers} "
        f"-H 'Zotero-API-Key: {alice}' -H 'If-None-Match: *' -d 'upload={alice_token}'"
    )
    alice_location = machine.succeed(
        f"curl -sf -D /tmp/alice-file -o /dev/null {base}/users/101/items/SHARED22/file "
        f"{api_headers} -H 'Zotero-API-Key: {alice}' "
        "&& grep -i '^location:' /tmp/alice-file | tr -d '\\r' | awk '{print $2}'"
    ).strip()

    bob_token = machine.succeed(
        f"curl -sf -X POST {base}/users/202/items/SHARED22/file {api_headers} "
        f"-H 'Zotero-API-Key: {bob_full}' -H 'If-None-Match: *' "
        "-d 'md5=7d793037a0760186574b0282f2f435e7&filename=bob.pdf&filesize=5&mtime=2' "
        "| jq -r .uploadKey"
    ).strip()
    machine.succeed(f"printf world | curl -sf -X POST {base}/uploads/{bob_token} --data-binary @-")
    machine.succeed(
        f"curl -sf -X POST {base}/users/202/items/SHARED22/file {api_headers} "
        f"-H 'Zotero-API-Key: {bob_full}' -H 'If-None-Match: *' -d 'upload={bob_token}'"
    )
    bob_blob_key = psql(
        "select blob_key from file where library_id = 22 and item_key = 'SHARED22'"
    )
    assert bob_blob_key.startswith("libraries/22/uploads/"), bob_blob_key
    assert bob_blob_key != psql(
        "select blob_key from file where library_id = 1 and item_key = 'LEGACY22'"
    )
    bob_location = machine.succeed(
        f"curl -sf -D /tmp/bob-file -o /dev/null {base}/users/202/items/SHARED22/file "
        f"{api_headers} -H 'Zotero-API-Key: {bob_full}' "
        "&& grep -i '^location:' /tmp/bob-file | tr -d '\\r' | awk '{print $2}'"
    ).strip()
    assert machine.succeed(f"curl -sf '{alice_location}'").strip() == "hello"
    assert machine.succeed(f"curl -sf '{bob_location}'").strip() == "world"

with subtest("recovery upload cannot cross bootstrap-user reconfiguration"):
    recovery_pending = machine.succeed(
        f"curl -sf -X POST {base}/users/101/items/SHARED22/file {api_headers} "
        f"-H 'Zotero-API-Key: {recovery}' "
        "-H 'If-Match: 5d41402abc4b2a76b9719d911017c592' "
        "-d 'md5=7d793037a0760186574b0282f2f435e7&filename=r.pdf&filesize=5&mtime=4' "
        "| jq -r .uploadKey"
    ).strip()
    psql(
        """update pending_uploads set bootstrap_user_id = 202
           where library_id = 1 and item_key = 'SHARED22'"""
    )
    restart_xotero()
    before = body_admission_snapshot()
    assert incomplete_body_status(f"/uploads/{recovery_pending}") == "403"
    assert body_admission_snapshot() == before
    assert http_code(f"/uploads/{recovery_pending}", method="POST", body="world") == "403"
    psql(
        """update pending_uploads
           set created_at = now() - interval '2 hours',
               expires_at = now() - interval '1 hour'
           where library_id = 1 and item_key = 'SHARED22'"""
    )

with subtest("revoked key cannot finish an authorized upload"):
    psql(
        """insert into object (library_id, kind, key, version, data)
           select id, 'item', 'REVKE222', version,
                  jsonb_build_object(
                    'key', 'REVKE222', 'version', version,
                    'itemType', 'attachment', 'linkMode', 'imported_file',
                    'filename', 'revoked.pdf')
           from library where id = 22"""
    )
    pending_token = machine.succeed(
        f"curl -sf -X POST {base}/users/202/items/REVKE222/file {api_headers} "
        f"-H 'Zotero-API-Key: {bob_full}' -H 'If-None-Match: *' "
        "-d 'md5=7d793037a0760186574b0282f2f435e7&filename=r.pdf&filesize=5&mtime=3' "
        "| jq -r .uploadKey"
    ).strip()
    restart_xotero()
    psql("update api_keys set revoked_at = now() where id = 1005")
    before = body_admission_snapshot()
    assert incomplete_body_status(f"/uploads/{pending_token}") == "403"
    assert body_admission_snapshot() == before
    assert http_code(f"/uploads/{pending_token}", method="POST", body="world") == "403"

with subtest("revocation takes effect on the next request"):
    assert http_code("/keys/current", alice) == "200"
    psql("update api_keys set revoked_at = now() where id = 1001")
    assert http_code("/keys/current", alice) == "403"

with subtest("gzip admission enforces exact public and authenticated boundaries"):
    before = body_admission_snapshot()
    assert gzip_body_status("/login", 1024 * 1024) == "403"
    assert gzip_body_status("/login", 1024 * 1024 + 1) == "413"
    for corruption in ("truncated", "crc"):
        assert gzip_body_status("/login", 1024 * 1024, corruption=corruption) == "400"
        assert gzip_body_status("/users/101/items", 64, recovery, corruption) == "400"
    assert gzip_body_status("/users/101/items", 256 * 1024 * 1024 + 1, recovery) == "413"
    assert body_admission_snapshot() == before
    # A valid authorized JSON body padded to the actual API maximum is accepted.
    boundary_before = json.loads(body_admission_snapshot())
    version_before = int(psql("select version from library where id = 1"))
    assert psql("select count(*) from object where library_id = 1 and key = 'BNDRY222'") == "0"
    assert gzip_body_status(
        "/users/101/items", 256 * 1024 * 1024, recovery, version=version_before
    ) == "200"
    version_after = int(psql("select version from library where id = 1"))
    boundary_after = json.loads(body_admission_snapshot())
    assert version_after == version_before + 1
    assert boundary_after[2] == boundary_before[2] + 1
    assert boundary_after[1] == boundary_before[1]
    assert boundary_after[3] == boundary_before[3]
    print(f"gzip-boundary-version before={version_before} after={version_after}")

with subtest("database stores only fixed-length key digests"):
    assert psql("select count(*) from api_keys where octet_length(token_hash) = 32") == "9"
    assert psql("select count(*) from api_keys where encode(token_hash, 'escape') like '%token%'") == "0"

with subtest("completed bootstrap never rewrites changed OIDC ownership"):
    machine.succeed("systemctl stop xotero.service")
    psql(
        f"""update external_identities
            set user_id = 202
            where issuer = '{oidc_issuer}' and subject = '{oidc_subject}'"""
    )
    machine.succeed("systemctl start xotero.service")
    machine.wait_for_unit("xotero.service")
    machine.wait_for_open_port(8189)
    assert (
        psql(
            f"""select user_id
                from external_identities
                where issuer = '{oidc_issuer}' and subject = '{oidc_subject}'"""
        )
        == "202"
    )

    psql(
        f"""update external_identities
            set user_id = 101
            where issuer = '{oidc_issuer}' and subject = '{oidc_subject}'"""
    )
    machine.succeed("systemctl reset-failed xotero.service")
    machine.succeed("systemctl start xotero.service")
    machine.wait_for_unit("xotero.service")
    machine.wait_for_open_port(8189)
    assert http_code("/keys/current", recovery) == "200"

with subtest("explicit recovery roles and pending digest authorization survive reload"):
    readonly_recovery = "recoveryreadonly"
    assert http_code("/keys/current", recovery) == "200"
    assert http_code("/keys/current", readonly_recovery) == "200"
    assert "write" not in get_json("/keys/current", readonly_recovery)["access"]["user"]
    assert http_code("/keys/current", "xotero-dev-key") == "403"
    before = body_admission_snapshot()
    version = psql("select version from library where id = 1")
    attachment = json.dumps([{
        "key": "RCVR2222", "itemType": "attachment",
        "linkMode": "imported_file", "filename": "recovery.txt",
    }])
    assert http_code("/users/101/items", readonly_recovery, "POST", attachment, version) == "403"
    assert body_admission_snapshot() == before
    assert http_code("/users/101/items", recovery, "POST", attachment, version) == "200"
    pending = machine.succeed(
        f"curl -sf -X POST {base}/users/101/items/RCVR2222/file {api_headers} "
        f"-H 'Zotero-API-Key: {recovery}' -H 'If-None-Match: *' "
        "-d 'md5=5d41402abc4b2a76b9719d911017c592&filename=recovery.txt&filesize=5&mtime=1' "
        "| jq -r .uploadKey"
    ).strip()
    assert psql(
        f"select bootstrap_user_id = 101 and authorizer_key_hash = "
        f"decode('{sha256_hex(recovery)}', 'hex') from pending_uploads "
        f"where token_hash = decode('{sha256_hex(pending)}', 'hex')"
    ) == "t"
    override = "/run/systemd/system/xotero.service.d/test-recovery.conf"
    machine.succeed("mkdir -p /run/systemd/system/xotero.service.d")
    try:
        for mode, setting in (
            ("removed", "UnsetEnvironment=XOTERO_KEYS"),
            ("restricted", "Environment=XOTERO_KEYS=ro:%d/key-recovery"),
        ):
            machine.succeed(
                f"printf '%s\\n' '[Service]' {shlex.quote(setting)} > {override} && "
                "systemctl daemon-reload"
            )
            restart_xotero()
            before = body_admission_snapshot()
            assert incomplete_body_status(f"/uploads/{pending}") == "403"
            assert http_code(f"/uploads/{pending}", method="POST", body="hello") == "403"
            assert body_admission_snapshot() == before
            assert http_code("/keys/current", recovery) == ("403" if mode == "removed" else "200")
            assert http_code("/keys/current", first_key) == "200"
            assert poll_login_session(first_session)["apiKey"] == first_key
            assert http_code("/keys/current", "xotero-dev-key") == "403"
            print("recovery-reload " + mode + ": pending upload denied; DB key and KDF replay valid")
    finally:
        machine.succeed(f"rm -f {override} && systemctl daemon-reload")
        restart_xotero()
    assert http_code(f"/uploads/{pending}", method="POST", body="hello") == "201"
    assert machine.succeed(
        f"curl -s -o /dev/null -w '%{{http_code}}' -X POST "
        f"{base}/users/101/items/RCVR2222/file {api_headers} "
        f"-H 'Zotero-API-Key: {recovery}' -d 'upload={pending}'"
    ).strip() == "204"
    assert machine.succeed(
        f"curl -sfL {api_headers} -H 'Zotero-API-Key: {recovery}' "
        f"{base}/users/101/items/RCVR2222/file"
    ) == "hello"

with subtest("login collision detection compares the configured recovery digest"):
    collision_session = create_login_session()
    collision_script = f"""
import hashlib
import hmac
import pathlib
alphabet = b"23456789ABCDEFGHIJKLMNPQRSTUVWXYZ"
kdf = pathlib.Path("/run/credentials/xotero.service/login-kdf-key").read_bytes().rstrip(b"\\r\\n")
key = bytearray()
counter = 0
while len(key) < 24:
    digest = hmac.digest(kdf, b"xotero login api key\\0" + {collision_session!r}.encode()
                         + counter.to_bytes(4, "big"), hashlib.sha256)
    key.extend(alphabet[byte % len(alphabet)] for byte in digest if byte < 231)
    counter += 1
pathlib.Path("/run/xotero-collision").write_bytes(bytes(key[:24]))
"""
    machine.succeed(f"python3 -c {shlex.quote(collision_script)}")
    count = psql("select count(*) from api_keys")
    override = "/run/systemd/system/xotero.service.d/test-collision.conf"
    try:
        machine.succeed(
            f"printf '%s\\n' '[Service]' "
            "'LoadCredential=key-collision:/run/xotero-collision' "
            "'Environment=XOTERO_KEYS=rw:%d/key-collision' "
            f"> {override} && systemctl daemon-reload"
        )
        restart_xotero()
        assert approve_login_session(collision_session) == "409"
        assert psql("select count(*) from api_keys") == count
        assert poll_login_session(collision_session)["status"] == "pending"
    finally:
        machine.succeed(f"rm -f {override} /run/xotero-collision && systemctl daemon-reload")
        restart_xotero()


def registration_snapshot(library_id: int, item_key: str) -> str:
    return psql(
        f"""select json_build_object(
            'library_version', (select version from library where id = {library_id}),
            'file', (select row_to_json(f) from file f
                     where library_id = {library_id} and item_key = '{item_key}'),
            'item', (select row_to_json(o) from object o
                     where library_id = {library_id} and kind = 'item' and key = '{item_key}'),
            'pending', (select json_agg(p order by token_hash) from pending_uploads p
                        where library_id = {library_id} and item_key = '{item_key}'))"""
    )


def authorize_bytes(path: str, token: str, payload: str, previous: str | None = None) -> str:
    condition = "If-None-Match: *" if previous is None else f"If-Match: {previous}"
    digest = hashlib.md5(payload.encode()).hexdigest()
    response = machine.succeed(
        f"curl -sS --max-time 10 -w '\\n%{{http_code}}' -X POST {base}{path} {api_headers} "
        f"-H 'Zotero-API-Key: {token}' -H '{condition}' "
        f"-d 'md5={digest}&filename=authority.txt&filesize={len(payload)}&mtime=1'"
    )
    body, status = response.rsplit("\n", 1)
    assert status == "200", (path, status, body)
    result = json.loads(body)
    upload = result["uploadKey"]
    assert http_code(f"/uploads/{upload}", method="POST", body=payload) == "201"
    return upload


def register_upload(path: str, token: str, upload: str) -> str:
    return machine.succeed(
        f"curl -sS --max-time 15 -o /dev/null -w '%{{http_code}}' -X POST "
        f"{base}{path} {api_headers} -H 'Zotero-API-Key: {token}' -d 'upload={upload}'"
    ).strip()


with subtest("registration revalidates original authority with a different live caller"):
    original_personal = "Task6PersonalOriginal2345"
    registrar_personal = "Task6PersonalRegistrar23"
    original_group = "Task6GroupOriginal234567"
    registrar_group = "Task6GroupRegistrar23456"
    for key_id, user_id, token, personal in (
        (6001, 202, original_personal, True),
        (6002, 202, registrar_personal, True),
        (6003, 202, original_group, False),
        (6004, 101, registrar_group, False),
    ):
        psql(
            f"""insert into api_keys (id, user_id, name, token_hash)
                values ({key_id}, {user_id}, 'registration authority fixture',
                        decode('{sha256_hex(token)}', 'hex'));
                insert into api_key_user_permissions (api_key_id, library, notes, write, files)
                values ({key_id}, {str(personal).lower()}, {str(personal).lower()},
                        {str(personal).lower()}, {str(personal).lower()})"""
        )
    psql(
        """begin;
           insert into library (id, version, kind) values (88, 0, 'group');
           insert into groups (id, library_id, owner_user_id, name,
                               library_editing, file_editing)
           values (808, 88, 101, 'Registration authority fixture', 'admins', 'members');
           insert into group_memberships (group_id, user_id, role)
           values (808, 101, 'owner'), (808, 202, 'member');
           insert into api_key_group_permissions (api_key_id, user_id, group_id, library, write)
           values (6003, 202, 808, true, true), (6004, 101, 808, true, true);
           commit"""
    )
    group_grant_restore = (
        "insert into api_key_group_permissions "
        "(api_key_id, user_id, group_id, library, write) values (6003, 202, 808, true, true)"
    )
    authority_failures = []
    for label, library_id, scope, original, registrar, revoke, restore in (
        (
            "original-key-revoked", 22, "/users/202", original_personal, registrar_personal,
            "update api_keys set revoked_at = now() where id = 6001",
            "update api_keys set revoked_at = null where id = 6001",
        ),
        (
            "original-personal-files-removed", 22, "/users/202", original_personal, registrar_personal,
            "update api_key_user_permissions set files = false where api_key_id = 6001",
            "update api_key_user_permissions set files = true where api_key_id = 6001",
        ),
        (
            "original-membership-removed", 88, "/groups/808", original_group, registrar_group,
            "delete from group_memberships where group_id = 808 and user_id = 202",
            "insert into group_memberships (group_id, user_id, role) values (808, 202, 'member'); "
            + group_grant_restore,
        ),
        (
            "original-group-grant-removed", 88, "/groups/808", original_group, registrar_group,
            "delete from api_key_group_permissions where api_key_id = 6003",
            group_grant_restore,
        ),
        (
            "original-group-file-policy-denied", 88, "/groups/808", original_group, registrar_group,
            "update groups set file_editing = 'admins' where id = 808",
            "update groups set file_editing = 'members' where id = 808",
        ),
        (
            "original-key-owner-disabled", 88, "/groups/808", original_group, registrar_group,
            "update users set disabled_at = now() where id = 202",
            "update users set disabled_at = null where id = 202",
        ),
    ):
        # Given: a real registered baseline and uploaded replacement authorized
        # by a different credential from the still-live registering caller.
        item_key = "T6AUTH22"
        path = f"{scope}/items/{item_key}/file"
        psql(
            f"""insert into object (library_id, kind, key, version, data)
                values ({library_id}, 'item', '{item_key}', 0,
                        '{{"key":"{item_key}","itemType":"attachment",
                          "linkMode":"imported_file","filename":"authority.txt"}}')"""
        )
        baseline = authorize_bytes(path, registrar, "hello")
        assert register_upload(path, registrar, baseline) == "204"
        pending = authorize_bytes(path, original, "world", hashlib.md5(b"hello").hexdigest())
        try:
            if label == "original-key-revoked":
                assert http_code("/keys/current", original, method="DELETE") == "204"
            else:
                psql(revoke)
            assert http_code("/keys/current", registrar) == "200"
            assert http_code(path, registrar) == "302"
            before = registration_snapshot(library_id, item_key)
            # When: original authority is gone but the caller remains allowed.
            status = register_upload(path, registrar, pending)
            # Then: denial cannot consume the token or mutate pointer/version.
            after = registration_snapshot(library_id, item_key)
            receipt = {
                "case": label, "status": int(status),
                "before": json.loads(before), "after": json.loads(after),
                "snapshot_unchanged": after == before,
            }
            print("REGISTRATION-AUTHORITY " + json.dumps(receipt, sort_keys=True))
            if status != "403" or after != before:
                authority_failures.append(label)
        finally:
            psql(restore)
            psql(
                f"delete from pending_uploads where library_id = {library_id} and item_key = '{item_key}'; "
                f"delete from file where library_id = {library_id} and item_key = '{item_key}'; "
                f"delete from object where library_id = {library_id} and kind = 'item' and key = '{item_key}'"
            )
    assert not authority_failures, (
        f"stale original authorization published: {authority_failures}"
    )

with subtest("live explicit group authority registers once without personal file permission"):
    psql(
        """insert into object (library_id, kind, key, version, data)
           values (88, 'item', 'T6LIVE22', 0,
                   '{"key":"T6LIVE22","itemType":"attachment",
                     "linkMode":"imported_file","filename":"live.txt"}')"""
    )
    path = "/groups/808/items/T6LIVE22/file"
    pending = authorize_bytes(path, original_group, "hello")
    before = int(psql("select version from library where id = 88"))
    assert register_upload(path, registrar_group, pending) == "204"
    snapshot = registration_snapshot(88, "T6LIVE22")
    assert int(psql("select version from library where id = 88")) == before + 1
    assert register_upload(path, registrar_group, pending) == "400"
    assert registration_snapshot(88, "T6LIVE22") == snapshot
    assert machine.succeed(
        f"curl -sfL --max-time 10 {api_headers} -H 'Zotero-API-Key: {registrar_group}' {base}{path}"
    ) == "hello"
    print("REGISTRATION-AUTHORITY live-explicit-group personal-files=false statuses=204,400 bytes=hello")


def registration_lock_race(path: str, token: str, upload: str, mutation: str,
                           item_lock: str | None = None) -> dict:
    """Release contenders only after PostgreSQL reports the exact blocking edge."""
    script = f"""
import json
import select
import subprocess
from contextlib import ExitStack

command = ["sudo", "-u", "xotero", "psql", "-X", "-qAt",
           "-v", "ON_ERROR_STOP=1", "-d", "xotero"]

def send(process, sql):
    process.stdin.write((sql + "\\n").encode())
    process.stdin.flush()

def receive(process):
    ready, _, _ = select.select([process.stdout], [], [], 15)
    assert ready, "database observer timed out"
    line = process.stdout.readline()
    assert line, ("database session exited", process.poll())
    return line.decode().strip()

def observe(process, blocker, query_fragment):
    # statement_timeout bounds a broken fixture. Success requires an observed
    # PostgreSQL lock edge, never elapsed time or a sleep-based head start.
    predicate = ("datname = 'xotero' and pid <> pg_backend_pid() "
                 "and wait_event_type = 'Lock' "
                 f"and {{blocker}} = any(pg_blocking_pids(pid)) "
                 f"and query like '%{{query_fragment}}%'")
    send(process, "set statement_timeout = '10s'; select 'OBSERVING'; "
         "do $$ begin loop perform pg_stat_clear_snapshot(); "
         f"exit when exists(select 1 from pg_stat_activity where {{predicate}}); "
         "end loop; end $$; "
         "select json_build_object('pid', pid, 'blockers', pg_blocking_pids(pid), "
         "'wait_event_type', wait_event_type, 'wait_event', wait_event, 'query', query) "
         f"from pg_stat_activity where {{predicate}};")
    assert receive(process) == "OBSERVING"

with ExitStack() as stack:
    blocker = stack.enter_context(subprocess.Popen(command, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, bufsize=0))
    observer = stack.enter_context(subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, bufsize=0))
    # Termination callbacks run before Popen.__exit__ waits, even on assertion.
    stack.callback(blocker.terminate)
    stack.callback(observer.terminate)
    send(blocker, "begin; " + ({item_lock!r} or {mutation!r}) +
         "; select 'HELD:' || pg_backend_pid();")
    held = receive(blocker)
    while not held.startswith("HELD:"):
        held = receive(blocker)
    blocker_pid = int(held.removeprefix("HELD:"))
    fragment = "from object" if {item_lock is not None!r} else "for share"
    observe(observer, blocker_pid, fragment)
    request = stack.enter_context(subprocess.Popen(
        ["curl", "-sS", "--max-time", "15", "-D", "-", "-X", "POST",
         {base + path!r}, "-H", "Zotero-API-Version: 3",
         "-H", "Content-Type: application/x-www-form-urlencoded",
         "-H", {"Zotero-API-Key: " + token!r}, "--data", {"upload=" + upload!r}],
        stdout=subprocess.PIPE))
    stack.callback(request.terminate)
    registration_wait = json.loads(receive(observer))
    revocation_wait = None
    if {item_lock is not None!r}:
        revoker = stack.enter_context(subprocess.Popen(command, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, bufsize=0))
        stack.callback(revoker.terminate)
        observe(observer, registration_wait["pid"], "update api_keys")
        send(revoker, {mutation!r} + "; select 'REVOKED';")
        revocation_wait = json.loads(receive(observer))
    send(blocker, "commit; select 'RELEASED';")
    assert receive(blocker) == "RELEASED"
    wire, _ = request.communicate(timeout=15)
    assert request.returncode == 0, (request.returncode, wire.decode())
    if {item_lock is not None!r}:
        assert receive(revoker) == "REVOKED"
    print(json.dumps({{"registration_wait": registration_wait,
                      "revocation_wait": revocation_wait,
                      "response": wire.decode()}}))
"""
    return json.loads(machine.succeed(f"python3 -c {shlex.quote(script)}"))


with subtest("committed revocation wins after observed registration authority lock wait"):
    race_cases = (
        ("original-key", 22, "/users/202", original_personal, registrar_personal,
         "update api_keys set revoked_at = now() where id = 6001",
         "update api_keys set revoked_at = null where id = 6001"),
        ("current-key", 22, "/users/202", original_personal, registrar_personal,
         "update api_keys set revoked_at = now() where id = 6002",
         "update api_keys set revoked_at = null where id = 6002"),
        ("current-personal-files", 22, "/users/202", original_personal, registrar_personal,
         "update api_key_user_permissions set files = false where api_key_id = 6002",
         "update api_key_user_permissions set files = true where api_key_id = 6002"),
        ("original-group-grant", 88, "/groups/808", original_group, registrar_group,
         "update api_key_group_permissions set write = false where api_key_id = 6003",
         "update api_key_group_permissions set write = true where api_key_id = 6003"),
        ("current-group-grant", 88, "/groups/808", original_group, registrar_group,
         "update api_key_group_permissions set write = false where api_key_id = 6004",
         "update api_key_group_permissions set write = true where api_key_id = 6004"),
        ("original-membership", 88, "/groups/808", original_group, registrar_group,
         "delete from group_memberships where group_id = 808 and user_id = 202",
         "insert into group_memberships (group_id, user_id, role) values (808, 202, 'member'); "
         + group_grant_restore),
        ("group-file-policy", 88, "/groups/808", original_group, registrar_group,
         "update groups set file_editing = 'none' where id = 808",
         "update groups set file_editing = 'members' where id = 808"),
        ("group-owner-disabled", 88, "/groups/808", original_group, registrar_group,
         "update users set disabled_at = now() where id = 101",
         "update users set disabled_at = null where id = 101"),
    )
    for index, (label, library_id, scope, original, registrar, revoke, restore) in enumerate(race_cases):
        item_key = "T6RACE" + "23456789"[index] + "2"
        path = f"{scope}/items/{item_key}/file"
        psql(
            f"""insert into object (library_id, kind, key, version, data)
                values ({library_id}, 'item', '{item_key}', 0,
                        '{{"key":"{item_key}","itemType":"attachment",
                          "linkMode":"imported_file","filename":"race.txt"}}')"""
        )
        pending = authorize_bytes(path, original, "hello")
        before = registration_snapshot(library_id, item_key)
        try:
            receipt = registration_lock_race(path, registrar, pending, revoke)
            after = registration_snapshot(library_id, item_key)
            receipt.update({"case": label, "winner": "revocation",
                            "before": json.loads(before), "after": json.loads(after)})
            print("REGISTRATION-LOCK " + json.dumps(receipt, sort_keys=True))
            assert receipt["response"].splitlines()[0].split()[1] == "403", receipt
            assert after == before, receipt
        finally:
            psql(restore)
        # Denial leaves an intact capability: restored authority can commit once.
        assert register_upload(path, registrar, pending) == "204"
        snapshot = registration_snapshot(library_id, item_key)
        assert register_upload(path, registrar, pending) == "400"
        assert registration_snapshot(library_id, item_key) == snapshot

with subtest("locked registration commits before a later revocation"):
    psql(
        """insert into object (library_id, kind, key, version, data)
           values (22, 'item', 'T6FIRST2', 0,
                   '{"key":"T6FIRST2","itemType":"attachment",
                     "linkMode":"imported_file","filename":"first.txt"}')"""
    )
    path = "/users/202/items/T6FIRST2/file"
    pending = authorize_bytes(path, original_personal, "hello")
    before = registration_snapshot(22, "T6FIRST2")
    try:
        receipt = registration_lock_race(
            path, registrar_personal, pending,
            "update api_keys set revoked_at = now() where id = 6001",
            "select 1 from object where library_id = 22 and key = 'T6FIRST2' for update",
        )
        after = registration_snapshot(22, "T6FIRST2")
        receipt.update({"case": "registration-first", "winner": "registration",
                        "before": json.loads(before), "after": json.loads(after)})
        print("REGISTRATION-LOCK " + json.dumps(receipt, sort_keys=True))
        assert receipt["response"].splitlines()[0].split()[1] == "204", receipt
        assert json.loads(after)["library_version"] == json.loads(before)["library_version"] + 1
        assert json.loads(after)["pending"] is None
        assert register_upload(path, registrar_personal, pending) == "400"
        assert registration_snapshot(22, "T6FIRST2") == after
        assert machine.succeed(
            f"curl -sfL --max-time 10 {api_headers} "
            f"-H 'Zotero-API-Key: {registrar_personal}' {base}{path}"
        ) == "hello"
    finally:
        psql("update api_keys set revoked_at = null where id = 6001")

with subtest("bootstrap fails closed without users identity metadata"):
    missing_metadata_script = r'''
import json
import os
import pwd
import shutil
import subprocess
import tempfile

pid = subprocess.check_output(
    ["systemctl", "show", "-p", "MainPID", "--value", "xotero.service"],
    text=True).strip()
assert pid and pid != "0", pid
service_environment = {}
with open("/proc/" + pid + "/environ", "rb") as source:
    for entry in source.read().split(b"\0"):
        if entry.startswith(b"XOTERO_"):
            key, value = entry.split(b"=", 1)
            service_environment[key.decode()] = value.decode()
assert "XOTERO_DATABASE_URL" in service_environment

def copy_credential(path, name):
    destination = os.path.join(credential_root, name)
    shutil.copyfile(path, destination)
    os.chown(destination, xotero_uid, xotero_gid)
    os.chmod(destination, 0o600)
    return destination

def sql(statement):
    return subprocess.check_output(
        ["sudo", "-u", "xotero", "psql", "-v", "ON_ERROR_STOP=1", "-At",
         "-d", "xotero", "-c", statement], text=True).strip()

success_before = int(sql("""select count(*) from audit_events
    where action='bootstrap.identity' and outcome='success'"""))
denied_before = int(sql("""select count(*) from audit_events
    where action='bootstrap.identity' and outcome='denied'"""))
users_before = int(sql("select count(*) from users"))
identities_before = int(sql("select count(*) from external_identities"))
account = pwd.getpwnam("xotero")
xotero_uid, xotero_gid = account.pw_uid, account.pw_gid
credential_root = tempfile.mkdtemp(prefix="xotero-task20-", dir="/run")
os.chown(credential_root, xotero_uid, xotero_gid)
os.chmod(credential_root, 0o700)
try:
    key_entries = []
    for index, entry in enumerate(service_environment["XOTERO_KEYS"].split(",")):
        scope, path = entry.split(":", 1)
        key_entries.append(
            scope + ":" + copy_credential(path, "key-" + str(index)))
    service_environment["XOTERO_KEYS"] = ",".join(key_entries)
    for variable, filename in (
        ("XOTERO_LOGIN_KDF_KEY_FILE", "login-kdf-key"),
        ("XOTERO_S3_ACCESS_KEY_FILE", "s3-access-key"),
        ("XOTERO_S3_SECRET_KEY_FILE", "s3-secret-key"),
    ):
        service_environment[variable] = copy_credential(
            service_environment[variable], filename)
    subprocess.run(["systemctl", "stop", "xotero.service"], check=True)
    sql("delete from bootstrap_state where name='identity'")
    sql("alter table users alter column id drop identity")
    assert sql("select pg_get_serial_sequence('users','id') is null") == "t"
    binary = shutil.which("xotero")
    assert binary
    process = subprocess.Popen(
        ["sudo", "-u", "xotero", "env",
         *[key + "=" + value for key, value in service_environment.items()], binary],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        output, _ = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise AssertionError("missing-metadata startup did not terminate")
    assert process.returncode == 101, (process.returncode, output)
    assert "bootstrap identity" in output and "bootstrap setup denied" in output, output
    assert "users identity sequence metadata is missing" not in output, output
    assert "xotero listening" not in output, output
    assert sql("select count(*) from bootstrap_state where name='identity'") == "0"
    assert int(sql("select count(*) from users")) == users_before
    assert int(sql("select count(*) from external_identities")) == identities_before
    success_after = int(sql("""select count(*) from audit_events
        where action='bootstrap.identity' and outcome='success'"""))
    denied_after = int(sql("""select count(*) from audit_events
        where action='bootstrap.identity' and outcome='denied'"""))
    assert success_after == success_before, (success_before, success_after)
    assert denied_after == denied_before + 1, (denied_before, denied_after)
    missing_metadata_receipt = {
        "exit": process.returncode,
        "pid": process.pid,
        "identity_metadata": None,
        "diagnostic": "bootstrap setup denied",
        "bootstrap_marker": False,
        "users_unchanged": True,
        "identities_unchanged": True,
        "success_delta": 0,
        "denied_delta": 1,
    }
finally:
    shutil.rmtree(credential_root)
    assert not os.path.exists(credential_root)
missing_metadata_receipt["credential_dir_removed"] = True
print(json.dumps(missing_metadata_receipt), flush=True)
'''
    compile(missing_metadata_script, "checkpoint20-missing-metadata", "exec")
    missing_metadata_receipt = json.loads(
        machine.succeed(
            f"python3 -c {shlex.quote(missing_metadata_script)}"
        )
    )
    assert missing_metadata_receipt["exit"] == 101
    assert missing_metadata_receipt["bootstrap_marker"] is False
    assert missing_metadata_receipt["success_delta"] == 0
    assert missing_metadata_receipt["denied_delta"] == 1
    assert missing_metadata_receipt["users_unchanged"] is True
    assert missing_metadata_receipt["identities_unchanged"] is True
    assert missing_metadata_receipt["credential_dir_removed"] is True
