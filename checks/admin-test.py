"""Instance bootstrap and reusable authority core against real PostgreSQL."""

import shlex

machine.wait_for_unit("postgresql.service")
machine.wait_for_unit("rustfs.service")

script = r'''
import concurrent.futures
import contextlib
import http.client
import json
import os
import pathlib
import selectors
import signal
import subprocess
import tempfile
import uuid
import urllib.parse

import psycopg

root = pathlib.Path(tempfile.mkdtemp(prefix="checkpoint13-"))
print("CHECKPOINT13_RESOURCES " + json.dumps({"pid": os.getpid(), "root": str(root)}), flush=True)
databases = []
processes = []
logs = []
receipts = {}

def connect(database, **kwargs):
    return psycopg.connect(host="127.0.0.1", user="xotero", dbname=database,
                          options="-c statement_timeout=20000 -c lock_timeout=15000", **kwargs)

def sql(database, statement, params=None):
    with connect(database, autocommit=True) as connection:
        cursor=connection.execute(statement, params)
        return cursor.fetchall() if cursor.description is not None else []

def database(name, legacy=False):
    name = "checkpoint13_" + name
    subprocess.run(["sudo", "-u", "postgres", "createdb", "-O", "xotero", name], check=True)
    databases.append(name)
    if legacy:
        subprocess.run(["env", "DATABASE_URL=postgres://xotero@127.0.0.1/" + name,
                        "sqlx", "migrate", "run", "--source", "/etc/xotero-test/v15-migrations"], check=True)
    return name

def start(database, opt_in=True, expect_failure=False, subject="owner", keep_running=False, **extra):
    environment = os.environ | {
        "XOTERO_DATABASE_URL": "postgres://xotero@127.0.0.1/" + database,
        "XOTERO_BIND": "127.0.0.1:8189",
        "XOTERO_USER_ID": "101",
        "XOTERO_USERNAME": "owner",
        "XOTERO_DISPLAY_NAME": "Owner",
        "XOTERO_BOOTSTRAP_OIDC_ISSUER": "https://id.example.test",
        "XOTERO_BOOTSTRAP_OIDC_SUBJECT": subject,
        "XOTERO_BOOTSTRAP_INSTANCE_ADMIN": str(opt_in).lower(),
        "XOTERO_LOGIN_KDF_KEY_FILE": "/etc/xotero-test/kdf",
        "XOTERO_S3_ENDPOINT": "http://127.0.0.1:9000",
        "XOTERO_S3_ACCESS_KEY": "rustfsadmin",
        "XOTERO_S3_SECRET_KEY": "rustfsadmin",
        "RUST_LOG": "info",
    } | extra
    process = subprocess.Popen(["xotero"], env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, bufsize=0)
    processes.append(process)
    lines = []
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            assert selector.select(45), ("startup timeout", lines)
            line = process.stdout.readline()
            if not line:
                assert expect_failure and process.wait(timeout=10) != 0, lines
                break
            lines.append(line.decode())
            if "xotero listening" in lines[-1]:
                assert not expect_failure, lines
                break
    logs.extend(lines)
    print("STARTUP " + json.dumps({"database": database, "opt_in": opt_in,
                                 "failed": expect_failure, "lines": lines}), flush=True)
    if process.poll() is None:
        port = int(environment["XOTERO_BIND"].rsplit(":", 1)[1])
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=10)) as client:
            client.request("GET", "/keys/current")
            response = client.getresponse()
            assert response.status == 403
            response.read()
        if keep_running:
            return process
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=15) == 0
    return process

def reachable(database):
    return sql(database, """select count(*) from instance_admins a
        join users u on u.id=a.user_id and u.disabled_at is null
        join personal_libraries p on p.user_id=u.id
        join library l on l.id=p.library_id and l.kind=p.library_kind
        where exists(select 1 from external_identities e where e.user_id=u.id)""")[0][0]

def wait_edges(database, predicate):
    """Observe exact lock graph; timeout guards failure, not release timing."""
    with connect(database, autocommit=True) as observer:
        observer.execute("set statement_timeout='15s'")
        observer.execute("""do $$
            declare deadline timestamptz := clock_timestamp()+interval '10 seconds';
            begin loop
              exit when (""" + predicate + """);
              if clock_timestamp()>deadline then raise exception 'missing lock edge'; end if;
              perform pg_stat_clear_snapshot();
            end loop; end $$""")

def request(method, path, body=None, headers=None):
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=20)) as client:
        client.request(method,path,body,headers or {})
        response=client.getresponse()
        return response.status,response.read()

def enrollment():
    status, body=request("POST","/keys/sessions",b"{}")
    assert status==201, (status,body)
    return json.loads(body)["sessionToken"]

def approve(token):
    return request("POST","/login",urllib.parse.urlencode({"session":token}),{
        "Content-Type":"application/x-www-form-urlencoded",
        "X-Xotero-OIDC-Issuer":"https://id.example.test",
        "X-Xotero-OIDC-Subject":"owner",
    })[0]

try:
    fresh = database("fresh")
    start(fresh)
    assert reachable(fresh) == 1
    assert sql(fresh, "select user_id from instance_admins") == [(101,)]
    assert sql(fresh, "select outcome from audit_events where action='bootstrap.instance-admin'") == [("success",)]
    start(fresh)
    assert sql(fresh, "select count(*) from audit_events where action='bootstrap.instance-admin' and outcome='success'") == [(1,)]
    sql(fresh, "update users set username='renamed', display_name='Changed' where id=101 returning id")
    sql(fresh, "delete from instance_admins returning user_id")
    sql(fresh, "delete from external_identities returning user_id")
    start(fresh, XOTERO_DISPLAY_NAME="Configuration changed")
    assert sql(fresh, "select username, display_name from users where id=101") == [("renamed", "Changed")]
    assert reachable(fresh) == 0
    assert sql(fresh, "select count(*) from external_identities") == [(0,)]
    assert sql(fresh, "select count(*) from bootstrap_state where name='instance-admin'") == [(1,)]
    receipts["one_shot"] = True

    recovery = database("recovery")
    start(recovery, opt_in=False, XOTERO_API_KEY="fixture-recovery")
    assert reachable(recovery) == 0
    assert sql(recovery, "select count(*) from bootstrap_state where name='instance-admin'") == [(0,)]
    start(recovery)
    assert reachable(recovery) == 1
    receipts["explicit_opt_in"] = True

    concurrent_db = database("concurrent")
    subprocess.run(["env","DATABASE_URL=postgres://xotero@127.0.0.1/"+concurrent_db,
        "sqlx","migrate","run","--source","/etc/xotero-test/current-migrations"],check=True)
    with connect(concurrent_db) as blocker, concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        blocker.execute("select xotero_lock_instance_authority()")
        futures=[executor.submit(start,concurrent_db,XOTERO_BIND="127.0.0.1:"+str(port))
                 for port in (8189,8190)]
        wait_edges(concurrent_db,f"""(select count(*) from pg_stat_activity where
            datname='{concurrent_db}' and {blocker.info.backend_pid}=any(pg_blocking_pids(pid)))=2""")
        blocker.commit()
        for future in futures:
            future.result(timeout=30)
    assert reachable(concurrent_db)==1
    assert sql(concurrent_db,"select count(*) from audit_events where action='bootstrap.instance-admin' and outcome='success'")==[(1,)]
    assert sql(concurrent_db,"select count(*) from bootstrap_state where name='instance-admin'")==[(1,)]
    receipts["concurrent_first_bootstrap"] = True

    upgrade = database("upgrade", legacy=True)
    sql(upgrade, """insert into users(id,username,display_name) values
        (101,'existing','Existing'),(202,'other','Other') returning id""")
    sql(upgrade, "insert into personal_libraries(user_id,library_id) values(101,1) returning user_id")
    sql(upgrade, """insert into external_identities(issuer,subject,user_id)
        values('https://id.example.test','secret-claim-conflict',202) returning user_id""")
    sql(upgrade,"insert into library(id,version,kind) values(33,17,'group') returning id")
    with connect(upgrade) as fixture:
        fixture.execute("""insert into groups(id,library_id,owner_user_id,name,version)
            values(303,33,101,'Preserved private group',7)""")
        fixture.execute("""insert into group_memberships(group_id,user_id,role)
            values(303,101,'owner'),(303,202,'admin')""")
    sql(upgrade,"""insert into object(library_id,kind,key,version,data)
        values(1,'item','PRESRV22',3,'{"itemType":"book","title":"Private fixture"}'),
              (33,'item','GROUP222',17,'{"itemType":"book","title":"Group fixture"}') returning key""")
    sql(upgrade,"""insert into api_keys(id,user_id,name,token_hash)
        values(401,101,'Preserved key',decode(repeat('42',32),'hex')) returning id""")
    sql(upgrade,"""insert into api_key_user_permissions(api_key_id,library,notes,write,files)
        values(401,true,true,true,true) returning api_key_id""")
    snapshot="""select jsonb_build_array(
        (select jsonb_agg(to_jsonb(u) order by id) from users u),
        (select jsonb_agg(to_jsonb(l) order by id) from library l),
        (select jsonb_agg(to_jsonb(p) order by user_id) from personal_libraries p),
        (select jsonb_agg(to_jsonb(g) order by id) from groups g),
        (select jsonb_agg(to_jsonb(m) order by group_id,user_id) from group_memberships m),
        (select jsonb_agg(to_jsonb(o) order by library_id,kind,key) from object o),
        (select jsonb_agg(to_jsonb(k) order by id) from api_keys k),
        (select jsonb_agg(to_jsonb(p) order by api_key_id) from api_key_user_permissions p))"""
    preserved=sql(upgrade,snapshot)
    before = sql(upgrade, "select version,checksum from _sqlx_migrations order by version")
    start(upgrade, opt_in=False)
    assert sql(upgrade,snapshot)==preserved
    assert reachable(upgrade) == 0
    assert sql(upgrade, "select version,checksum from _sqlx_migrations where version<=15 order by version") == before
    start(upgrade, expect_failure=True, subject="secret-claim-conflict")
    assert sql(upgrade, "select count(*) from bootstrap_state where name='instance-admin'") == [(0,)]
    assert sql(upgrade, "select count(*) from instance_admins") == [(0,)]
    assert sql(upgrade, "select count(*) from external_identities where subject='owner'") == [(0,)]
    assert sql(upgrade, "select outcome from audit_events where action='bootstrap.instance-admin'") == [("denied",)]
    start(upgrade)
    assert sql(upgrade,snapshot)==preserved
    assert reachable(upgrade) == 1
    assert sql(upgrade, "select username,display_name from users where id=101") == [("existing","Existing")]
    receipts["populated_upgrade_conflict_atomic"] = True

    race = database("race")
    start(race)
    sql(race, "insert into library(id,version,kind) values(22,0,'personal') returning id")
    sql(race, "insert into users(id,username,display_name) values(202,'second','Second') returning id")
    sql(race, "insert into personal_libraries(user_id,library_id) values(202,22) returning user_id")
    sql(race, """insert into external_identities(issuer,subject,user_id)
        values('https://id.example.test','second',202) returning user_id""")

    def transition(user, change, request, subject=None):
        with connect(race, autocommit=True, application_name=request) as connection:
            return connection.execute(
                "select xotero_change_authority(%s,%s,%s,%s,%s,%s)",
                (user, change, "https://id.example.test", subject or ("owner" if user == 101 else "second"),
                 101, uuid.uuid4())).fetchone()[0]

    # Hold sentinel, arm worker connections, observe exact database lock waits,
    # then release. No head starts or wall-clock sleeps establish contention.
    for changes in [("revoke-admin","revoke-admin"), ("disable-user","revoke-admin"),
                    ("unlink-identity","disable-user")]:
        sql(race, "update users set disabled_at=null returning id")
        sql(race, "insert into instance_admins(user_id) values(101),(202) on conflict do nothing returning user_id")
        sql(race, """insert into external_identities(issuer,subject,user_id)
            values('https://id.example.test','owner',101),('https://id.example.test','second',202)
            on conflict do nothing returning user_id""")
        with connect(race) as blocker, concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            blocker.execute("select xotero_lock_instance_authority()")
            futures = [executor.submit(transition, user, change, "race-" + str(user))
                       for user, change in zip((101,202), changes)]
            wait_edges(race,f"""(select count(*) from pg_stat_activity
                where application_name in ('race-101','race-202')
                and {blocker.info.backend_pid}=any(pg_blocking_pids(pid)))=2""")
            blocker.commit()
            outcomes = [future.result(timeout=20) for future in futures]
        assert sorted(outcomes) == ["conflict","success"], outcomes
        assert reachable(race) == 1
        print("AUTHORITY_RACE " + json.dumps({"changes":changes,"outcomes":outcomes}), flush=True)
    receipts["serialized_mixed_final_admin"] = True
    sql(race,"insert into users(id,username,display_name) values(303,'ordinary','Ordinary') returning id")
    sql(race,"insert into library(id,version,kind) values(44,0,'personal') returning id")
    sql(race,"insert into personal_libraries(user_id,library_id) values(303,44) returning user_id")
    sql(race,"""insert into external_identities(issuer,subject,user_id)
        values('https://id.example.test','identity-a',303),
              ('https://id.example.test','identity-b',303) returning user_id""")
    with connect(race) as blocker, concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        blocker.execute("select xotero_lock_instance_authority()")
        futures=[executor.submit(transition,303,"unlink-identity",name,name)
                 for name in ("identity-a","identity-b")]
        wait_edges(race,f"""(select count(*) from pg_stat_activity where
            application_name in ('identity-a','identity-b')
            and {blocker.info.backend_pid}=any(pg_blocking_pids(pid)))=2""")
        blocker.commit()
        outcomes=[future.result(timeout=25) for future in futures]
    assert sorted(outcomes)==["conflict","success"],outcomes
    assert sql(race,"select count(*) from external_identities where user_id=303")==[(1,)]
    remaining=sql(race,"select subject from external_identities where user_id=303")[0][0]
    assert transition(303,"unlink-identity","enabled-final",remaining)=="conflict"
    sql(race,"update users set disabled_at=now() where id=303 returning id")
    assert transition(303,"unlink-identity","disabled-final",remaining)=="success"
    assert transition(303,"unlink-identity","absent-identity",remaining)=="noop"
    receipts["last_enabled_identity_serialized"] = True
    assert transition(999, "revoke-admin", "missing") == "missing"
    survivor = sql(race, "select user_id from xotero_reachable_admins()")[0][0]
    assert transition(survivor, "unlink-identity", "last-identity") == "conflict"
    assert transition(survivor, "disable-user", "last-enabled") == "conflict"
    assert transition(survivor, "revoke-admin", "last-role") == "conflict"
    assert transition(101, "disable-user", "already-disabled") in ("noop","conflict")
    assert sql(race, "select count(*) from audit_events where outcome='denied'")[0][0] >= 3
    # Unexpected audit failure rolls back the authority mutation as well.
    sql(race,"update users set disabled_at=null returning id")
    sql(race,"insert into instance_admins(user_id) values(101),(202) on conflict do nothing returning user_id")
    before=sql(race,"select count(*) from audit_events")
    try:
        with connect(race,autocommit=True) as connection:
            connection.execute("""select xotero_change_authority(202,'revoke-admin',null,null,101,null)""")
    except psycopg.errors.NotNullViolation:
        pass
    else:
        raise AssertionError("missing audit must reject mutation")
    assert sql(race,"select count(*) from instance_admins")==[(2,)]
    assert sql(race,"select count(*) from audit_events")==before
    receipts["audit_rollback_atomic"] = True

    sql(race,"update users set disabled_at=now() where id=202 returning id")
    sql(race,"update users set disabled_at=null where id=303 returning id")
    sql(race,"""insert into users(id,username,display_name) values
        (404,'unmapped','Unmapped') returning id""")
    sql(race,"""insert into external_identities(issuer,subject,user_id)
        values('https://id.example.test','unmapped',404) returning user_id""")
    sql(race,"insert into instance_admins(user_id) values(303),(404) returning user_id")
    assert reachable(race)==1
    assert transition(101,"revoke-admin","unreachable-not-counted")=="conflict"
    sql(race,"delete from instance_admins where user_id in (303,404) returning user_id")
    sql(race,"update users set disabled_at=null where id=202 returning id")
    receipts["unreachable_roles_not_counted"] = True

    # Real HTTP enrollment versus production unlink/disable, in BOTH lock orders.
    # Secondary identity makes unlink a legal operation without lockout.
    sql(race,"""insert into external_identities(issuer,subject,user_id)
        values('https://id.example.test','backup',101) returning user_id""")
    server=start(race,keep_running=True)
    for change in ("unlink-identity","disable-user"):
        for order in ("authority-first","enrollment-first"):
            sql(race,"update users set disabled_at=null returning id")
            sql(race,"""insert into external_identities(issuer,subject,user_id)
                values('https://id.example.test','owner',101) on conflict do nothing returning user_id""")
            token=enrollment()
            keys_before=sql(race,"select count(*) from api_keys")[0][0]
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                if order=="authority-first":
                    with connect(race) as mutation:
                        assert mutation.execute(
                            "select xotero_change_authority(101,%s,'https://id.example.test','owner',202,%s)",
                            (change,uuid.uuid4())).fetchone()[0]=="success"
                        pending=executor.submit(approve,token)
                        wait_edges(race,f"""exists(select 1 from pg_stat_activity
                            where {mutation.info.backend_pid}=any(pg_blocking_pids(pid)))""")
                        mutation.commit()
                        assert pending.result(timeout=20)==403
                    assert sql(race,"select count(*) from api_keys")[0][0]==keys_before
                else:
                    # DDL has no result rows, unlike fixture SQL helpers.
                    with connect(race,autocommit=True) as ddl:
                        ddl.execute("""create or replace function checkpoint13_key_gate() returns trigger
                            language plpgsql as $$begin perform pg_advisory_xact_lock(772213);
                            return new; end$$""")
                        ddl.execute("""create trigger checkpoint13_key_gate before insert on api_keys
                            for each row execute function checkpoint13_key_gate()""")
                    try:
                        with connect(race) as gate:
                            gate.execute("select pg_advisory_xact_lock(772213)")
                            pending=executor.submit(approve,token)
                            wait_edges(race,f"""exists(select 1 from pg_stat_activity
                                where {gate.info.backend_pid}=any(pg_blocking_pids(pid)))""")
                            mutation=executor.submit(transition,101,change,"enrollment-contender")
                            wait_edges(race,"""exists(select 1 from pg_stat_activity
                                where application_name='enrollment-contender' and wait_event_type='Lock')""")
                            gate.commit()
                            assert pending.result(timeout=20)==200
                            assert mutation.result(timeout=20)=="success"
                    finally:
                        with connect(race,autocommit=True) as ddl:
                            ddl.execute("drop trigger checkpoint13_key_gate on api_keys")
                            ddl.execute("drop function checkpoint13_key_gate()")
                    assert sql(race,"select count(*) from api_keys")[0][0]==keys_before+1
                assert approve(enrollment())==403
                print("ENROLLMENT_RACE "+json.dumps({"change":change,"order":order,
                    "revoked_approval":403,"stale_keys":0}),flush=True)
    server.send_signal(signal.SIGINT)
    assert server.wait(timeout=15)==0
    receipts["ordered_enrollment_revocation"] = True
    assert not any("secret-claim-conflict" in line for line in logs), logs
    assert sql(upgrade, "select count(*) from audit_events where row_to_json(audit_events)::text like '%secret-claim%'") == [(0,)]
    receipts["sanitized_durable_audit"] = True
    print("CHECKPOINT13_BOOTSTRAP " + json.dumps(receipts, sort_keys=True), flush=True)
finally:
    for process in processes:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
            process.wait(timeout=15)
    for name in databases:
        subprocess.run(["sudo","-u","postgres","dropdb",name],check=True)
    root.rmdir()
    print("CHECKPOINT13_CLEANUP " + json.dumps({"databases":databases,"processes":[p.pid for p in processes],
                                              "root_removed":not root.exists()}), flush=True)
'''
print(machine.succeed("python3 -u -c " + shlex.quote(script)))

web_script = r'''
import concurrent.futures
import contextlib
import hashlib
import http.client
import http.server
import json
import os
import selectors
import signal
import subprocess
import threading

import psycopg

database = "checkpoint14_web"
print("CHECKPOINT14_RESOURCES "+json.dumps({"database":database,"pid":os.getpid()}),flush=True)
server = None
proxy = None
receipts = {}
secrets = []
origin = "https://library.example.test"

def connect(**kwargs):
    return psycopg.connect(host="127.0.0.1",user="xotero",dbname=database,
        options="-c statement_timeout=20000 -c lock_timeout=15000",**kwargs)

def sql(statement,params=None):
    with connect(autocommit=True) as connection:
        cursor=connection.execute(statement,params)
        return cursor.fetchall() if cursor.description is not None else []

def wait_edge(blocker,count=1):
    with connect(autocommit=True) as observer:
        observer.execute("""do $$declare deadline timestamptz:=clock_timestamp()+interval '10 seconds';
            begin loop
              exit when (select count(*) from pg_stat_activity where
                """+str(blocker)+"""=any(pg_blocking_pids(pid)))="""+str(count)+""";
              if clock_timestamp()>deadline then raise exception 'missing exact lock edge'; end if;
              perform pg_stat_clear_snapshot();
            end loop; end$$""")

class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.forward()
    def do_POST(self):
        self.forward()
    def log_message(self,*args):
        pass
    def forward(self):
        # Stand-in for verified local OIDC authentication. Caller identity
        # headers never reach the trusted backend, including duplicate copies.
        identity = {
            "Bearer fixture-owner-auth": "owner",
            "Bearer fixture-second-auth": "second",
            "Bearer fixture-disabled-auth": "disabled",
            "Bearer fixture-unknown-auth": "unknown",
        }.get(self.headers.get("Authorization"))
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=20)) as backend:
            backend.putrequest(self.command,self.path)
            for name,value in self.headers.items():
                if name.lower() not in ("host","connection","content-length","authorization",
                    "x-xotero-oidc-issuer","x-xotero-oidc-subject"):
                    backend.putheader(name,value)
            if identity is not None:
                backend.putheader("X-Xotero-OIDC-Issuer","https://id.example.test")
                backend.putheader("X-Xotero-OIDC-Subject",identity)
            backend.endheaders()
            response=backend.getresponse()
            body=response.read()
            self.send_response(response.status)
            for name,value in response.getheaders():
                if name.lower() not in ("connection","transfer-encoding","content-length"):
                    self.send_header(name,value)
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)

def request(method,path,cookies=None,csrf=None,user="owner",request_origin=origin,extra=()):
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1",proxy.server_port,timeout=25)) as client:
        client.putrequest(method,path)
        if cookies:
            client.putheader("Cookie","; ".join(k+"="+v for k,v in cookies.items()))
        if request_origin is not None:
            client.putheader("Origin",request_origin)
        if csrf is not None:
            client.putheader("X-Xotero-CSRF",csrf)
        if user is not None:
            client.putheader("Authorization","Bearer fixture-"+user+"-auth")
        for name,value in extra:
            client.putheader(name,value)
        client.endheaders()
        response=client.getresponse()
        body=response.read()
        return response.status,body,response.headers

def challenge(cookies=None):
    status,body,headers=request("GET","/xotero/web/session",cookies)
    assert status==200,("web challenge GET",status,body)
    result=json.loads(body)
    assert set(result)=={"csrfToken"},result
    assert len(result["csrfToken"])==64
    secrets.append(result["csrfToken"])
    values=headers.get_all("Set-Cookie")
    assert len(values)==1 and values[0].startswith("__Host-xotero-browser="),values
    assert "HttpOnly" in values[0] and "Secure" in values[0] and "Path=/" in values[0]
    jar=dict(cookies or {})
    name,value=values[0].split(";",1)[0].split("=",1)
    jar[name]=value
    secrets.append(value)
    assert headers["Cache-Control"]=="no-store"
    return jar,result["csrfToken"]

def login(cookies=None):
    jar,csrf=challenge(cookies)
    status,body,headers=request("POST","/xotero/web/session",jar,csrf)
    assert status==200,(status,body)
    result=json.loads(body)
    assert set(result)=={"csrfToken","userID"} and result["userID"]==101,result
    values=headers.get_all("Set-Cookie")
    assert len(values)==2,values
    assert {value.split("=",1)[0] for value in values}=={"__Host-xotero-session","__Host-xotero-browser"},values
    for value in values:
        for attribute in ("Secure","HttpOnly","SameSite=Lax","Path=/","Max-Age=28800"):
            assert attribute in value,values
        name,token=value.split(";",1)[0].split("=",1)
        jar[name]=token
        secrets.append(token)
    secrets.append(result["csrfToken"])
    return jar,result["csrfToken"]

def token_hash(jar):
    return hashlib.sha256(jar["__Host-xotero-session"].encode()).digest()

def family_lock(connection,jar):
    family=int.from_bytes(hashlib.sha256(jar["__Host-xotero-browser"].encode()).digest()[:4],
                          "big",signed=True)
    connection.execute("select pg_advisory_xact_lock(146415674,%s)",(family,))

def logout(jar,csrf):
    return request("POST","/xotero/web/session/logout",jar,csrf)[0]

try:
    subprocess.run(["sudo","-u","postgres","createdb","-O","xotero",database],check=True)
    subprocess.run(["env","DATABASE_URL=postgres://xotero@127.0.0.1/"+database,
        "sqlx","migrate","run","--source","/etc/xotero-test/v16-migrations"],check=True)
    preserved_key="23456789ABCDEFGHJKLMNPQR"
    secrets.append(preserved_key)
    sql("insert into users(id,username,display_name) values(101,'owner','Owner')")
    sql("insert into personal_libraries(user_id,library_id) values(101,1)")
    sql("""insert into external_identities(issuer,subject,user_id)
        values('https://id.example.test','owner',101)""")
    sql("insert into instance_admins(user_id) values(101)")
    sql("insert into bootstrap_state(name) values('identity'),('instance-admin')")
    sql("""select xotero_append_audit(101,101,'bootstrap.instance-admin','success',
        '11111111-1111-4111-8111-111111111111')""")
    sql("""insert into api_keys(id,user_id,name,token_hash) values(401,101,'Preserved v16 credential',%s)""",
        (hashlib.sha256(preserved_key.encode()).digest(),))
    sql("""insert into api_key_user_permissions(api_key_id,library,notes,write,files)
        values(401,true,true,true,true)""")
    v16_snapshot="""select jsonb_build_array(
        (select jsonb_agg(to_jsonb(u) order by id) from users u),
        (select jsonb_agg(to_jsonb(e) order by issuer,subject) from external_identities e),
        (select jsonb_agg(to_jsonb(p) order by user_id) from personal_libraries p),
        (select jsonb_agg(to_jsonb(a) order by user_id) from instance_admins a),
        (select jsonb_agg(to_jsonb(b) order by name) from bootstrap_state b),
        (select jsonb_agg(to_jsonb(a) order by id) from audit_events a where id<=1),
        (select jsonb_agg(to_jsonb(k) order by id) from api_keys k),
        (select jsonb_agg(to_jsonb(p) order by api_key_id) from api_key_user_permissions p))"""
    preserved=sql(v16_snapshot)
    v16_checksums=sql("select version,checksum from _sqlx_migrations order by version")
    environment = os.environ | {
        "XOTERO_DATABASE_URL":"postgres://xotero@127.0.0.1/"+database,
        "XOTERO_BIND":"127.0.0.1:8189",
        "XOTERO_PUBLIC_URL":"https://library.example.test",
        "XOTERO_USER_ID":"101","XOTERO_USERNAME":"owner","XOTERO_DISPLAY_NAME":"Owner",
        "XOTERO_BOOTSTRAP_OIDC_ISSUER":"https://id.example.test",
        "XOTERO_BOOTSTRAP_OIDC_SUBJECT":"owner","XOTERO_BOOTSTRAP_INSTANCE_ADMIN":"true",
        "XOTERO_LOGIN_KDF_KEY_FILE":"/etc/xotero-test/kdf",
        "XOTERO_S3_ENDPOINT":"http://127.0.0.1:9000",
        "XOTERO_S3_ACCESS_KEY":"rustfsadmin","XOTERO_S3_SECRET_KEY":"rustfsadmin",
    }
    server=subprocess.Popen(["xotero"],env=environment,stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,bufsize=0)
    with selectors.DefaultSelector() as observer:
        observer.register(server.stdout,selectors.EVENT_READ)
        while True:
            assert observer.select(45),"startup timeout"
            line=server.stdout.readline()
            assert line,server.poll()
            if b"xotero listening" in line:
                break
    proxy=http.server.ThreadingHTTPServer(("127.0.0.1",0),Proxy)
    proxy_thread=threading.Thread(target=proxy.serve_forever)
    proxy_thread.start()
    print("CHECKPOINT14_PROXY "+json.dumps({"port":proxy.server_port,"backend":8189}),flush=True)
    assert sql(v16_snapshot)==preserved
    assert sql("select version,checksum from _sqlx_migrations where version<=16 order by version")==v16_checksums
    assert sql("select max(version) from _sqlx_migrations")==[(17,)]
    assert request("GET","/keys/current",extra=[("Zotero-API-Key",preserved_key)])[0]==200
    receipts["populated_v16_authority_audit_key_upgrade_preserved"]=True
    sql("insert into users(id,username,display_name) values(202,'second','Second'),(303,'disabled','Disabled')")
    sql("insert into library(id,version,kind) values(22,0,'personal'),(33,0,'personal')")
    sql("insert into personal_libraries(user_id,library_id) values(202,22),(303,33)")
    sql("""insert into external_identities(issuer,subject,user_id) values
        ('https://id.example.test','second',202),('https://id.example.test','disabled',303)""")
    sql("update users set disabled_at=clock_timestamp() where id=303")
    jar,csrf=challenge()
    assert sql("select count(*) from web_sessions")==[(0,)]
    assert sql("select count(*) from api_keys")==[(1,)]
    receipts["challenge_only"]=True
    for supplied_origin in (None,"null","https://evil.example","https://library.example.test/"):
        assert request("POST","/xotero/web/session",jar,csrf,request_origin=supplied_origin)[0]==403
    for extra in [
        [("Origin",origin)],
        [("X-Xotero-CSRF",csrf)],
        [("X-Forwarded-Host","evil.example"),("Origin","https://evil.example")],
    ]:
        assert request("POST","/xotero/web/session",jar,csrf,extra=extra)[0]==403
    for user in ("unknown","disabled",None):
        assert request("POST","/xotero/web/session",jar,csrf,user=user,
            extra=[("X-Xotero-OIDC-Issuer","https://id.example.test"),
                   ("X-Xotero-OIDC-Subject","owner")])[0]==403
    # Overwriting spoofed claims with a different authenticated identity must
    # select that user's exact personal library, never caller's claimed owner.
    status,body,headers=request("POST","/xotero/web/session",jar,csrf,user="second",
        extra=[("X-Xotero-OIDC-Issuer","forged"),("X-Xotero-OIDC-Subject","owner")])
    assert status==200 and json.loads(body)["userID"]==202,(status,body)
    assert sql("select user_id,library_id from web_sessions")==[(202,22)]
    receipts["proxy_overwrite_unknown_disabled_origin"]=True
    jar,csrf=challenge()
    alien,unused=challenge()
    assert request("POST","/xotero/web/session",alien,csrf)[0]==403
    assert request("POST","/xotero/web/session",jar,"0"*64)[0]==403
    before=sql("select count(*) from api_keys")[0][0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        with connect() as blocker:
            family_lock(blocker,jar)
            futures=[executor.submit(request,"POST","/xotero/web/session",jar,csrf) for _ in range(2)]
            wait_edge(blocker.info.backend_pid,2)
            blocker.commit()
            outcomes=[future.result()[0] for future in futures]
    assert sorted(outcomes)==[200,403],outcomes
    assert sql("select count(*) from api_keys")[0][0]==before+1
    receipts["one_use_browser_bound_concurrent"]=True
    jar,csrf=login()
    old=dict(jar)
    old_csrf=csrf
    old_key=sql("select api_key_id from web_sessions where token_hash=%s",(token_hash(old),))[0][0]
    jar,csrf=login(jar)
    assert jar["__Host-xotero-session"]!=old["__Host-xotero-session"]
    assert sql("select revoked_at is not null from api_keys where id=%s",(old_key,))==[(True,)]
    assert logout(old,old_csrf)==403
    for path in ("/keys/current","/users/101/items","/groups/303/items"):
        assert request("GET",path,jar,csrf)[0]==403
    for supplied_origin in (None,"null","https://evil.example"):
        assert request("POST","/xotero/web/session/logout",jar,csrf,request_origin=supplied_origin)[0]==403
    assert logout(jar,"0"*64)==403
    key=sql("select api_key_id from web_sessions where token_hash=%s",(token_hash(jar),))[0][0]
    assert logout(jar,csrf)==204
    assert logout(jar,csrf)==403
    assert sql("select revoked_at is not null from api_keys where id=%s",(key,))==[(True,)]
    receipts["rotation_logout_key_cookie_isolation"]=True
    jar,csrf=login()
    one,c1=challenge(jar)
    two,c2=challenge(jar)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        with connect() as blocker:
            family_lock(blocker,jar)
            futures=[executor.submit(request,"POST","/xotero/web/session",j,c)
                     for j,c in ((one,c1),(two,c2))]
            wait_edge(blocker.info.backend_pid,2)
            blocker.commit()
            outcomes=[future.result()[0] for future in futures]
    assert sorted(outcomes)==[200,403],outcomes
    assert sql("select count(*) from web_sessions where browser_hash=%s and revoked_at is null",
        (hashlib.sha256(jar["__Host-xotero-browser"].encode()).digest(),))==[(1,)]
    receipts["same_old_session_single_rotation"]=True
    jar,csrf=login()
    rotating,challenge_csrf=challenge(jar)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        with connect() as blocker:
            family_lock(blocker,jar)
            rotating_future=executor.submit(request,"POST","/xotero/web/session",rotating,challenge_csrf)
            logout_future=executor.submit(logout,jar,csrf)
            wait_edge(blocker.info.backend_pid,2)
            blocker.commit()
            outcomes=[rotating_future.result()[0],logout_future.result()]
    assert sorted(outcomes) in ([200,403],[204,403]),outcomes
    receipts["logout_rotation_single_winner"]=True
    # An unfinished body must not postpone boundary rejection. Direct backend
    # probes test parsing only; arbitrary local processes are trusted here.
    for extras in (
        [("Content-Length","1048576")],
        [("Origin",origin),("Origin",origin),("Content-Length","1048576")],
        [("Origin",origin),("X-Xotero-OIDC-Issuer","https://id.example.test"),
         ("X-Xotero-OIDC-Issuer","https://id.example.test"),
         ("X-Xotero-OIDC-Subject","owner"),("Content-Length","1048576")],
    ):
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=5)) as client:
            client.putrequest("POST","/xotero/web/session")
            for name,value in extras:
                client.putheader(name,value)
            client.endheaders()
            response=client.getresponse()
            assert response.status==403,response.status
            response.read()
    receipts["prebody_singleton_boundary"]=True
    # Both operations must encounter their live expiry/revocation/identity
    # after an observed authority-row wait, not transaction-start now().
    for mutation in ("expiry","key","disabled","mapping"):
        jar,csrf=login()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with connect() as blocker:
                blocker.execute("select id from library where id=1 for update")
                future=executor.submit(logout,jar,csrf)
                wait_edge(blocker.info.backend_pid)
                if mutation=="expiry":
                    blocker.execute("""update web_sessions set created_at=clock_timestamp()-interval '9 hours',
                        expires_at=clock_timestamp()-interval '1 hour' where token_hash=%s""",(token_hash(jar),))
                elif mutation=="key":
                    blocker.execute("""update api_keys set revoked_at=clock_timestamp() where id=
                        (select api_key_id from web_sessions where token_hash=%s)""",(token_hash(jar),))
                elif mutation=="disabled":
                    blocker.execute("update users set disabled_at=clock_timestamp() where id=101")
                else:
                    blocker.execute("update external_identities set user_id=202 where subject='owner'")
                blocker.commit()
                assert future.result(timeout=25)==403,mutation
        sql("update users set disabled_at=null where id=101")
        sql("update external_identities set user_id=101 where subject='owner'")
    receipts["live_expiry_key_disabled_mapping_after_wait"]=True
    for mutation in ("disabled","mapping","challenge-expiry"):
        jar,csrf=challenge()
        before=sql("select count(*) from api_keys")[0][0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with connect() as blocker:
                if mutation=="challenge-expiry":
                    family_lock(blocker,jar)
                else:
                    blocker.execute("select id from library where id=1 for update")
                future=executor.submit(request,"POST","/xotero/web/session",jar,csrf)
                wait_edge(blocker.info.backend_pid)
                if mutation=="disabled":
                    blocker.execute("update users set disabled_at=clock_timestamp() where id=101")
                elif mutation=="mapping":
                    blocker.execute("update external_identities set user_id=202 where subject='owner'")
                else:
                    blocker.execute("""update web_challenges set expires_at=clock_timestamp()-interval '1 hour'
                        where token_hash=%s""",(hashlib.sha256(csrf.encode()).digest(),))
                blocker.commit()
                assert future.result(timeout=25)[0]==403,mutation
        assert sql("select count(*) from api_keys")[0][0]==before
        sql("update users set disabled_at=null where id=101")
        sql("update external_identities set user_id=101 where subject='owner'")
    receipts["login_stale_discovery_no_mint"]=True
    jar,csrf=login()
    jar,challenge_csrf=challenge(jar)
    before=sql("select count(*) from api_keys")[0][0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        with connect() as blocker:
            blocker.execute("select id from library where id=1 for update")
            future=executor.submit(request,"POST","/xotero/web/session",jar,challenge_csrf)
            wait_edge(blocker.info.backend_pid)
            blocker.execute("""update api_keys set revoked_at=clock_timestamp() where id=
                (select api_key_id from web_sessions where token_hash=%s)""",(token_hash(jar),))
            blocker.commit()
            assert future.result(timeout=25)[0]==403
    assert sql("select count(*) from api_keys")[0][0]==before
    receipts["rotation_revoked_credential_after_discovery_no_mint"]=True
    # Failed session insert cannot leave an orphan credential or consume the
    # challenge. A failed revoke must preserve both session and credential.
    with connect(autocommit=True) as ddl:
        ddl.execute("""create function checkpoint14_fail() returns trigger language plpgsql as
            $$begin raise exception 'fixture constraint failure'; end$$""")
        ddl.execute("create trigger checkpoint14_fail before insert on web_sessions for each row execute function checkpoint14_fail()")
    jar,csrf=challenge()
    before=sql("select count(*) from api_keys")[0][0]
    assert request("POST","/xotero/web/session",jar,csrf)[0]==500
    assert sql("select count(*) from api_keys")[0][0]==before
    with connect(autocommit=True) as ddl:
        ddl.execute("drop trigger checkpoint14_fail on web_sessions")
    status,body,headers=request("POST","/xotero/web/session",jar,csrf)
    assert status==200,(status,body)
    jar["__Host-xotero-session"]=headers["Set-Cookie"].split(";",1)[0].split("=",1)[1]
    csrf=json.loads(body)["csrfToken"]
    with connect(autocommit=True) as ddl:
        ddl.execute("create trigger checkpoint14_fail before update on web_sessions for each row execute function checkpoint14_fail()")
    assert logout(jar,csrf)==500
    assert sql("""select k.revoked_at,s.revoked_at from web_sessions s join api_keys k on k.id=s.api_key_id
        where s.token_hash=%s""",(token_hash(jar),))==[(None,None)]
    with connect(autocommit=True) as ddl:
        ddl.execute("drop trigger checkpoint14_fail on web_sessions")
        ddl.execute("drop function checkpoint14_fail()")
    assert logout(jar,csrf)==204
    receipts["atomic_issue_revoke_rollback"]=True
    raw=sql("select row_to_json(s)::text from web_sessions s")+sql("select row_to_json(k)::text from api_keys k")
    for secret in secrets:
        assert all(secret not in row[0] for row in raw)
    assert sql("select bool_and(extract(epoch from expires_at-created_at) between 28799 and 28801) from web_sessions where created_at>clock_timestamp()-interval '1 hour'")==[(True,)]
    receipts["hash_only_absolute_eight_hours"]=True
    jar,csrf=login()
    old_hash=token_hash(jar)
    before=sql("select expires_at from web_sessions where token_hash=%s",(old_hash,))
    jar,unused=challenge(jar)
    assert sql("select expires_at from web_sessions where token_hash=%s",(old_hash,))==before
    sql("""update web_sessions set created_at=clock_timestamp()-interval '9 hours',
        expires_at=clock_timestamp()-interval '1 hour' where token_hash=%s""",(old_hash,))
    del jar["__Host-xotero-session"]
    jar,csrf=login(jar)
    assert sql("""select s.revoked_at is not null,k.revoked_at is not null from web_sessions s
        join api_keys k on k.id=s.api_key_id where s.token_hash=%s""",(old_hash,))==[(True,True)]
    assert logout(jar,csrf)==204
    receipts["expired_cookie_retained_browser_relogin"]=True
    jar,csrf=login()
    retained={k:v for k,v in jar.items() if k!="__Host-xotero-session"}
    retained,challenge_csrf=challenge(retained)
    before=sql("select count(*) from api_keys")[0][0]
    assert request("POST","/xotero/web/session",retained,challenge_csrf)[0]==403
    assert sql("select count(*) from api_keys")[0][0]==before
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        with connect() as blocker:
            blocker.execute("select id from library where id=1 for update")
            future=executor.submit(request,"POST","/xotero/web/session",retained,challenge_csrf)
            wait_edge(blocker.info.backend_pid)
            blocker.execute("""update web_sessions set created_at=clock_timestamp()-interval '9 hours',
                expires_at=clock_timestamp()-interval '1 hour' where token_hash=%s""",(token_hash(jar),))
            blocker.commit()
            assert future.result(timeout=25)[0]==200
    receipts["live_cookie_required_expiry_after_wait_relogin"]=True
    # UUIDs are generated server-side and correlate exact safe durable events.
    jar,csrf=challenge()
    baseline=sql("select coalesce(max(id),0) from audit_events")[0][0]
    assert request("POST","/xotero/web/session",jar,csrf,user="unknown")[0]==403
    denied=sql("""select actor_user_id,subject_user_id,action::text,outcome::text,
        request_id::text,occurred_at is not null from audit_events where id>%s""",(baseline,))
    assert len(denied)==1 and denied[0][:4]==(None,None,"web.login","denied") and denied[0][5]
    status,body,headers=request("POST","/xotero/web/session",jar,csrf)
    assert status==200
    issued=sql("""select actor_user_id,subject_user_id,action::text,outcome::text,
        request_id::text from audit_events where id>%s order by id""",(baseline,))
    assert issued[1][:4]==(101,101,"web.login","success") and issued[0][4]!=issued[1][4]
    jar["__Host-xotero-session"]=headers["Set-Cookie"].split(";",1)[0].split("=",1)[1]
    csrf=json.loads(body)["csrfToken"]
    with connect(autocommit=True) as ddl:
        ddl.execute("""create function checkpoint14_audit_fail() returns trigger language plpgsql as
            $$begin raise exception 'private-audit-failure-must-not-log'; end$$""")
        ddl.execute("create trigger checkpoint14_audit_fail before insert on audit_events for each row execute function checkpoint14_audit_fail()")
    assert logout(jar,csrf)==500
    assert sql("""select s.revoked_at,k.revoked_at from web_sessions s join api_keys k on k.id=s.api_key_id
        where s.token_hash=%s""",(token_hash(jar),))==[(None,None)]
    failed_jar,failed_csrf=challenge()
    before=sql("select count(*) from api_keys")[0][0]
    assert request("POST","/xotero/web/session",failed_jar,failed_csrf)[0]==500
    assert sql("select count(*) from api_keys")[0][0]==before
    with connect(autocommit=True) as ddl:
        ddl.execute("drop trigger checkpoint14_audit_fail on audit_events")
        ddl.execute("drop function checkpoint14_audit_fail()")
    assert logout(jar,csrf)==204
    events=sql("""select actor_user_id,subject_user_id,action::text,outcome::text,request_id::text
        from audit_events where id>%s order by id""",(baseline,))
    assert events[-1][:4]==(101,101,"web.logout","success")
    assert len({row[4] for row in events})==len(events)
    secrets.append("private-audit-failure-must-not-log")
    receipts["uuid_bound_safe_audit_atomic_failure"]=True
    print("CHECKPOINT14_SESSIONS "+json.dumps(receipts,sort_keys=True),flush=True)
finally:
    if proxy is not None:
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(timeout=10)
        assert not proxy_thread.is_alive()
    if server is not None:
        if server.poll() is None:
            server.send_signal(signal.SIGINT)
        assert server.wait(timeout=15)==0
        logs=server.stdout.read().decode()
        assert all(secret not in logs for secret in secrets)
    subprocess.run(["sudo","-u","postgres","dropdb",database],check=True)
    print("CHECKPOINT14_CLEANUP "+json.dumps({"database":database,"server":None if server is None else server.pid}),flush=True)
'''
print(machine.succeed("python3 -u -c " + shlex.quote(web_script)))
