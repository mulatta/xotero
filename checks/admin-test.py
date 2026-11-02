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
    upgrade18=database("keys_upgrade18")
    subprocess.run(["env","DATABASE_URL=postgres://xotero@127.0.0.1/"+upgrade18,
        "sqlx","migrate","run","--source","/etc/xotero-test/v18-migrations"],check=True)
    with connect(upgrade18) as fixture:
        fixture.execute("insert into users(id,username,display_name) values(101,'owner','Owner')")
        fixture.execute("insert into personal_libraries(user_id,library_id) values(101,1)")
        fixture.execute("insert into external_identities(issuer,subject,user_id) values('https://id.example.test','owner',101)")
        fixture.execute("insert into instance_admins(user_id) values(101)")
        fixture.execute("insert into bootstrap_state(name) values('identity'),('instance-admin')")
        fixture.execute("""insert into api_keys(id,user_id,name,token_hash) values
            (401,101,'Preserved API',decode(repeat('44',32),'hex')),
            (402,101,'Preserved Web',decode(repeat('55',32),'hex'))""")
        fixture.execute("""insert into api_key_user_permissions(api_key_id,library,notes,write,files)
            values(401,true,false,false,true),(402,true,true,true,true)""")
        fixture.execute("insert into api_key_all_groups_permissions(api_key_id,library,write) values(401,true,false)")
        fixture.execute("insert into library(id,version,kind) values(88,9,'group')")
        fixture.execute("insert into groups(id,library_id,owner_user_id,name) values(808,88,101,'Preserved key group')")
        fixture.execute("insert into group_memberships(group_id,user_id,role) values(808,101,'owner')")
        fixture.execute("""insert into api_key_group_permissions(api_key_id,user_id,group_id,library,write)
            values(401,101,808,true,true)""")
        fixture.execute("""insert into web_sessions(token_hash,browser_hash,csrf_hash,origin,
            user_id,library_id,issuer,subject,api_key_id) values(
            decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),
            'https://library.example.test',101,1,'https://id.example.test','owner',402)""")
    snapshot18="""select jsonb_build_array(
        (select jsonb_agg(to_jsonb(k) order by id) from api_keys k),
        (select jsonb_agg(to_jsonb(p) order by api_key_id) from api_key_user_permissions p),
        (select jsonb_agg(to_jsonb(p) order by api_key_id) from api_key_all_groups_permissions p),
        (select jsonb_agg(to_jsonb(p)-'policy_limited' order by api_key_id,group_id) from api_key_group_permissions p),
        (select jsonb_agg(to_jsonb(s) order by token_hash) from web_sessions s),
        (select jsonb_agg(to_jsonb(e) order by issuer,subject) from external_identities e),
        (select jsonb_agg(to_jsonb(m) order by group_id,user_id) from group_memberships m))"""
    saved18=sql(upgrade18,snapshot18)
    checksums18=sql(upgrade18,"select version,checksum from _sqlx_migrations order by version")
    start(upgrade18)
    assert sql(upgrade18,snapshot18)==saved18
    assert sql(upgrade18,"select version,checksum from _sqlx_migrations where version<=18 order by version")==checksums18
    assert sql(upgrade18,"select policy_limited from api_key_group_permissions")==[(False,)]
    assert sql(upgrade18,"select max(version) from _sqlx_migrations")==[(21,)]
    print("CHECKPOINT16_UPGRADE "+json.dumps({"from":18,"to":21,"preserved_keys":2,
        "preserved_sessions":1,"preserved_personal_permissions":2,
        "preserved_all_group_permissions":1,"preserved_explicit_permissions":1,
        "legacy_explicit_policy_limited":False,"checksums_preserved":True}),flush=True)
    upgrade19=database("groups_upgrade19")
    subprocess.run(["env","DATABASE_URL=postgres://xotero@127.0.0.1/"+upgrade19,
        "sqlx","migrate","run","--source","/etc/xotero-test/v19-migrations"],check=True)
    with connect(upgrade19) as fixture:
        fixture.execute("insert into users(id,username,display_name) values(101,'owner','Owner')")
        fixture.execute("insert into personal_libraries(user_id,library_id) values(101,1)")
        fixture.execute("insert into external_identities(issuer,subject,user_id) values('https://id.example.test','owner',101)")
        fixture.execute("insert into bootstrap_state(name) values('identity'),('instance-admin')")
        fixture.execute("insert into instance_admins(user_id) values(101)")
        fixture.execute("insert into library(id,version,kind) values(91,23,'group')")
        fixture.execute("insert into groups(id,library_id,owner_user_id,name,version) values(901,91,101,'Preserved nineteen',13)")
        fixture.execute("insert into group_memberships(group_id,user_id,role) values(901,101,'owner')")
        fixture.execute("""insert into api_keys(id,user_id,name,token_hash)
            values(401,101,'Nineteen key',decode(repeat('44',32),'hex'))""")
        fixture.execute("insert into api_key_group_permissions(api_key_id,user_id,group_id,library,write,policy_limited) values(401,101,901,true,true,true)")
        fixture.execute("""insert into pending_uploads(token_hash,library_id,group_id,authorizer_key_hash,
            item_key,blob_key,md5,upload_md5,filename,filesize,mtime,state) values
            (decode(repeat('77',32),'hex'),91,901,decode(repeat('44',32),'hex'),
            'PEND2222','libraries/91/uploads/upgrade19','hash','hash','private.txt',4,1,'uploaded')""")
        fixture.execute("select xotero_append_audit(101,101,'keys.create','success',gen_random_uuid())")
        fixture.execute("select setval(pg_get_serial_sequence('groups','id'),1900,true)")
    tables19=("users","library","personal_libraries","external_identities","instance_admins",
        "bootstrap_state","groups","group_memberships","api_keys","api_key_group_permissions",
        "pending_uploads","audit_events")
    saved19={table:sql(upgrade19,"select jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text) from "+table+" t")
        for table in tables19}
    last_audit19=sql(upgrade19,"select max(id) from audit_events")[0][0]
    checksums19=sql(upgrade19,"select version,checksum from _sqlx_migrations order by version")
    start(upgrade19)
    for table in tables19:
        value="to_jsonb(t)-'subject_group_id'" if table=="audit_events" else "to_jsonb(t)"
        old_rows=" where id<="+str(last_audit19) if table=="audit_events" else ""
        assert sql(upgrade19,"select jsonb_agg("+value+" order by ("+value+")::text) from "+table+" t"+old_rows)==saved19[table],table
    assert sql(upgrade19,"select subject_group_id from audit_events where id<=%s",(last_audit19,))==[(None,)]
    assert sql(upgrade19,"select policy_limited from api_key_group_permissions")==[(True,)]
    assert sql(upgrade19,"select version,checksum from _sqlx_migrations where version<=19 order by version")==checksums19
    assert sql(upgrade19,"select nextval(pg_get_serial_sequence('groups','id'))")==[(1901,)]
    print("CHECKPOINT17_UPGRADE "+json.dumps({"from":19,"to":21,"all_old_fields_preserved":True,
        "pending_uploaded_receipt_preserved":True,"sequence_high_water_preserved":True,
        "new_audit_subject_default":None,"checksums_preserved":True}),flush=True)
    upgrade20=database("transitions_upgrade20")
    subprocess.run(["env","DATABASE_URL=postgres://xotero@127.0.0.1/"+upgrade20,
        "sqlx","migrate","run","--source","/etc/xotero-test/v20-migrations"],check=True)
    with connect(upgrade20) as fixture:
        fixture.execute("insert into users(id,username,display_name) values(101,'owner','Owner'),(202,'member','Member')")
        fixture.execute("insert into personal_libraries(user_id,library_id) values(101,1)")
        fixture.execute("insert into external_identities(issuer,subject,user_id) values('https://id.example.test','owner',101)")
        fixture.execute("insert into bootstrap_state(name) values('identity'),('instance-admin')")
        fixture.execute("insert into instance_admins(user_id) values(101)")
        fixture.execute("insert into library(id,version,kind) values(92,27,'group')")
        fixture.execute("insert into groups(id,library_id,owner_user_id,name,version) values(902,92,101,'Preserved twenty',19)")
        fixture.execute("insert into group_memberships(group_id,user_id,role) values(902,101,'owner'),(902,202,'member')")
        fixture.execute("insert into api_keys(id,user_id,name,token_hash) values(402,202,'Twenty key',decode(repeat('45',32),'hex'))")
        fixture.execute("insert into api_key_group_permissions(api_key_id,user_id,group_id,library,write,policy_limited) values(402,202,902,true,true,true)")
        fixture.execute("insert into api_key_all_groups_permissions(api_key_id,library,write) values(402,true,true)")
        fixture.execute("select xotero_append_audit(101,202,'groups.update','success',gen_random_uuid())")
    tables20=(*tables19,"api_key_all_groups_permissions")
    saved20={table:sql(upgrade20,"select jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text) from "+table+" t")
        for table in tables20}
    last_audit20=sql(upgrade20,"select max(id) from audit_events")[0][0]
    checksums20=sql(upgrade20,"select version,checksum from _sqlx_migrations order by version")
    start(upgrade20)
    for table in tables20:
        old_rows=" where id<="+str(last_audit20) if table=="audit_events" else ""
        assert sql(upgrade20,"select jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text) from "+table+" t"+old_rows)==saved20[table],table
    assert sql(upgrade20,"select version,checksum from _sqlx_migrations where version<=20 order by version")==checksums20
    assert sql(upgrade20,"select max(version) from _sqlx_migrations")==[(21,)]
    print("CHECKPOINT18_UPGRADE "+json.dumps({"from":20,"to":21,"all_populated_rows_preserved":True,
        "checksums_preserved":True,"owner_fk_and_unique_index_unchanged":True}),flush=True)
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
import socket
import urllib.parse

import psycopg

database = "checkpoint14_web"
print("CHECKPOINT14_RESOURCES "+json.dumps({"database":database,"pid":os.getpid()}),flush=True)
server = None
server_output = bytearray()
server_log_thread = None
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
    def do_PATCH(self):
        self.forward()
    def do_PUT(self):
        self.forward()
    def do_DELETE(self):
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
            "Bearer fixture-provisioned-auth": "provisioned",
        }.get(self.headers.get("Authorization"))
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=20)) as backend:
            backend.putrequest(self.command,self.path)
            for name,value in self.headers.items():
                if name.lower() not in ("host","connection","content-length","authorization",
                    "x-xotero-oidc-issuer","x-xotero-oidc-subject"):
                    backend.putheader(name,value)
            if identity is not None:
                backend.putheader("X-Xotero-OIDC-Issuer","https://id.example.test")
                backend.putheader("X-Xotero-OIDC-Subject",identity)
            backend.putheader("Content-Length", str(len(body)))
            backend.endheaders(body)
            response=backend.getresponse()
            body=response.read()
            self.send_response(response.status)
            for name,value in response.getheaders():
                if name.lower() not in ("connection","transfer-encoding","content-length"):
                    self.send_header(name,value)
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)

def request(method,path,cookies=None,csrf=None,user="owner",request_origin=origin,extra=(),body=None):
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
        payload = b"" if body is None else json.dumps(body).encode()
        client.putheader("Content-Type", "application/json")
        client.putheader("Content-Length", str(len(payload)))
        client.endheaders(payload)
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

def login(cookies=None,user="owner",user_id=101):
    jar,csrf=challenge(cookies)
    status,body,headers=request("POST","/xotero/web/session",jar,csrf,user=user)
    assert status==200,(status,body)
    result=json.loads(body)
    assert set(result)=={"csrfToken","userID"} and result["userID"]==user_id,result
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
        (select jsonb_agg(to_jsonb(a)-'subject_key_id'-'subject_group_id' order by id) from audit_events a where id<=1),
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
        "XOTERO_API_KEY":"fixture-admin-recovery",
    }
    server=subprocess.Popen(["xotero"],env=environment,stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,bufsize=0)
    with selectors.DefaultSelector() as observer:
        observer.register(server.stdout,selectors.EVENT_READ)
        while True:
            assert observer.select(45),"startup timeout"
            line=server.stdout.readline()
            assert line,server.poll()
            server_output.extend(line)
            if b"xotero listening" in line:
                break
    def drain_server_log():
        # Real HTTP/race coverage emits more than a pipe buffer of diagnostics.
        # Drain continuously so log backpressure cannot masquerade as API hangs.
        while chunk := server.stdout.read(65536):
            server_output.extend(chunk)
    server_log_thread=threading.Thread(target=drain_server_log)
    server_log_thread.start()
    proxy=http.server.ThreadingHTTPServer(("127.0.0.1",0),Proxy)
    proxy_thread=threading.Thread(target=proxy.serve_forever)
    proxy_thread.start()
    print("CHECKPOINT14_PROXY "+json.dumps({"port":proxy.server_port,"backend":8189}),flush=True)
    assert sql(v16_snapshot)==preserved
    assert sql("select version,checksum from _sqlx_migrations where version<=16 order by version")==v16_checksums
    assert sql("select max(version) from _sqlx_migrations")==[(21,)]
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
    # Given a live mapped instance-admin session, provision through supported API.
    jar,csrf=login()
    status,body,headers=request("POST","/xotero/admin/users",jar,csrf,body={
        "username":"provisioned","displayName":"Provisioned",
        "issuer":"https://id.example.test","subject":"provisioned",
    })
    assert status==201,("checkpoint15 supported admin user create",status,body)
    created=json.loads(body)
    assert set(created)=={"userID","libraryID"}
    assert created["userID"]>0 and created["libraryID"]!=1
    assert sql("select library_id from personal_libraries where user_id=%s",
        (created["userID"],))==[(created["libraryID"],)]
    receipts["supported_admin_user_create"]=True
    admin_receipts = {"api_provisioned_isolated_library": True}
    target=created["userID"]
    target_path="/xotero/admin/users/"+str(target)
    identity={"issuer":"https://id.example.test","subject":"provisioned"}
    extra_identity={"issuer":"https://id.example.test","subject":"second-exact-identity"}
    ordinary,ordinary_csrf=login(user="provisioned",user_id=target)

    # Given an ordinary mapped session, issue a named, explicitly narrowed key.
    key_scope={"user":{"library":True,"notes":False,"write":False,"files":False},
               "groups":{"all":{"library":False,"write":False},"individual":[]}}
    status,body,headers=request("POST","/xotero/me/keys",ordinary,ordinary_csrf,
        body={"name":"Checkpoint16 read only","access":key_scope})
    assert status==201,("checkpoint16 supported ordinary key issuance",status,body)
    managed_key=json.loads(body)
    assert set(managed_key)=={"id","name","createdAt","revokedAt","access","token"}
    assert managed_key["access"]==key_scope and len(managed_key["token"])==64
    secrets.append(managed_key["token"])
    key_receipts={}
    def key_api(method,path="/xotero/me/keys",payload=None,credential=None,
                cookies=ordinary,token=ordinary_csrf):
        headers=[] if credential is None else [("Zotero-API-Key",credential)]
        if method=="POST" and path=="/groups/707/items":
            # These empty-batch permission probes preserve seeded version zero.
            headers.append(("If-Unmodified-Since-Version","0"))
        return request(method,path,cookies if credential is None else None,
            token if credential is None else None,body=payload,
            extra=headers)

    def mint(scope,name="Scoped child",credential=None,cookies=ordinary,token=ordinary_csrf):
        status,body,_=key_api("POST",payload={"name":name,"access":scope},
            credential=credential,cookies=cookies,token=token)
        assert status==201,(status,body)
        result=json.loads(body)
        secrets.append(result["token"])
        return result

    assert sql("select token_hash from api_keys where id=%s",(managed_key["id"],))==[
        (hashlib.sha256(managed_key["token"].encode()).digest(),)]
    for path,cookies,token in (("/xotero/me/keys",ordinary,ordinary_csrf),
            (target_path+"/keys",jar,csrf)):
        status,body,headers=key_api("GET",path,cookies=cookies,token=token)
        assert status==200 and headers["Cache-Control"]=="no-store",(status,body)
        listed=json.loads(body)
        assert all(set(row)=={"id","name","createdAt","revokedAt","access"} for row in listed)
        assert managed_key["id"] in [row["id"] for row in listed]
        assert not set(row["id"] for row in listed).intersection(
            row[0] for row in sql("select api_key_id from web_sessions"))
        assert managed_key["token"].encode() not in body
        assert hashlib.sha256(managed_key["token"].encode()).hexdigest().encode() not in body
    assert key_api("GET",credential=managed_key["token"])[0]==200
    assert key_api("GET","/users/"+str(target)+"/items",credential=managed_key["token"])[0]==200
    assert key_api("GET","/users/101/items",credential=managed_key["token"])[0]==403
    assert request("GET","/users/"+str(target)+"/items",ordinary,ordinary_csrf)[0]==403
    child=mint(key_scope,credential=managed_key["token"])
    for payload in ({},{"name":"Missing scope"},{"name":"Missing groups","access":{"user":key_scope["user"]}},
                    {"name":"Null","access":None},{"name":"Unknown","access":key_scope,"userID":101}):
        assert key_api("POST",payload=payload,credential=managed_key["token"])[0]==400
    widened=json.loads(json.dumps(key_scope))
    widened["user"]["write"]=True
    stronger=mint(widened,name="Unrelated stronger same-user key")
    assert key_api("POST",payload={"name":"Widen","access":widened},
        credential=managed_key["token"])[0]==403
    assert key_api("GET","/keys/current",credential=stronger["token"])[0]==200
    for path in ("/xotero/me/keys",target_path+"/keys"):
        assert request("GET",path,extra=[("Zotero-API-Key","fixture-admin-recovery")])[0] in (401,403)
    assert request("DELETE","/keys/current",extra=[("Zotero-API-Key","fixture-admin-recovery")])[0]==403
    assert request("DELETE","/keys/current",ordinary,ordinary_csrf)[0]==401
    assert key_api("GET",target_path+"/keys",credential=managed_key["token"])[0]==401
    assert key_api("GET","/xotero/admin/users/101/keys")[0]==403
    own=mint(key_scope,cookies=jar,token=csrf)
    assert key_api("DELETE","/xotero/me/keys/"+str(own["id"]))[0]==404
    assert key_api("DELETE","/xotero/me/keys/"+str(child["id"]))[0]==204
    assert key_api("DELETE","/xotero/me/keys/"+str(child["id"]))[0]==204
    assert key_api("GET","/keys/current",credential=child["token"])[0]==403
    assert key_api("DELETE","/keys/current",credential=managed_key["token"])[0]==204
    assert key_api("GET","/keys/current",credential=managed_key["token"])[0]==403
    key_receipts["supported_named_narrowed_issue_metadata_cross_user_readonly_self_revoke"]=True

    # Group policy is a fixture until checkpoints 17/18; issuance is always HTTP.
    sql("insert into library(id,version,kind) values(77,0,'group')")
    with connect() as fixture:
        fixture.execute("""insert into groups(id,library_id,owner_user_id,name)
            values(707,77,101,'Key scope fixture')""")
        fixture.execute("""insert into group_memberships(group_id,user_id,role)
            values(707,101,'owner'),(707,%s,'member')""",(target,))
    empty={"user":{"library":False,"notes":False,"write":False,"files":False},
           "groups":{"all":{"library":False,"write":False},"individual":[]}}
    wildcard=json.loads(json.dumps(empty))
    wildcard["groups"]["all"]={"library":True,"write":True}
    all_key=mint(wildcard)
    individual=json.loads(json.dumps(empty))
    individual["groups"]["individual"]=[{"groupID":707,"library":True,"write":True}]
    member_explicit=mint(individual)
    assert key_api("POST","/groups/707/items",[],credential=member_explicit["token"])[0]==200
    before=(sql("select count(*) from api_keys"),
        sql("select count(*) from api_key_user_permissions"),
        sql("select count(*) from api_key_all_groups_permissions"),
        sql("select count(*) from api_key_group_permissions"))
    baseline=sql("select coalesce(max(id),0) from audit_events")[0][0]
    rejected=key_api("POST",payload={"name":"Policy escape","access":individual},
        credential=all_key["token"])
    assert rejected[0]==403 and b"token" not in rejected[1],rejected[:2]
    assert (sql("select count(*) from api_keys"),
        sql("select count(*) from api_key_user_permissions"),
        sql("select count(*) from api_key_all_groups_permissions"),
        sql("select count(*) from api_key_group_permissions"))==before
    assert sql("""select actor_user_id,subject_user_id,action::text,outcome::text
        from audit_events where id>%s""",(baseline,))==[(target,target,"keys.create","denied")]
    individual["groups"]["individual"][0]["write"]=False
    explicit_key=mint(individual,credential=all_key["token"])
    assert key_api("POST",payload={"name":"Future groups","access":wildcard},
        credential=explicit_key["token"])[0]==403
    assert key_api("GET","/groups/707/items",credential=explicit_key["token"])[0]==200
    assert key_api("POST","/groups/707/items",[],credential=all_key["token"])[0]==200
    sql("update groups set library_editing='admins' where id=707")
    assert key_api("POST","/groups/707/items",[],credential=all_key["token"])[0]==403
    assert key_api("POST","/groups/707/items",[],credential=member_explicit["token"])[0]==403
    individual["groups"]["individual"][0]["write"]=True
    assert key_api("POST",payload={"name":"Current policy escape","access":individual},
        credential=all_key["token"])[0]==403
    assert key_api("POST",payload={"name":"Session policy escape","access":individual})[0]==403
    explicit_owner=mint(individual,cookies=jar,token=csrf)
    inherited_explicit=mint(individual,credential=explicit_owner["token"])
    assert key_api("POST","/groups/707/items",[],credential=inherited_explicit["token"])[0]==200
    assert key_api("POST","/groups/707/items",[],credential=explicit_owner["token"])[0]==200
    with connect() as fixture:
        fixture.execute("update group_memberships set role='member' where group_id=707 and user_id=101")
        fixture.execute("insert into group_memberships(group_id,user_id,role) values(707,202,'owner')")
        fixture.execute("update groups set owner_user_id=202 where id=707")
    assert key_api("POST","/groups/707/items",[],credential=explicit_owner["token"])[0]==403
    assert key_api("POST","/groups/707/items",[],credential=inherited_explicit["token"])[0]==403
    sql("delete from group_memberships where group_id=707 and user_id=%s",(target,))
    assert key_api("GET","/groups/707/items",credential=explicit_key["token"])[0]==403
    assert key_api("POST",payload={"name":"Removed membership","access":individual})[0]==403
    key_receipts["no_omission_wildcard_future_membership_or_policy_escape"]=True

    # Every expected outcome has one secret-free, request-correlated audit.
    correlations=[]
    for method,path,payload,cookies,token,status,outcome in (
        ("GET",target_path+"/keys",None,jar,csrf,200,"success"),
        ("DELETE",target_path+"/keys/"+str(all_key["id"]),None,jar,csrf,204,"success"),
        ("DELETE",target_path+"/keys/"+str(all_key["id"]),None,jar,csrf,204,"noop"),
        ("DELETE",target_path+"/keys/999999",None,jar,csrf,404,"denied"),
        ("POST","/xotero/me/keys",{"name":"Omitted"},ordinary,ordinary_csrf,400,"denied"),
    ):
        baseline=sql("select coalesce(max(id),0) from audit_events")[0][0]
        result=key_api(method,path,payload,cookies=cookies,token=token)
        assert result[0]==status,(result,status)
        events=sql("""select action::text,outcome::text,request_id::text,subject_key_id
            from audit_events where id>%s""",(baseline,))
        assert len(events)==1 and events[0][1]==outcome,events
        assert events[0][0].startswith("keys.")
        correlations.append(events[0][2])
    assert len(set(correlations))==len(correlations)
    survivor=mint(key_scope)
    with connect(autocommit=True) as ddl:
        ddl.execute("""create function checkpoint16_audit_fail() returns trigger language plpgsql as
            $$begin raise exception 'private-key-audit-failure'; end$$""")
        ddl.execute("create trigger checkpoint16_audit_fail before insert on audit_events for each row execute function checkpoint16_audit_fail()")
    before=sql("select count(*) from api_keys"),sql("select count(*) from audit_events")
    assert key_api("POST",payload={"name":"Rollback","access":key_scope})[0]==500
    assert key_api("DELETE","/xotero/me/keys/"+str(survivor["id"]))[0]==500
    assert (sql("select count(*) from api_keys"),sql("select count(*) from audit_events"))==before
    assert sql("select revoked_at from api_keys where id=%s",(survivor["id"],))==[(None,)]
    with connect(autocommit=True) as ddl:
        ddl.execute("drop trigger checkpoint16_audit_fail on audit_events")
        ddl.execute("drop function checkpoint16_audit_fail()")
    secrets.append("private-key-audit-failure")
    key_receipts["audit_exact_counts_correlation_noop_missing_and_atomic_rollback"]=True
    # Body stays incomplete: invalid authority must be rejected without a poll.
    for credential,cookies,token,expected in (
        (None,{},None,401),(None,ordinary,"0"*64,403),
        ("fixture-admin-recovery",{},None,403),("unknown-key",{},None,401),
    ):
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=5)) as client:
            client.putrequest("POST","/xotero/me/keys")
            client.putheader("Content-Length","1048576")
            client.putheader("Origin",origin)
            if cookies:
                client.putheader("Cookie","; ".join(k+"="+v for k,v in cookies.items()))
            if token is not None:
                client.putheader("X-Xotero-CSRF",token)
            if credential is not None:
                client.putheader("Zotero-API-Key",credential)
            client.endheaders()
            response=client.getresponse()
            assert response.status==expected,(response.status,expected)
            response.read()
    key_receipts["prebody_session_csrf_recovery_and_invalid_key_denial"]=True

    # Prove live ordinary-session revocation and admin role revalidation after
    # actual library-row waits. The response cannot borrow the discovered user.
    key_races=[]
    for mutation in ("session","key","mapping","disabled","association","role"):
        race_jar,race_csrf=login(user="provisioned",user_id=target) if mutation!="role" else login()
        actor=target if mutation!="role" else 101
        library=created["libraryID"] if mutation!="role" else 1
        route="/xotero/me/keys" if mutation!="role" else target_path+"/keys"
        before=sql("select count(*) from api_keys")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with connect() as blocker:
                blocker.execute("select id from library where id=%s for update",(library,))
                future=executor.submit(key_api,"GET",route,None,None,race_jar,race_csrf)
                wait_edge(blocker.info.backend_pid)
                edges=sql("""select pid,%s=any(pg_blocking_pids(pid)) from pg_stat_activity
                    where %s=any(pg_blocking_pids(pid))""",
                    (blocker.info.backend_pid,blocker.info.backend_pid))
                match mutation:
                    case "session":
                        blocker.execute("update web_sessions set revoked_at=clock_timestamp() where token_hash=%s",(token_hash(race_jar),))
                    case "key":
                        blocker.execute("""update api_keys set revoked_at=clock_timestamp() where id=
                            (select api_key_id from web_sessions where token_hash=%s)""",(token_hash(race_jar),))
                    case "mapping":
                        blocker.execute("update external_identities set user_id=202 where subject='provisioned'")
                    case "disabled":
                        blocker.execute("update users set disabled_at=clock_timestamp() where id=%s",(actor,))
                    case "association":
                        blocker.execute("update web_sessions set api_key_id=%s where token_hash=%s",
                            (survivor["id"],token_hash(race_jar)))
                    case "role":
                        blocker.execute("delete from instance_admins where user_id=101")
                blocker.commit()
                result=future.result(timeout=25)
                assert result[0]==(403 if mutation=="role" else 401),(mutation,result)
                key_races.append({"case":mutation,"blocker":blocker.info.backend_pid,
                    "contenders":edges,"status":result[0]})
        assert sql("select count(*) from api_keys")==before
        sql("update users set disabled_at=null where id=%s",(actor,))
        sql("update external_identities set user_id=%s where subject='provisioned'",(target,))
        sql("insert into instance_admins(user_id) values(101) on conflict do nothing")
    # Association fixture deliberately turned survivor into an internal key:
    # metadata/revocation must now hide it, not follow or expose its binding.
    assert key_api("DELETE","/xotero/me/keys/"+str(survivor["id"]))[0]==404
    key_receipts["live_session_key_identity_disable_association_and_admin_role_races"]=key_races
    # Admission commits while body is withheld. Supported logout then wins
    # before final issuance authorization, without polling/sleeping in the test.
    race_jar,race_csrf=login(user="provisioned",user_id=target)
    payload=json.dumps({"name":"After logout","access":key_scope}).encode()
    before=sql("select count(*) from api_keys")
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=20)) as client:
        with connect() as blocker:
            blocker.execute("select id from library where id=%s for update",(created["libraryID"],))
            client.putrequest("POST","/xotero/me/keys")
            client.putheader("Content-Length",str(len(payload)))
            client.putheader("Content-Type","application/json")
            client.putheader("Cookie","; ".join(k+"="+v for k,v in race_jar.items()))
            client.putheader("Origin",origin)
            client.putheader("X-Xotero-CSRF",race_csrf)
            client.endheaders()
            wait_edge(blocker.info.backend_pid)
            admission_pid=sql("select pid from pg_stat_activity where %s=any(pg_blocking_pids(pid))",
                (blocker.info.backend_pid,))[0][0]
            blocker.commit()
        with connect(autocommit=True) as observer:
            observer.execute("""do $$declare deadline timestamptz:=clock_timestamp()+interval '10 seconds';
                begin loop exit when exists(select 1 from pg_stat_activity where pid="""+str(admission_pid)+"""
                and state='idle' and query='COMMIT');
                if clock_timestamp()>deadline then raise exception 'key admission did not commit'; end if;
                perform pg_stat_clear_snapshot(); end loop; end$$""")
        assert logout(race_jar,race_csrf)==204
        client.send(payload)
        response=client.getresponse()
        assert response.status==401,response.status
        response.read()
    assert sql("select count(*) from api_keys")==before
    key_receipts["supported_logout_between_admission_and_body"]=True
    print("CHECKPOINT16_KEYS "+json.dumps(key_receipts,sort_keys=True),flush=True)

    # Given a mapped ordinary session, group creation is a supported extension
    # API rather than an upstream XML mutation or a direct SQL action.
    subprocess.run(["curl","--fail-with-body","--silent","--show-error",
        "--max-time","20","--aws-sigv4","aws:amz:us-east-1:s3",
        "--user","rustfsadmin:rustfsadmin","-X","PUT","http://127.0.0.1:9000/zotero"],
        check=True)
    group_owner,group_owner_csrf=login(user="provisioned",user_id=target)
    status,body,_=request("POST","/xotero/groups",group_owner,group_owner_csrf,
        body={"name":"Membership transitions"})
    assert status==201,(status,body)
    transition_group=json.loads(body)
    transition_path="/xotero/groups/"+str(transition_group["groupID"])
    status,body,_=request("PUT",transition_path+"/members/202",group_owner,group_owner_csrf,
        body={"role":"member"},extra=[("If-Match",'"1"')])
    assert status==204,("checkpoint18 supported membership PUT",status,body)
    assert sql("select user_id,role from group_memberships where group_id=%s order by user_id",
        (transition_group["groupID"],))==sorted([(target,"owner"),(202,"member")])
    transition_gid=transition_group["groupID"]
    transition_lib=transition_group["libraryID"]
    transition_admin="/xotero/admin/groups/"+str(transition_gid)
    transition_member,transition_csrf=login(user="second",user_id=202)
    transition_roles=[]
    transition_races=[]

    # No request body byte is sent for these boundary denials.
    for cookies,token,supplied_origin,expected in (
        ({},None,origin,401),(transition_member,transition_csrf,origin,403),
        (group_owner,group_owner_csrf,None,403),(group_owner,"0"*64,origin,403),
    ):
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=5)) as client:
            client.putrequest("PUT",transition_path+"/members/202")
            client.putheader("Content-Length","1048576")
            client.putheader("If-Match",'"2"')
            client.putheader("Cookie","; ".join(k+"="+v for k,v in cookies.items()))
            if supplied_origin is not None:
                client.putheader("Origin",supplied_origin)
            if token is not None:
                client.putheader("X-Xotero-CSRF",token)
            client.endheaders()
            response=client.getresponse()
            assert response.status==expected,(response.status,expected)
            response.read()
    transition_races.append({"race":"prebody session role origin CSRF denials","statuses":[401,403,403,403]})

    def transition(method,suffix,payload=None,cookies=group_owner,token=group_owner_csrf,
                   expected=204,version=None,administrative=False):
        if version is None:
            version=sql("select version from groups where id=%s",(transition_gid,))[0][0]
        before=sql("select version from library where id=%s",(transition_lib,))
        metadata_before=sql("select version from groups where id=%s",(transition_gid,))[0][0]
        baseline=sql("select coalesce(max(id),0) from audit_events")[0][0]
        path=(transition_admin if administrative else transition_path)+suffix
        status,body,_=request(method,path,cookies,token,body=payload,
            extra=[("If-Match",'"'+str(version)+'"')])
        assert status==expected,(method,path,payload,status,expected,body)
        assert sql("select version from library where id=%s",(transition_lib,))==before
        events=sql("""select action::text,outcome::text,subject_user_id,subject_group_id
            from audit_events where id>%s order by id""",(baseline,))
        assert len(events)==1 and events[0][3]==transition_gid,events
        metadata_after=sql("select version from groups where id=%s",(transition_gid,))[0][0]
        assert metadata_after in (metadata_before,metadata_before+1)
        if status!=204:
            assert metadata_after==metadata_before
        expected_subject=None
        if suffix.startswith("/members/"):
            expected_subject=int(suffix.rsplit("/",1)[1])
        elif (status not in (401,403,412) and payload is not None and set(payload)=={"ownerUserID"}
                and type(payload["ownerUserID"]) is int and payload["ownerUserID"]>0):
            expected_subject=payload["ownerUserID"]
        expected_action="groups.transfer-owner" if suffix=="/owner" else (
            "groups.set-member" if method=="PUT" else "groups.remove-member")
        expected_outcome="denied" if status!=204 else (
            "noop" if metadata_after==metadata_before else "success")
        assert events[0]==(expected_action,expected_outcome,expected_subject,transition_gid),events
        transition_roles.append({"method":method,"path":path,"status":status,
            "audit":events[0],"metadata":sql("select version from groups where id=%s",(transition_gid,))[0][0]})
        return status

    # Strict role and owner input cannot alter membership or metadata.
    for payload in ({"role":{"admin":None}},{"role":{"member":None}},
                    {},{"role":None},{"role":"owner"},{"role":"ADMIN"},
                    {"role":"member","extra":True}):
        transition("PUT","/members/202",payload,expected=400)
    for payload in ({},{"ownerUserID":None},{"ownerUserID":0},{"ownerUserID":True},
                    {"ownerUserID":"202"},{"ownerUserID":202,"role":"owner"}):
        transition("POST","/owner",payload,expected=400)
    transition("DELETE","/members/202",{},expected=400)
    transition("PUT","/members/202",{"role":"member"})
    assert sql("select version from groups where id=%s",(transition_gid,))==[(2,)]
    transition("PUT","/members/202",{"role":"admin"},version=1,expected=412)
    transition("PUT","/members/"+str(target),{"role":"admin"},expected=409)
    transition("DELETE","/members/"+str(target),expected=409)
    transition("POST","/owner",{"ownerUserID":target})
    transition("POST","/owner",{"ownerUserID":101},expected=409)
    transition("PUT","/members/999999",{"role":"member"},expected=404)
    transition("POST","/owner",{"ownerUserID":999999},expected=404)
    for method,suffix,payload in (
        ("PUT","/members/101",{"role":"member"}),("DELETE","/members/202",None),
        ("POST","/owner",{"ownerUserID":202}),
    ):
        transition(method,suffix,payload,transition_member,transition_csrf,expected=403)
        transition(method,suffix,payload,jar,csrf,expected=403)
    transition("PUT","/members/202",{"role":"admin"})
    # Group administrator metadata authority is not membership authority.
    transition("PUT","/members/101",{"role":"member"},transition_member,transition_csrf,expected=403)
    transition("POST","/owner",{"ownerUserID":202},transition_member,transition_csrf,expected=403)
    transition("DELETE","/members/202",cookies=transition_member,token=transition_csrf,expected=403)
    sql("update users set disabled_at=clock_timestamp() where id=202")
    transition("PUT","/members/202",{"role":"member"},expected=409)
    transition("POST","/owner",{"ownerUserID":202},expected=409)
    sql("update users set disabled_at=null where id=202")
    transition("POST","/owner",{"ownerUserID":202})
    assert sql("select owner_user_id from groups where id=%s",(transition_gid,))==[(202,)]
    assert sql("select user_id,role from group_memberships where group_id=%s order by user_id",
        (transition_gid,))==sorted([(target,"admin"),(202,"owner")])
    transition("DELETE","/members/202",expected=403)
    transition("POST","/owner",{"ownerUserID":target},jar,csrf,administrative=True)
    transition("PUT","/members/202",{"role":"member"},jar,csrf,administrative=True)
    transition("DELETE","/members/101")
    transition("PUT","/members/101",{"role":"member"},jar,csrf,administrative=True)
    transition("DELETE","/members/101",cookies=jar,token=csrf,administrative=True)
    assert request("GET","/groups/"+str(transition_gid)+"/items",
        extra=[("Zotero-API-Key","fixture-admin-recovery")])[0]==403

    # An audit failure must roll back role and metadata together.
    before=sql("select version from groups where id=%s",(transition_gid,))
    with connect(autocommit=True) as ddl:
        ddl.execute("""create function checkpoint18_audit_fail() returns trigger language plpgsql as
            $$begin raise exception 'private-transition-audit-failure'; end$$""")
        ddl.execute("create trigger checkpoint18_audit_fail before insert on audit_events for each row execute function checkpoint18_audit_fail()")
    assert request("POST",transition_path+"/owner",group_owner,group_owner_csrf,
        body={"ownerUserID":202},extra=[("If-Match",'"'+str(before[0][0])+'"')])[0]==500
    assert sql("select version from groups where id=%s",(transition_gid,))==before
    assert sql("select owner_user_id from groups where id=%s",(transition_gid,))==[(target,)]
    with connect(autocommit=True) as ddl:
        ddl.execute("drop trigger checkpoint18_audit_fail on audit_events")
        ddl.execute("drop function checkpoint18_audit_fail()")
    secrets.append("private-transition-audit-failure")

    # Competing transitions observe the exact same group lock; only one stale
    # precondition can win, and the deferred owner FK holds at commit.
    version=before[0][0]
    race_audit=sql("select coalesce(max(id),0) from audit_events")[0][0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        with connect() as blocker:
            blocker.execute("select id from library where id=%s for update",(transition_lib,))
            futures=[
                executor.submit(request,"POST",transition_path+"/owner",group_owner,group_owner_csrf,
                    body={"ownerUserID":202},extra=[("If-Match",'"'+str(version)+'"')]),
                executor.submit(request,"DELETE",transition_path+"/members/202",group_owner,group_owner_csrf,
                    extra=[("If-Match",'"'+str(version)+'"')]),
            ]
            # PostgreSQL's tuple queue may place the second waiter behind the
            # first. Both must be observed in the exact blocker's lock graph.
            graph=f"""with recursive waiters(pid) as (
                select pid from pg_stat_activity where {blocker.info.backend_pid}=any(pg_blocking_pids(pid))
                union select a.pid from pg_stat_activity a join waiters w
                    on w.pid=any(pg_blocking_pids(a.pid))
                ) select a.pid,pg_blocking_pids(a.pid),a.query,a.wait_event_type
                from pg_stat_activity a join waiters w on a.pid=w.pid
                where a.datname=current_database()"""
            try:
                with connect(autocommit=True) as observer:
                    observer.execute("""do $$declare deadline timestamptz:=clock_timestamp()+interval '10 seconds';
                        begin loop
                        exit when (select count(*) from ("""+graph+""") edges
                            where query='select id from library where id=$1 for update' and wait_event_type='Lock')=2;
                        if clock_timestamp()>deadline then raise exception 'missing two transition library waiters'; end if;
                        perform pg_stat_clear_snapshot();
                        end loop; end$$""")
            finally:
                transition_edges=sql(graph)
                print("CHECKPOINT18_LOCK_GRAPH "+json.dumps({"blocker":blocker.info.backend_pid,
                    "library":transition_lib,"edges":transition_edges}),flush=True)
            assert len(transition_edges)==2,transition_edges
            blocker.commit()
            statuses=[future.result(timeout=25)[0] for future in futures]
    assert statuses.count(204)==1 and all(status in (204,409,412,403) for status in statuses),statuses
    assert sql("select version from groups where id=%s",(transition_gid,))==[(version+1,)]
    race_events=sql("""select action::text,outcome::text,subject_user_id,subject_group_id
        from audit_events where id>%s order by id""",(race_audit,))
    assert len(race_events)==2 and sorted(row[1] for row in race_events)==["denied","success"],race_events
    assert sql("""select count(*) from groups g join group_memberships m on m.group_id=g.id
        and m.user_id=g.owner_user_id and m.role='owner' join users u on u.id=m.user_id
        and u.disabled_at is null where g.id=%s""",(transition_gid,))==[(1,)]
    transition_races.append({"race":"transfer versus removal","statuses":statuses,
        "enabled_owners":1,"edges":transition_edges,"audit":race_events,"metadata":version+1})
    if sql("select owner_user_id from groups where id=%s",(transition_gid,))==[(202,)]:
        transition("POST","/owner",{"ownerUserID":target},jar,csrf,administrative=True)
    transition("PUT","/members/202",{"role":"member"})

    # Target disablement committed while add/transfer awaits the user's positive
    # SHARE lock wins; no timing or body-admission assumption.
    for method,suffix,payload in (
        ("PUT","/members/202",{"role":"admin"}),("POST","/owner",{"ownerUserID":202}),
    ):
        version=sql("select version from groups where id=%s",(transition_gid,))[0][0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with connect() as blocker:
                blocker.execute("select id from users where id=202 for update")
                future=executor.submit(request,method,transition_path+suffix,group_owner,group_owner_csrf,
                    body=payload,extra=[("If-Match",'"'+str(version)+'"')])
                wait_edge(blocker.info.backend_pid)
                blocker.execute("update users set disabled_at=clock_timestamp() where id=202")
                blocker.commit()
                assert future.result(timeout=25)[0]==409
        sql("update users set disabled_at=null where id=202")
        transition_races.append({"race":"target disablement","method":method,"status":409})

    # Removing one group must not revoke personal or other-group authority.
    transition_key=mint(wildcard,cookies=transition_member,token=transition_csrf)
    mixed18=json.loads(json.dumps(empty))
    mixed18["user"]={"library":True,"notes":False,"write":False,"files":False}
    mixed18["groups"]["individual"]=[
        {"groupID":transition_gid,"library":True,"write":True},
        {"groupID":707,"library":True,"write":True},
    ]
    explicit18=mint(mixed18,cookies=transition_member,token=transition_csrf)
    owner18=mint(wildcard,cookies=group_owner,token=group_owner_csrf)
    other_grant=sql("select to_jsonb(p) from api_key_group_permissions p where api_key_id=%s and group_id=707",
        (explicit18["id"],))
    def transition_data(method,suffix,body=b"",credential=owner18["token"],headers=None):
        fields={"Zotero-API-Key":credential,"Content-Type":"application/x-www-form-urlencoded"}
        fields.update(headers or {})
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=25)) as client:
            client.request(method,f"/groups/{transition_gid}/"+suffix,body,fields)
            response=client.getresponse()
            return response.status,response.read()

    status,body=transition_data("POST","items",
        json.dumps([{"key":"MEMBER22","itemType":"attachment","linkMode":"imported_file"}]),
        headers={"Content-Type":"application/json","If-Unmodified-Since-Version":"0"})
    assert status==200 and not json.loads(body)["failed"],(status,body)
    content=b"member original authorizer"
    status,body=transition_data("POST","items/MEMBER22/file",urllib.parse.urlencode({
        "md5":hashlib.md5(content).hexdigest(),"filename":"member.txt","filesize":len(content),"mtime":1}),
        explicit18["token"],{"If-None-Match":"*"})
    assert status==200,(status,body)
    upload18=json.loads(body)["uploadKey"]
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=25)) as client:
        client.request("POST","/uploads/"+upload18,content)
        response=client.getresponse()
        assert response.status==201,response.read()
        response.read()
    transition("DELETE","/members/202")
    for credential in (explicit18["token"],transition_key["token"]):
        assert transition_data("GET","items",credential=credential)[0]==403
    before=sql("select version from library where id=%s",(transition_lib,))
    assert transition_data("POST","items/MEMBER22/file",urllib.parse.urlencode({"upload":upload18}))[0]==403
    assert sql("select version from library where id=%s",(transition_lib,))==before
    assert sql("select count(*) from file where library_id=%s",(transition_lib,))==[(0,)]
    assert sql("select count(*) from api_key_group_permissions where api_key_id=%s and group_id=%s",
        (explicit18["id"],transition_gid))==[(0,)]
    assert sql("select to_jsonb(p) from api_key_group_permissions p where api_key_id=%s and group_id=707",
        (explicit18["id"],))==other_grant
    assert key_api("GET","/groups/707/items",credential=explicit18["token"])[0]==200
    assert key_api("GET","/users/202/items",credential=explicit18["token"])[0]==200
    assert sql("select revoked_at from api_keys where id=any(%s) order by id",
        ([explicit18["id"],transition_key["id"]],))==[(None,),(None,)]
    transition("PUT","/members/202",{"role":"member"})
    assert transition_data("GET","items",credential=explicit18["token"])[0]==403
    assert transition_data("GET","items",credential=transition_key["token"])[0]==200
    assert transition_data("POST","items/MEMBER22/file",urllib.parse.urlencode({"upload":upload18}))[0]==403
    transition_races.append({"race":"original explicit authorizer removed before alternate registration",
        "removed_registration":403,"readded_registration":403,"wildcard_readded":200,
        "explicit_readded":403,"mixed_other_scope":200,"file_rows":0})

    # Exact backend100 proves ordinary key admission happened before supported
    # removal. The shared MutationProof still denies the withheld write.
    payload=b'[{"key":"STALE822","itemType":"book","title":"Must not persist"}]'
    with socket.create_connection(("127.0.0.1",8189),timeout=20) as stream:
        stream.sendall((
            f"POST /groups/{transition_gid}/items HTTP/1.1\r\nHost: localhost\r\n"
            f"Zotero-API-Key: {transition_key['token']}\r\n"
            f"If-Unmodified-Since-Version: {before[0][0]}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
            "Expect: 100-continue\r\nConnection: close\r\n\r\n").encode())
        interim=b""
        while not interim.endswith(b"\r\n\r\n"):
            chunk=stream.recv(1)
            assert chunk,"connection ended before admission"
            interim+=chunk
        assert interim.startswith(b"HTTP/1.1 100 "),interim
        transition("DELETE","/members/202")
        stream.sendall(payload)
        response=http.client.HTTPResponse(stream)
        response.begin()
        assert response.status==403,response.status
        response.read()
    assert sql("select version from library where id=%s",(transition_lib,))==before
    assert sql("select count(*) from object where library_id=%s and key='STALE822'",(transition_lib,))==[(0,)]
    transition_races.append({"race":"ordinary write admission then supported member removal","admission":100,"status":403})
    transition("PUT","/members/202",{"role":"member"})

    # Revoke the session while the target membership lock is held. Its final
    # session read must follow that wait, not trust prebody admission.
    race_owner,race_token=login(user="provisioned",user_id=target)
    version=sql("select version from groups where id=%s",(transition_gid,))[0][0]
    payload=b'{"role":"admin"}'
    with socket.create_connection(("127.0.0.1",8189),timeout=20) as stream:
        stream.sendall((
            f"PUT {transition_path}/members/202 HTTP/1.1\r\nHost: localhost\r\n"
            f"Cookie: {'; '.join(k+'='+v for k,v in race_owner.items())}\r\n"
            f"Origin: {origin}\r\nX-Xotero-CSRF: {race_token}\r\nIf-Match: \"{version}\"\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
            "Expect: 100-continue\r\nConnection: close\r\n\r\n").encode())
        interim=b""
        while not interim.endswith(b"\r\n\r\n"):
            chunk=stream.recv(1)
            assert chunk,"connection ended before management admission"
            interim+=chunk
        assert interim.startswith(b"HTTP/1.1 100 "),interim
        with connect() as blocker:
            blocker.execute("select user_id from group_memberships where group_id=%s and user_id=202 for update",
                (transition_gid,))
            stream.sendall(payload)
            wait_edge(blocker.info.backend_pid)
            blocker.execute("update web_sessions set revoked_at=clock_timestamp() where token_hash=%s",
                (token_hash(race_owner),))
            blocker.commit()
        response=http.client.HTTPResponse(stream)
        response.begin()
        assert response.status==401,response.status
        response.read()
    assert sql("select role from group_memberships where group_id=%s and user_id=202",(transition_gid,))==[("member",)]
    assert sql("select version from groups where id=%s",(transition_gid,))==[(version,)]
    transition_races.append({"race":"session revoked during postbody membership wait","admission":100,"status":401})

    # Cancel the exact blocked operation, not the service or another test's
    # connection. A clean retry uses the unchanged metadata precondition.
    version=sql("select version from groups where id=%s",(transition_gid,))[0][0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        with connect() as blocker:
            blocker.execute("select user_id from group_memberships where group_id=%s and user_id=202 for update",
                (transition_gid,))
            future=executor.submit(request,"PUT",transition_path+"/members/202",group_owner,group_owner_csrf,
                body={"role":"admin"},extra=[("If-Match",'"'+str(version)+'"')])
            wait_edge(blocker.info.backend_pid)
            blocked=sql("select pid from pg_stat_activity where %s=any(pg_blocking_pids(pid))",
                (blocker.info.backend_pid,))
            assert len(blocked)==1,blocked
            assert sql("select pg_cancel_backend(%s)",(blocked[0][0],))==[(True,)]
            assert future.result(timeout=25)[0]==500
            blocker.commit()
    assert sql("select role from group_memberships where group_id=%s and user_id=202",(transition_gid,))==[("member",)]
    assert sql("select version from groups where id=%s",(transition_gid,))==[(version,)]
    transition("PUT","/members/202",{"role":"admin"},version=version)
    transition_races.append({"race":"cancel exact blocked backend then resume","backend":blocked[0][0],
        "cancelled":500,"retry":204,"partial_mutation":False})

    print("CHECKPOINT18_ROLES "+json.dumps(transition_roles,sort_keys=True),flush=True)
    print("CHECKPOINT18_RACES "+json.dumps(transition_races,sort_keys=True),flush=True)
    version=sql("select version from groups where id=%s",(transition_gid,))[0][0]
    assert request("DELETE",transition_path,group_owner,group_owner_csrf,
        extra=[("If-Match",'"'+str(version)+'"')])[0]==204
    status,body,headers=request("POST","/xotero/groups",group_owner,group_owner_csrf,
        body={"name":"Managed private group"})
    assert status==201,("checkpoint17 supported group create",status,body)
    managed_group=json.loads(body)
    assert set(managed_group)=={"groupID","libraryID"}
    assert managed_group["groupID"]>0 and managed_group["libraryID"]>0
    gid=managed_group["groupID"]
    glib=managed_group["libraryID"]
    group_path="/xotero/groups/"+str(gid)
    group_admin_path="/xotero/admin/groups/"+str(gid)
    group_receipts={}

    def group_api(method,path=group_path,payload=None,cookies=group_owner,
                  token=group_owner_csrf,version=1):
        extra=[] if version is None else [("If-Match",'"'+str(version)+'"')]
        return request(method,path,cookies,token,body=payload,extra=extra)

    status,body,headers=group_api("GET")
    assert status==200 and headers["ETag"]=='"1"'
    metadata=json.loads(body)
    assert metadata=={
        "groupID":gid,"libraryID":glib,"ownerUserID":target,"version":1,
        "name":"Managed private group","description":"","url":"","type":"Private",
        "libraryReading":"members","libraryEditing":"members","fileEditing":"members"}
    assert sql("select user_id,role from group_memberships where group_id=%s",(gid,))==[(target,"owner")]
    assert sql("select version,kind from library where id=%s",(glib,))==[(0,"group")]
    assert group_api("GET",group_admin_path,cookies=jar,token=csrf)[0]==200
    assert group_api("GET",cookies=jar,token=csrf)[0]==403
    assert group_api("PATCH",payload={"name":"No role elevation"},cookies=jar,token=csrf)[0]==403
    assert group_api("DELETE",cookies=jar,token=csrf)[0]==403
    assert request("GET","/xotero/groups",group_owner,group_owner_csrf)[0]==200
    for credential in ("fixture-admin-recovery",stronger["token"]):
        assert request("GET","/xotero/groups",extra=[("Zotero-API-Key",credential)])[0]==401
    assert group_api("PATCH",payload={"name":"No precondition"},version=None)[0]==428
    for condition in ("1","*",'W/"1"','"0"','"-1"','"1", "2"'):
        assert request("PATCH",group_path,group_owner,group_owner_csrf,
            body={"name":"Malformed"},extra=[("If-Match",condition)])[0]==400
    for payload in ({},{"name":None},{"name":" "},{"ownerUserID":101},
                    {"members":[101]},{"libraryReading":"all"},{"type":"PublicOpen"},
                    {"libraryEditing":"none"},{"fileEditing":"all"},{"url":None}):
        assert group_api("PATCH",payload=payload)[0]==400,payload
    assert group_api("PATCH",payload={"description":"Policy description","url":"https://example.test/group",
        "libraryEditing":"admins","fileEditing":"admins"})[0]==204
    assert group_api("PATCH",payload={"name":"Stale"})[0]==412
    assert group_api("PATCH",payload={"fileEditing":"admins"},version=2)[0]==204
    assert sql("select version from groups where id=%s",(gid,))==[(2,)]
    assert sql("select version from library where id=%s",(glib,))==[(0,)]
    group_receipts["supported_create_strict_metadata_versions_no_elevation"]=True

    # Membership changes belong to checkpoint18, so only fixture setup uses SQL.
    sql("insert into group_memberships(group_id,user_id,role) values(%s,202,'member')",(gid,))
    group_member,group_member_csrf=login(user="second",user_id=202)
    assert group_api("GET",cookies=group_member,token=group_member_csrf)[0]==200
    assert group_api("PATCH",payload={"fileEditing":"members"},cookies=group_member,
        token=group_member_csrf,version=2)[0]==403
    assert group_api("DELETE",cookies=group_member,token=group_member_csrf,version=2)[0]==403
    sql("update group_memberships set role='admin' where group_id=%s and user_id=202",(gid,))
    assert group_api("PATCH",payload={"fileEditing":"members"},cookies=group_member,
        token=group_member_csrf,version=2)[0]==204
    assert group_api("DELETE",cookies=group_member,token=group_member_csrf,version=3)[0]==403
    group_receipts["owner_admin_member_management_matrix"]=True

    # Library-lock observation proves the demotion committed before admission
    # completes, not merely a serial permission probe.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        with connect() as blocker:
            blocker.execute("select id from library where id=%s for update",(glib,))
            future=executor.submit(group_api,"PATCH",group_path,{"name":"Demoted"},
                group_member,group_member_csrf,3)
            wait_edge(blocker.info.backend_pid)
            blocker.execute("update group_memberships set role='member' where group_id=%s and user_id=202",(gid,))
            blocker.commit()
            assert future.result(timeout=25)[0]==403
    assert sql("select name,version from groups where id=%s",(gid,))==[("Managed private group",3)]
    group_receipts["role_demotion_after_observed_library_wait"]=True

    # A failed audit must roll back both metadata and library allocation.
    with connect(autocommit=True) as ddl:
        ddl.execute("""create function checkpoint17_audit_fail() returns trigger language plpgsql as
            $$begin if new.action::text like 'groups.%' then
            raise exception 'private-group-audit-failure'; end if; return new; end$$""")
        ddl.execute("create trigger checkpoint17_audit_fail before insert on audit_events for each row execute function checkpoint17_audit_fail()")
    before=(sql("select count(*) from library"),sql("select count(*) from groups"))
    assert group_api("PATCH",payload={"name":"Rollback"},version=3)[0]==500
    assert group_api("POST","/xotero/groups",{"name":"Rollback create"})[0]==500
    assert (sql("select count(*) from library"),sql("select count(*) from groups"))==before
    assert sql("select name,version from groups where id=%s",(gid,))==[("Managed private group",3)]
    with connect(autocommit=True) as ddl:
        ddl.execute("drop trigger checkpoint17_audit_fail on audit_events")
        ddl.execute("drop function checkpoint17_audit_fail()")
    secrets.append("private-group-audit-failure")
    group_receipts["audit_failure_rolls_back_metadata_and_allocation"]=True
    # Allocation skips explicit fixture/configuration IDs without overwriting
    # their libraries. Metadata administration never grants data access.
    assert group_api("POST","/xotero/admin/groups",{"name":"Missing owner"},jar,csrf)[0]==400
    for owner,status in ((303,409),(999999,404)):
        assert group_api("POST","/xotero/admin/groups",{"name":"Invalid owner","ownerUserID":owner},
            jar,csrf)[0]==status
    sql("select setval(pg_get_serial_sequence('groups','id'),707,false)")
    sql("select setval(pg_get_serial_sequence('library','id'),77,false)")
    status,body,_=group_api("POST","/xotero/admin/groups",
        {"name":"Allocated by operator","ownerUserID":202},jar,csrf)
    assert status==201,(status,body)
    allocated=json.loads(body)
    assert allocated=={"groupID":708,"libraryID":78},allocated
    assert sql("select library_id,name from groups where id=707")==[(77,"Key scope fixture")]
    assert group_api("DELETE","/xotero/admin/groups/708",cookies=jar,token=csrf)[0]==204
    group_receipts["admin_create_enabled_owner_collision_safe_allocation"]=True

    # No body is supplied. Authentication, role and cookie-CSRF decisions must
    # arrive before buffering the declared payload.
    for cookies,token,supplied_origin,expected in (
        ({},None,origin,401),(group_member,group_member_csrf,origin,403),
        (group_owner,group_owner_csrf,None,403),(group_owner,"0"*64,origin,403),
        (group_owner,group_owner_csrf,"null",403),
    ):
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=5)) as client:
            client.putrequest("PATCH",group_path)
            client.putheader("Content-Length","1048576")
            client.putheader("If-Match",'"3"')
            client.putheader("Cookie","; ".join(k+"="+v for k,v in cookies.items()))
            if token is not None:
                client.putheader("X-Xotero-CSRF",token)
            if supplied_origin is not None:
                client.putheader("Origin",supplied_origin)
            client.endheaders()
            response=client.getresponse()
            assert response.status==expected,(response.status,expected)
            response.read()
    group_receipts["prebody_session_role_origin_csrf"]=True

    # Commit admission, then demote the group admin while body is withheld.
    sql("update group_memberships set role='admin' where group_id=%s and user_id=202",(gid,))
    payload=json.dumps({"name":"After demotion"}).encode()
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=20)) as client:
        with connect() as blocker:
            blocker.execute("select id from library where id=%s for update",(glib,))
            client.putrequest("PATCH",group_path)
            client.putheader("Content-Length",str(len(payload)))
            client.putheader("If-Match",'"3"')
            client.putheader("Cookie","; ".join(k+"="+v for k,v in group_member.items()))
            client.putheader("Origin",origin)
            client.putheader("X-Xotero-CSRF",group_member_csrf)
            client.endheaders()
            wait_edge(blocker.info.backend_pid)
            admission_pid=sql("select pid from pg_stat_activity where %s=any(pg_blocking_pids(pid))",
                (blocker.info.backend_pid,))[0][0]
            blocker.commit()
        with connect(autocommit=True) as observer:
            observer.execute("""do $$declare deadline timestamptz:=clock_timestamp()+interval '10 seconds';
                begin loop exit when exists(select 1 from pg_stat_activity where pid="""+str(admission_pid)+"""
                and state='idle' and query='COMMIT');
                if clock_timestamp()>deadline then raise exception 'group admission did not commit'; end if;
                perform pg_stat_clear_snapshot(); end loop; end$$""")
        sql("update group_memberships set role='member' where group_id=%s and user_id=202",(gid,))
        client.send(payload)
        response=client.getresponse()
        assert response.status==403,response.status
        response.read()
    assert sql("select name,version from groups where id=%s",(gid,))==[("Managed private group",3)]
    group_receipts["role_demotion_between_admission_and_body"]=True

    # Original group owner/library binding is never followed after a wait.
    sql("insert into library(id,version,kind) values(9090,0,'group')")
    for mutation,expected in (("owner_disabled",409),("library_binding",409),("version",412)):
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with connect() as blocker:
                blocker.execute("select id from library where id=%s for update",(glib,))
                future=executor.submit(group_api,"PATCH",group_admin_path,
                    {"name":"Wait loser"},jar,csrf,3)
                wait_edge(blocker.info.backend_pid)
                match mutation:
                    case "owner_disabled":
                        blocker.execute("update users set disabled_at=clock_timestamp() where id=%s",(target,))
                    case "library_binding":
                        blocker.execute("update groups set library_id=9090 where id=%s",(gid,))
                    case "version":
                        blocker.execute("update groups set version=4 where id=%s",(gid,))
                blocker.commit()
                result=future.result(timeout=25)
                assert result[0]==expected,(mutation,result)
        sql("update users set disabled_at=null where id=%s",(target,))
        sql("update groups set library_id=%s,version=3 where id=%s",(glib,gid))
    sql("delete from library where id=9090")
    group_receipts["postwait_owner_library_version_original_binding"]=True

    # Owner disabling wins a create race before the positive user lock.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        with connect() as blocker:
            blocker.execute("select id from users where id=202 for update")
            future=executor.submit(group_api,"POST","/xotero/admin/groups",
                {"name":"Disabled create contender","ownerUserID":202},jar,csrf)
            wait_edge(blocker.info.backend_pid)
            blocker.execute("update users set disabled_at=clock_timestamp() where id=202")
            blocker.commit()
            assert future.result(timeout=25)[0]==409
    assert sql("select id from groups where name='Disabled create contender'")==[]
    sql("update users set disabled_at=null where id=202")
    group_receipts["disabled_owner_create_after_observed_user_wait"]=True

    assert group_api("PATCH",payload={"libraryEditing":"members","fileEditing":"members"},version=3)[0]==204
    owner_key=mint(wildcard,cookies=group_owner,token=group_owner_csrf)
    member_key=mint(wildcard,cookies=group_member,token=group_member_csrf)
    individual_scope=json.loads(json.dumps(empty))
    individual_scope["groups"]["individual"]=[{"groupID":gid,"library":True,"write":True}]
    individual_key=mint(individual_scope,cookies=group_member,token=group_member_csrf)
    assert sql("select policy_limited from api_key_group_permissions where api_key_id=%s",
        (individual_key["id"],))==[(True,)]
    # A mixed explicit grant must survive target deletion for unrelated group707.
    mixed=json.loads(json.dumps(empty))
    mixed["groups"]["individual"]=[{"groupID":gid,"library":True,"write":True},
        {"groupID":707,"library":True,"write":False}]
    sql("insert into group_memberships(group_id,user_id,role) values(707,%s,'member')",(target,))
    mixed_key=mint(mixed,cookies=group_owner,token=group_owner_csrf)

    def data_call(method,path,body=b"",headers=None,credential=owner_key["token"]):
        fields={"Zotero-API-Key":credential,"Content-Type":"application/x-www-form-urlencoded"}
        fields.update(headers or {})
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=25)) as client:
            client.request(method,path,body,fields)
            response=client.getresponse()
            return response.status,response.read(),dict(response.getheaders())

    # Hyper emits100 only when middleware first polls the body, after its
    # key/scope admission. Tighten through supported management before sending
    # bytes; every store family, including no-op paths, must recheck live policy.
    status,body,_=group_api("POST","/xotero/groups",{"name":"Policy race group"})
    assert status==201
    policy_group=json.loads(body)
    policy_gid=policy_group["groupID"]
    policy_lib=policy_group["libraryID"]
    policy_path="/xotero/groups/"+str(policy_gid)
    sql("insert into group_memberships(group_id,user_id,role) values(%s,202,'member')",(policy_gid,))
    policy_version=1
    policy_races=[]
    for method,suffix,payload in (
        ("POST","items",b"[]"),
        ("POST","items",b'[{"key":"WAIT2222","itemType":"book","title":"Denied"}]'),
        ("DELETE","items",b" "),
        ("POST","collections",b'[{"key":"CLLC2222","name":"Denied"}]'),
        ("POST","searches",b'[{"key":"SRCH2222","name":"Denied","conditions":[]}]'),
        ("POST","fulltext",b"[]"),
        ("POST","fulltext",b'[{"key":"TEXT2222","content":"Denied"}]'),
        ("POST","settings",b"{}"),
        ("POST","settings",b'{"tagColors":{"value":[]}}'),
        ("DELETE","settings",b" "),
        ("DELETE","tags",b" "),
        ("DELETE","tags?tag=Denied",b" "),
    ):
        before=sql("select version from library where id=%s",(policy_lib,))
        with socket.create_connection(("127.0.0.1",8189),timeout=20) as stream:
            stream.sendall((
                f"{method} /groups/{policy_gid}/{suffix} HTTP/1.1\r\nHost: localhost\r\n"
                f"Zotero-API-Key: {member_key['token']}\r\nIf-Unmodified-Since-Version: 0\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
                "Expect: 100-continue\r\nConnection: close\r\n\r\n").encode())
            interim=b""
            while not interim.endswith(b"\r\n\r\n"):
                chunk=stream.recv(1)
                assert chunk,"connection ended before100"
                interim+=chunk
            assert interim.startswith(b"HTTP/1.1 100 "),interim
            assert group_api("PATCH",policy_path,{"libraryEditing":"admins"},
                version=policy_version)[0]==204
            policy_version+=1
            stream.sendall(payload)
            response=http.client.HTTPResponse(stream)
            response.begin()
            status=response.status
            response.read()
            assert status==403,("checkpoint17 live ordinary policy after body admission",method,suffix,status)
        assert sql("select version from library where id=%s",(policy_lib,))==before
        assert group_api("PATCH",policy_path,{"libraryEditing":"members"},
            version=policy_version)[0]==204
        policy_version+=1
        policy_races.append({"method":method,"path":suffix,"admission":100,"status":403})
    for table in ("object","fulltext","setting","deletion","file"):
        assert sql("select count(*) from "+table+" where library_id=%s",(policy_lib,))==[(0,)]
    assert group_api("DELETE",policy_path,version=policy_version)[0]==204
    group_receipts["live_ordinary_mutation_body_policy_races"]=policy_races

    def candidate(item,content,credential=owner_key["token"]):
        status,body,_=data_call("POST",f"/groups/{gid}/items/{item}/file",
            urllib.parse.urlencode({"md5":hashlib.md5(content).hexdigest(),"filename":"group.txt",
                "filesize":len(content),"mtime":1}),{"If-None-Match":"*"},credential)
        assert status==200,(status,body)
        token=json.loads(body)["uploadKey"]
        assert data_call("POST","/uploads/"+token,content)[0]==201
        blob=sql("select blob_key from pending_uploads where token_hash=%s",
            (hashlib.sha256(token.encode()).digest(),))[0][0]
        return token,blob

    def download(url):
        parsed=urllib.parse.urlsplit(url)
        with contextlib.closing(http.client.HTTPConnection(parsed.hostname,parsed.port,timeout=20)) as client:
            client.request("GET",parsed.path+"?"+parsed.query)
            response=client.getresponse()
            return response.status,response.read()

    items=[{"key":key,"itemType":"attachment","linkMode":"imported_file"}
        for key in ("GRUPPF22","PENDNG22","UNCERT22")]
    status,body,_=data_call("POST",f"/groups/{gid}/items",json.dumps(items),
        {"Content-Type":"application/json","If-Unmodified-Since-Version":"0"})
    assert status==200 and not json.loads(body)["failed"],(status,body)
    registered,registered_blob=candidate("GRUPPF22",b"registered group bytes")
    assert data_call("POST",f"/groups/{gid}/items/GRUPPF22/file",
        urllib.parse.urlencode({"upload":registered}))[0]==204
    status,_,headers=data_call("GET",f"/groups/{gid}/items/GRUPPF22/file")
    assert status==302
    signed_url=headers["location"]
    assert download(signed_url)==(200,b"registered group bytes")
    pending,pending_blob=candidate("PENDNG22",b"pending member bytes",individual_key["token"])
    uncertain,uncertain_blob=candidate("UNCERT22",b"uncertain candidate bytes")
    sql("update pending_uploads set state='discarded',expires_at='infinity' where token_hash=%s",
        (hashlib.sha256(uncertain.encode()).digest(),))
    before=sql("select version from library where id=%s",(glib,))
    assert group_api("PATCH",payload={"fileEditing":"admins"},version=4)[0]==204
    assert data_call("POST",f"/groups/{gid}/items/PENDNG22/file",
        urllib.parse.urlencode({"upload":pending}))[0]==403
    assert sql("select version from library where id=%s",(glib,))==before
    assert sql("select item_key from file where library_id=%s",(glib,))==[("GRUPPF22",)]
    assert group_api("PATCH",payload={"libraryEditing":"admins"},version=5)[0]==204
    for credential in (individual_key["token"],member_key["token"]):
        assert data_call("POST",f"/groups/{gid}/items",b"[]",
            {"Content-Type":"application/json","If-Unmodified-Since-Version":str(before[0][0])},
            credential)[0]==403
    # New grants remain policy-limited; legacy false retains its established rule.
    sql("update api_key_group_permissions set policy_limited=false where api_key_id=%s",
        (individual_key["id"],))
    assert data_call("POST",f"/groups/{gid}/items",b"[]",
        {"Content-Type":"application/json","If-Unmodified-Since-Version":str(before[0][0])},
        individual_key["token"])[0]==200
    assert data_call("POST",f"/groups/{gid}/items/PENDNG22/file",
        urllib.parse.urlencode({"upload":pending}))[0]==403
    group_receipts["live_policy_original_authorizer_and_legacy_explicit_semantics"]=True
    assert group_api("PATCH",payload={"libraryEditing":"members","fileEditing":"members"},version=6)[0]==204

    # Preserve another live reference to the registered bytes in unrelated707.
    sql("""insert into object(library_id,kind,key,version,data)
        select 77,kind,'SHARED22',0,data from object where library_id=%s and key='GRUPPF22'""",(glib,))
    sql("""insert into file(library_id,item_key,md5,filename,filesize,mtime,version,blob_key,blob_md5,compressed)
        select 77,'SHARED22',md5,filename,filesize,mtime,0,blob_key,blob_md5,compressed
        from file where library_id=%s and item_key='GRUPPF22'""",(glib,))
    receipt_fields="""jsonb_build_object('token_hash',token_hash,'library_id',library_id,
        'group_id',group_id,'authorizer_key_hash',authorizer_key_hash,'item_key',item_key,
        'blob_key',blob_key,'md5',md5,'upload_md5',upload_md5,'filename',filename,
        'filesize',filesize,'mtime',mtime,'compressed',compressed,'expires_at',expires_at)"""
    receipts_before=sql("select "+receipt_fields+" from pending_uploads where library_id=%s order by token_hash",(glib,))
    # Deletion owns library before waiting for the observed blob lock. A
    # registration contender then waits behind deletion, rather than publishing.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        with connect() as blocker:
            blocker.execute("select pg_advisory_xact_lock(1481593922,hashtext(%s))",(registered_blob,))
            deletion=executor.submit(group_api,"DELETE",group_path,None,group_owner,group_owner_csrf,7)
            wait_edge(blocker.info.backend_pid)
            deleting_pid=sql("select pid from pg_stat_activity where %s=any(pg_blocking_pids(pid))",
                (blocker.info.backend_pid,))[0][0]
            registration=executor.submit(data_call,"POST",f"/groups/{gid}/items/PENDNG22/file",
                urllib.parse.urlencode({"upload":pending}))
            wait_edge(deleting_pid)
            blocker.commit()
            assert deletion.result(timeout=25)[0]==204
            assert registration.result(timeout=25)[0] in (403,404)
    assert group_api("GET")[0]==404
    assert sql("select id from library where id=%s",(glib,))==[]
    assert sql("select user_id from group_memberships where group_id=%s",(gid,))==[]
    assert sql("select "+receipt_fields+" from pending_uploads where library_id=%s order by token_hash",(glib,))==receipts_before
    assert sql("select group_id from api_key_group_permissions where api_key_id=%s",(mixed_key["id"],))==[(707,)]
    assert data_call("GET","/groups/707/items",credential=mixed_key["token"])[0]==200
    assert data_call("POST",f"/groups/{gid}/items/PENDNG22/file",
        urllib.parse.urlencode({"upload":pending}))[0]==404
    assert download(signed_url)==(200,b"registered group bytes")
    assert sql("""select not_before>clock_timestamp()+interval '60 seconds' from blob_retirements
        where blob_key=%s""",(registered_blob,))==[(True,)]
    sql("update blob_retirements set not_before=clock_timestamp()-interval '1 second' where blob_key=%s",
        (registered_blob,))
    cleanup=subprocess.run(["xotero","maintenance","gc","--once"],env=environment,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
    assert cleanup.returncode==0,cleanup.stdout
    assert download(signed_url)==(200,b"registered group bytes")
    # Uncertain receipt recurs, but its exact bytes are removed. It cannot
    # consume another key, group grant or the still-live registered shared blob.
    assert sql("select state,expires_at='infinity'::timestamptz from pending_uploads where blob_key=%s",
        (uncertain_blob,))==[("discarded",True)]
    sql("""update pending_uploads set created_at=clock_timestamp()-interval '2 hours',
        expires_at=clock_timestamp()-interval '1 hour' where blob_key=%s""",(pending_blob,))
    # Registered-blob maintenance intentionally does not reset live uploads.
    # A real new authorization invokes the existing finite pending cleanup pass.
    status,body,_=data_call("POST","/groups/707/items/SHARED22/file",
        urllib.parse.urlencode({"md5":hashlib.md5(b"cleanup probe").hexdigest(),
            "filename":"probe.txt","filesize":13,"mtime":1}),
        {"If-Match":hashlib.md5(b"registered group bytes").hexdigest()},member_key["token"])
    assert status==200,(status,body)
    assert sql("select blob_key from pending_uploads where blob_key=%s",(pending_blob,))==[]
    for blob in (pending_blob,uncertain_blob):
        status=subprocess.run(["curl","--silent","--show-error","--max-time","20",
            "--aws-sigv4","aws:amz:us-east-1:s3","--user","rustfsadmin:rustfsadmin",
            "--output","/dev/null","--write-out","%{http_code}",
            "http://127.0.0.1:9000/zotero/"+blob],
            check=True,stdout=subprocess.PIPE,text=True).stdout
        assert status=="404",(blob,status)
    assert download(signed_url)==(200,b"registered group bytes")
    group_receipts["registered_retirement_shared_grace_pending_receipts_no_collateral"]=True
    group_receipts["deletion_registration_observed_overlap"]=True
    print("CHECKPOINT17_GROUPS "+json.dumps(group_receipts,sort_keys=True),flush=True)

    def admin(method,path,payload=None,cookies=jar,token=csrf):
        return request(method,path,cookies,token,body=payload)

    for key in (preserved_key,"fixture-admin-recovery"):
        assert request("GET","/xotero/admin/users",extra=[("Zotero-API-Key",key)])[0]==401
    assert admin("GET","/xotero/admin/users",cookies=ordinary,token=ordinary_csrf)[0]==403
    status,body,headers=admin("GET","/xotero/admin/users")
    assert status==200 and headers["Cache-Control"]=="no-store"
    listed=json.loads(body)
    assert all(set(row)=={"userID","libraryID","username","displayName","disabled","instanceAdmin"}
               for row in listed)
    assert next(row for row in listed if row["userID"]==target)["libraryID"]==created["libraryID"]
    assert admin("PATCH",target_path,{"displayName":"Renamed"})[0]==204
    assert sql("select display_name from users where id=%s",(target,))==[("Renamed",)]
    for path,payload in (
        (target_path,{}),(target_path,{"displayName":None}),
        (target_path,{"disabled":"true"}),(target_path,{"displayName":" "}),
        (target_path,{"unknown":True}),(target_path,{"disabled":None}),
    ):
        assert admin("PATCH",path,payload)[0]==400,(path,payload)
    assert admin("PUT",target_path+"/instance-admin",{"enabled":True,"unexpected":1})[0]==400
    assert admin("POST",target_path+"/identities",{"issuer":"","subject":"valid"})[0]==400
    assert admin("PATCH","/xotero/admin/users/not-an-id",{"disabled":True})[0]==400
    assert admin("PATCH","/xotero/admin/users/999999",{"disabled":True})[0]==404
    before=sql("select count(*) from library"),sql("select count(*) from users")
    assert admin("POST","/xotero/admin/users",{
        "username":"duplicate","displayName":"Duplicate",**identity})[0]==409
    assert (sql("select count(*) from library"),sql("select count(*) from users"))==before
    assert admin("POST",target_path+"/identities",
        {"issuer":"https://id.example.test","subject":"owner"})[0]==409
    assert sql("select user_id from external_identities where subject='owner'")==[(101,)]
    assert admin("POST",target_path+"/identities",extra_identity)[0]==204
    assert admin("POST",target_path+"/identities",extra_identity)[0]==204
    assert admin("DELETE",target_path+"/identities",extra_identity)[0]==204
    assert admin("DELETE",target_path+"/identities",extra_identity)[0]==204
    assert admin("DELETE",target_path+"/identities",identity)[0]==409
    admin_receipts["strict_contract_exact_mapping_conflict_atomic_create"]=True

    assert admin("PUT",target_path+"/instance-admin",{"enabled":True})[0]==204
    assert admin("GET","/xotero/admin/users",cookies=ordinary,token=ordinary_csrf)[0]==200
    # An instance role does not confer data access, even when paired with its
    # owner's real scoped API key. Enrollment is an API action, not SQL minting.
    status,body,headers=request("POST","/keys/sessions",body={})
    assert status==201
    enrollment_token=json.loads(body)["sessionToken"]
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=10)) as client:
        payload="session="+enrollment_token
        client.request("POST","/login",payload,{
            "Content-Type":"application/x-www-form-urlencoded",
            "X-Xotero-OIDC-Issuer":"https://id.example.test",
            "X-Xotero-OIDC-Subject":"provisioned",
        })
        response=client.getresponse()
        assert response.status==200,response.read()
        response.read()
    status,body,headers=request("GET","/keys/sessions/"+enrollment_token)
    assert status==200
    issued_key=json.loads(body)["apiKey"]
    secrets.append(issued_key)
    assert request("GET","/users/101/items",extra=[("Zotero-API-Key",issued_key)])[0]==403
    assert request("GET","/users/"+str(target)+"/items",extra=[("Zotero-API-Key",issued_key)])[0]==200
    assert admin("PUT",target_path+"/instance-admin",{"enabled":False})[0]==204
    assert admin("GET","/xotero/admin/users",cookies=ordinary,token=ordinary_csrf)[0]==403
    assert admin("PUT","/xotero/admin/users/101/instance-admin",{"enabled":False})[0]==409
    assert admin("DELETE","/xotero/admin/users/101/identities",
        {"issuer":"https://id.example.test","subject":"owner"})[0]==409
    assert admin("PATCH","/xotero/admin/users/101",{"disabled":True})[0]==409
    admin_receipts["role_live_no_private_read_elevation_final_admin"]=True

    def session_status(cookies,token):
        return admin("GET","/xotero/admin/users",cookies=cookies,token=token)[0]
    def session_revoked(cookies):
        return sql("""select s.revoked_at is not null and k.revoked_at is not null
            from web_sessions s join api_keys k on k.id=s.api_key_id
            where s.token_hash=%s""",(token_hash(cookies),))==[(True,)]

    disabled_jar,disabled_csrf=login(user="provisioned",user_id=target)
    assert session_status(disabled_jar,disabled_csrf)==403
    assert admin("PATCH",target_path,{"disabled":True})[0]==204
    assert admin("DELETE",target_path+"/identities",identity)[0]==204
    assert admin("PATCH",target_path,{"disabled":False})[0]==409
    assert admin("PUT",target_path+"/instance-admin",{"enabled":True})[0]==409
    assert admin("POST",target_path+"/identities",identity)[0]==204
    assert admin("PATCH",target_path,{"disabled":False})[0]==204
    # Re-enabling must not revive a browser session that disabling ended.
    assert session_status(disabled_jar,disabled_csrf)==401
    assert session_revoked(disabled_jar)

    probe_identity={"issuer":"https://id.example.test","subject":"relink-probe"}
    unlinked_jar,unlinked_csrf=login(user="provisioned",user_id=target)
    assert session_status(unlinked_jar,unlinked_csrf)==403
    assert admin("POST",target_path+"/identities",probe_identity)[0]==204
    assert admin("DELETE",target_path+"/identities",identity)[0]==204
    assert admin("POST",target_path+"/identities",identity)[0]==204
    assert admin("DELETE",target_path+"/identities",probe_identity)[0]==204
    # Relinking must not revive a browser session bound to the unlinked identity.
    assert session_status(unlinked_jar,unlinked_csrf)==401
    assert session_revoked(unlinked_jar)
    admin_receipts["disable_and_unlink_revoke_browser_sessions"]=True
    # Disabling ended the earlier ordinary session; later checks need a live one.
    ordinary,ordinary_csrf=login(user="provisioned",user_id=target)
    # SQL creates only the not-yet-supported group lifecycle fixture.
    sql("insert into library(id,version,kind) values(66,0,'group')")
    with connect() as fixture:
        fixture.execute("""insert into groups(id,library_id,owner_user_id,name)
            values(606,66,%s,'Owned group')""",(target,))
        fixture.execute("""insert into group_memberships(group_id,user_id,role)
            values(606,%s,'owner'),(606,202,'admin')""",(target,))
    group_admin,group_csrf=login(user="second",user_id=202)
    assert admin("GET","/xotero/admin/users",cookies=group_admin,token=group_csrf)[0]==403
    assert admin("PATCH",target_path,{"disabled":True,"displayName":"Must not commit"})[0]==409
    assert sql("select display_name,disabled_at from users where id=%s",(target,))==[("Renamed",None)]
    admin_receipts["disabled_cleanup_reenable_policy_group_owner_conflict"]=True

    # Given incomplete bodies, boundary denial must arrive before any body byte.
    for cookies,token,supplied_origin,expected in (
        ({},None,origin,401),(ordinary,ordinary_csrf,origin,403),
        (jar,csrf,None,403),(jar,"0"*64,origin,403),(jar,csrf,"null",403),
    ):
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=5)) as client:
            client.putrequest("PATCH",target_path)
            client.putheader("Content-Length","1048576")
            client.putheader("Cookie","; ".join(k+"="+v for k,v in cookies.items()))
            if token is not None:
                client.putheader("X-Xotero-CSRF",token)
            if supplied_origin is not None:
                client.putheader("Origin",supplied_origin)
            client.endheaders()
            response=client.getresponse()
            assert response.status==expected,(response.status,expected)
            response.read()
    admin_receipts["prebody_auth_origin_csrf"]=True

    # A real lock barrier forces discovery before a committed authority change.
    # These SQL changes model competing revokers; the action under test is HTTP.
    for mutation in ("role","session","key","mapping","disabled","expiry"):
        race_jar,race_csrf=login()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with connect() as blocker:
                blocker.execute("select id from library where id=1 for update")
                future=executor.submit(admin,"PATCH",target_path,{"displayName":"Stale"},
                    race_jar,race_csrf)
                wait_edge(blocker.info.backend_pid)
                match mutation:
                    case "role":
                        blocker.execute("delete from instance_admins where user_id=101")
                    case "session":
                        blocker.execute("update web_sessions set revoked_at=clock_timestamp() where token_hash=%s",
                            (token_hash(race_jar),))
                    case "key":
                        blocker.execute("""update api_keys set revoked_at=clock_timestamp() where id=
                            (select api_key_id from web_sessions where token_hash=%s)""",(token_hash(race_jar),))
                    case "mapping":
                        blocker.execute("update external_identities set user_id=202 where subject='owner'")
                    case "disabled":
                        blocker.execute("update users set disabled_at=clock_timestamp() where id=101")
                    case "expiry":
                        blocker.execute("""update web_sessions set created_at=clock_timestamp()-interval '9 hours',
                            expires_at=clock_timestamp()-interval '1 hour' where token_hash=%s""",(token_hash(race_jar),))
                blocker.commit()
                assert future.result(timeout=25)[0]==(403 if mutation=="role" else 401),mutation
        assert sql("select display_name from users where id=%s",(target,))==[("Renamed",)]
        sql("insert into instance_admins(user_id) values(101) on conflict do nothing")
        sql("update external_identities set user_id=101 where subject='owner'")
        sql("update users set disabled_at=null where id=101")
    admin_receipts["live_role_session_key_identity_disabled_expiry_after_wait"]=True

    jar,csrf=login()
    # Prove authorization repeats AFTER body arrival, not merely at admission.
    # Observe the admission connection blocked on the library, then idle after
    # COMMIT, before an independent operator demotes it through supported API.
    assert admin("PUT",target_path+"/instance-admin",{"enabled":True},jar,csrf)[0]==204
    other_admin,other_csrf=login(user="provisioned",user_id=target)
    payload=json.dumps({"displayName":"Stale after body"}).encode()
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1",8189,timeout=20)) as client:
        with connect() as blocker:
            blocker.execute("select id from library where id=1 for update")
            client.putrequest("PATCH",target_path)
            client.putheader("Content-Type","application/json")
            client.putheader("Content-Length",str(len(payload)))
            client.putheader("Cookie","; ".join(k+"="+v for k,v in jar.items()))
            client.putheader("Origin",origin)
            client.putheader("X-Xotero-CSRF",csrf)
            client.endheaders()
            wait_edge(blocker.info.backend_pid)
            admission_pid=sql("""select pid from pg_stat_activity where %s=any(pg_blocking_pids(pid))""",
                (blocker.info.backend_pid,))[0][0]
            blocker.commit()
        with connect(autocommit=True) as observer:
            observer.execute("""do $$declare deadline timestamptz:=clock_timestamp()+interval '10 seconds';
                begin loop exit when exists(select 1 from pg_stat_activity where pid="""+str(admission_pid)+"""
                and state='idle' and query='COMMIT');
                if clock_timestamp()>deadline then raise exception 'admission did not commit'; end if;
                perform pg_stat_clear_snapshot(); end loop; end$$""")
        assert admin("PUT","/xotero/admin/users/101/instance-admin",{"enabled":False},
            other_admin,other_csrf)[0]==204
        client.send(payload)
        response=client.getresponse()
        assert response.status==403,response.status
        response.read()
    assert sql("select display_name from users where id=%s",(target,))==[("Renamed",)]
    assert admin("PUT","/xotero/admin/users/101/instance-admin",{"enabled":True},
        other_admin,other_csrf)[0]==204
    assert admin("PUT",target_path+"/instance-admin",{"enabled":False},jar,csrf)[0]==204
    admin_receipts["supported_demotion_after_admission_before_body_denies"]=True

    # One request UUID, one event per action, and attribution only to a verified
    # actor. Unknown tokens never borrow an actor ID from claims or the body.
    correlations=[]
    for method,path,payload,cookies,token,status,actor,subject,action,outcome in (
        ("PATCH",target_path,{"unknown":1},jar,csrf,400,101,target,"admin.update-user","denied"),
        ("PUT",target_path+"/instance-admin",{"enabled":True},other_admin,other_csrf,
            403,target,target,"admin.set-role","denied"),
        ("PATCH",target_path,{"displayName":"Unknown"},{},None,
            401,None,target,"admin.update-user","denied"),
        ("POST",target_path+"/identities",identity,jar,csrf,
            204,101,target,"admin.link-identity","noop"),
        ("DELETE",target_path+"/identities",extra_identity,jar,csrf,
            204,101,target,"authority.unlink-identity","noop"),
        ("PATCH","/xotero/admin/users/999999",{"disabled":True},jar,csrf,
            404,101,999999,"admin.update-user","denied"),
    ):
        baseline=sql("select coalesce(max(id),0) from audit_events")[0][0]
        assert admin(method,path,payload,cookies,token)[0]==status
        events=sql("""select actor_user_id,subject_user_id,action::text,outcome::text,request_id::text
            from audit_events where id>%s order by id""",(baseline,))
        assert len(events)==1 and events[0][:4]==(actor,subject,action,outcome),events
        correlations.append(events[0][4])
    assert len(set(correlations))==len(correlations)
    admin_receipts["single_action_audit_verified_attribution_and_correlation"]=True
    with connect(autocommit=True) as ddl:
        ddl.execute("""create function checkpoint15_audit_fail() returns trigger language plpgsql as
            $$begin raise exception 'private-admin-audit-failure'; end$$""")
        ddl.execute("create trigger checkpoint15_audit_fail before insert on audit_events for each row execute function checkpoint15_audit_fail()")
    before=sql("select count(*) from audit_events")
    assert admin("PATCH",target_path,{"displayName":"Rollback"},jar,csrf)[0]==500
    assert sql("select display_name from users where id=%s",(target,))==[("Renamed",)]
    assert sql("select count(*) from audit_events")==before
    with connect(autocommit=True) as ddl:
        ddl.execute("drop trigger checkpoint15_audit_fail on audit_events")
        ddl.execute("drop function checkpoint15_audit_fail()")
    secrets.append("private-admin-audit-failure")
    audits=sql("""select action::text,outcome::text,actor_user_id,subject_user_id,
        request_id::text,occurred_at is not null from audit_events where action::text like 'admin.%'""")
    assert any(row[:2]==("admin.update-user","success") and row[2:4]==(101,target) for row in audits)
    assert any(row[1]=="noop" for row in audits) and any(row[1]=="denied" for row in audits)
    assert all(row[4] and row[5] for row in audits)
    assert sql("""select count(*) from audit_events where row_to_json(audit_events)::text
        like '%second-exact-identity%'""")==[(0,)]
    admin_receipts["audit_success_noop_denied_safe_atomic_rollback"]=True

    server.send_signal(signal.SIGINT)
    assert server.wait(timeout=15)==0
    server_log_thread.join(timeout=10)
    assert not server_log_thread.is_alive()
    server.stdout.close()

    sequence_database="checkpoint20_sequence"
    subprocess.run(["sudo","-u","postgres","createdb","-O","xotero",
                    sequence_database],check=True)
    subprocess.run(["env","DATABASE_URL=postgres://xotero@127.0.0.1/"+sequence_database,
        "sqlx","migrate","run","--source","/etc/xotero-test/current-migrations"],check=True)
    def sequence_sql(statement,params=None):
        with psycopg.connect(host="127.0.0.1",user="xotero",dbname=sequence_database,
                             connect_timeout=5) as connection:
            cursor=connection.execute(statement,params)
            return cursor.fetchall() if cursor.description is not None else []
    assert sequence_sql("select count(*) from bootstrap_state")==[(0,)]
    sequence_sql("alter sequence users_id_seq rename to users_id_checkpoint20")
    sequence_sql("select setval('users_id_checkpoint20',200,true)")
    deleted_highwater=sequence_sql(
        "insert into users(username,display_name) values('deleted-high','Deleted') returning id"
    )[0][0]
    assert deleted_highwater>101
    sequence_sql("delete from users where id=%s",(deleted_highwater,))
    assert sequence_sql("select count(*) from users")==[(0,)]

    environment = environment | {
        "XOTERO_DATABASE_URL":"postgres://xotero@127.0.0.1/"+sequence_database,
        "XOTERO_BIND":"127.0.0.1:8189",
        "XOTERO_USER_ID":"101","XOTERO_USERNAME":"owner","XOTERO_DISPLAY_NAME":"Owner",
        "XOTERO_BOOTSTRAP_INSTANCE_ADMIN":"true",
    }
    server_output=bytearray()
    server=subprocess.Popen(["xotero"],env=environment,stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,bufsize=0)
    with selectors.DefaultSelector() as observer:
        observer.register(server.stdout,selectors.EVENT_READ)
        while True:
            assert observer.select(45),"checkpoint20 bootstrap startup timeout"
            line=server.stdout.readline()
            assert line,server.poll()
            server_output.extend(line)
            if b"xotero listening" in line:
                break
    server_log_thread=threading.Thread(target=drain_server_log)
    server_log_thread.start()
    assert sequence_sql("select pg_get_serial_sequence('users','id')")==[
        ("public.users_id_checkpoint20",)]
    assert sequence_sql("select last_value from users_id_checkpoint20")==[
        (deleted_highwater,)]
    assert sequence_sql("select id from users")==[(101,)]
    assert sequence_sql(
        "select count(*) from bootstrap_state where name in ('identity','instance-admin')"
    )==[(2,)]
    assert sequence_sql(
        "select count(*) from audit_events where action='bootstrap.instance-admin' and outcome='success'"
    )==[(1,)]

    sequence_jar,sequence_csrf=login()
    sequence_status,sequence_body,_=request(
        "POST","/xotero/admin/users",sequence_jar,sequence_csrf,
        body={"username":"after-bootstrap","displayName":"After Bootstrap",
              "issuer":"https://id.example.test","subject":"after-bootstrap"})
    assert sequence_status==201,(sequence_status,sequence_body)
    generated_after_bootstrap=json.loads(sequence_body)["userID"]
    assert generated_after_bootstrap>deleted_highwater,(
        deleted_highwater,generated_after_bootstrap)
    assert sequence_sql("select id from users where username='after-bootstrap'")==[
        (generated_after_bootstrap,)]
    assert sequence_sql("select last_value from users_id_checkpoint20")==[
        (generated_after_bootstrap,)]
    assert logout(sequence_jar,sequence_csrf)==204
    admin_receipts["renamed_sequence_real_bootstrap_preserves_deleted_highwater"]={
        "deleted_generated_id":deleted_highwater,"bootstrap_id":101,
        "next_supported_admin_id":generated_after_bootstrap}
    server.send_signal(signal.SIGINT)
    assert server.wait(timeout=15)==0
    server_log_thread.join(timeout=10)
    assert not server_log_thread.is_alive()
    assert all(secret not in server_output.decode() for secret in secrets)
    server.stdout.close()
    print("CHECKPOINT15_USERS "+json.dumps(admin_receipts,sort_keys=True),flush=True)
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
        server_log_thread.join(timeout=10)
        assert not server_log_thread.is_alive()
        logs=server_output.decode()
        assert all(secret not in logs for secret in secrets)
    databases=[database]
    subprocess.run(["sudo","-u","postgres","dropdb",database],check=True)
    if "sequence_database" in locals():
        subprocess.run(["sudo","-u","postgres","dropdb","--if-exists",
                        sequence_database],check=True)
        databases.append(sequence_database)
    print("CHECKPOINT14_CLEANUP "+json.dumps({
        "databases":databases,"server":None if server is None else server.pid}),flush=True)
'''
compile(web_script, "checkpoint20-admin-web-script", "exec")
print(machine.succeed("python3 -u -c " + shlex.quote(web_script)))
