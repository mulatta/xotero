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
