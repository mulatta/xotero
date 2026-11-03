"""Operator-facing migration command and unit ordering coverage."""

import hashlib
import json
import shlex


base = "http://localhost:8189"
recovery = "recoverytoken"
historical = "HistoricalOps23456789Ab"
api_headers = "-H 'Zotero-API-Version: 3' -H 'Zotero-Schema-Version: 42'"
identity_tables = [
    "users",
    "external_identities",
    "personal_libraries",
    "api_keys",
    "bootstrap_state",
    "instance_admins",
    "audit_events",
]


def psql(sql, database="xotero"):
    return machine.succeed(
        f"sudo -u xotero psql -v ON_ERROR_STOP=1 -At -d {database} -c {shlex.quote(sql)}"
    ).strip()


def recreate_database(name):
    machine.succeed(f"sudo -u postgres dropdb --if-exists {name}")
    machine.succeed(f"sudo -u postgres createdb -O xotero {name}")


def sqlx_migrate(database, source):
    url = f"postgresql://xotero@localhost/{database}?host=/run/postgresql"
    machine.succeed(
        f"sudo -u xotero env DATABASE_URL={shlex.quote(url)} "
        f"sqlx migrate run --source {source}"
    )


def service_properties():
    unit = machine.succeed("systemctl cat xotero.service")
    keep = ("Environment=", "LoadCredential=", "User=", "Group=")
    return [line for line in unit.splitlines() if line.startswith(keep)]


def run_with_service_env(*args):
    # Transient units do not expand %d in Environment=, so point it at the
    # probe unit's own credentials directory.
    unit = "xotero-migrate-probe"
    credentials = f"/run/credentials/{unit}.service"
    properties = " ".join(
        f"-p {shlex.quote(p.replace('%d', credentials))}" for p in service_properties()
    )
    command = " ".join(shlex.quote(a) for a in args)
    return machine.execute(
        f"systemd-run --unit={unit} --wait --pipe --quiet --collect "
        f"{properties} xotero {command} 2>&1"
    )


def current_version():
    return int(
        machine.succeed(
            "ls /etc/xotero-test/current-migrations | sed -n 's/^0*\\([0-9]*\\)_.*/\\1/p' "
            "| sort -n | tail -1"
        ).strip()
    )


def migration_state(database="xotero"):
    return psql(
        "select coalesce(max(version), 0), bool_and(success), count(*) from _sqlx_migrations",
        database,
    )


def identity_snapshot(database):
    return {
        table: psql(
            f"select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text), '[]') from {table} t",
            database,
        )
        for table in identity_tables
    }


def assert_port_closed():
    listeners = machine.succeed("ss -ltnH")
    assert ":8189 " not in listeners, f"nothing may listen on 8189:\n{listeners}"
    machine.fail(f"curl -s --max-time 2 {base}/keys/current")


def http_code(path, token):
    return machine.succeed(
        f"curl -s -o /dev/null -w '%{{http_code}}' {api_headers} "
        f"-H 'Zotero-API-Key: {token}' {base}{path}"
    ).strip()


def get_json(path, token):
    raw = machine.succeed(
        f"curl -s -w '\\n%{{http_code}}' {api_headers} "
        f"-H 'Zotero-API-Key: {token}' '{base}{path}'"
    )
    body, _, status = raw.rpartition("\n")
    assert status == "200", f"GET {path} must return 200, got {status}: {body}"
    return json.loads(body)


def journal_cursor():
    output = machine.succeed("journalctl -n0 --show-cursor -q")
    return output.strip().split("cursor: ", 1)[1]


def unit_journal(cursor):
    return machine.succeed(
        f"journalctl -u xotero.service -o cat --no-pager --after-cursor {shlex.quote(cursor)}"
    )


def start_xotero():
    machine.succeed("systemctl start xotero.service")
    machine.wait_for_unit("xotero.service")
    machine.wait_for_open_port(8189)


machine.wait_for_unit("postgresql.service")
machine.wait_for_unit("rustfs.service")
machine.succeed("aws s3 mb s3://zotero")
latest = current_version()
expected_state = f"{latest}|t|{latest}"

with subtest("xotero migrate applies the current schema without serving"):
    assert psql("select to_regclass('_sqlx_migrations') is null") == "t", (
        "fresh database must have no migration history"
    )
    status, output = run_with_service_env("migrate")
    assert status == 0, f"first migrate must exit 0, got {status}:\n{output}"
    assert migration_state() == expected_state, (
        f"migrate must record versions 1..{latest} as successful, got {migration_state()}"
    )
    assert_port_closed()

    recreate_database("migration_reference")
    sqlx_migrate("migration_reference", "/etc/xotero-test/current-migrations")
    reference = identity_snapshot("migration_reference")
    migrated = identity_snapshot("xotero")
    assert migrated == reference, (
        "migrate must create no identity rows beyond the migrations themselves: "
        f"{migrated} != {reference}"
    )

    status, output = run_with_service_env("migrate")
    assert status == 0, (
        f"second migrate must be a no-op exiting 0, got {status}:\n{output}"
    )
    assert migration_state() == expected_state, "second migrate must not change history"
    assert identity_snapshot("xotero") == reference, "second migrate must not bootstrap"
    assert_port_closed()

    status, output = run_with_service_env("bogus")
    assert status == 2, f"unknown subcommand must exit 2, got {status}:\n{output}"
    assert "migrate" in output, f"usage must list migrate:\n{output}"
    assert "maintenance gc --once" in output, (
        f"usage must list maintenance gc --once:\n{output}"
    )

with subtest("unit runs migrate before serving a fresh database"):
    recreate_database("xotero")
    start_xotero()
    pre = machine.succeed("systemctl show -p ExecStartPre --value xotero.service")
    assert " migrate" in pre and "status=0" in pre, (
        f"ExecStartPre migrate must exit 0: {pre}"
    )
    assert migration_state() == expected_state, (
        "fresh unit start must reach current schema"
    )
    assert http_code("/keys/current", recovery) == "200", (
        "recovery key must authenticate"
    )

with subtest("unit upgrades a populated v13 database and keeps its rows"):
    machine.succeed("systemctl stop xotero.service")
    recreate_database("xotero")
    sqlx_migrate("xotero", "/etc/xotero-test/v13-migrations")
    assert migration_state() == "13|t|13", "fixture must start at v13"
    token_hash = hashlib.sha256(historical.encode()).hexdigest()
    psql(
        """insert into users (id, username, display_name) values (101, 'alice', 'Alice');
           insert into personal_libraries (user_id, library_id) values (101, 1);
           update library set version = 12 where id = 1;"""
    )
    psql(
        f"""with inserted as (
              insert into api_keys (token_hash, user_id, name)
              values (decode('{token_hash}', 'hex'), 101, 'historical') returning id)
            insert into api_key_user_permissions (api_key_id, library, notes, write, files)
            select id, true, true, true, true from inserted"""
    )
    psql(
        """insert into object (library_id, kind, key, version, data)
           values (1, 'item', 'OPSITEM2', 11,
                   '{"key":"OPSITEM2","version":11,"itemType":"book","title":"Preserved book"}');
           insert into setting (library_id, key, version, value)
           values (1, 'tagColors', 12, '[{"name":"kept","color":"#ff0000"}]');
           insert into fulltext
           (library_id, item_key, content, indexed_chars, total_chars,
            indexed_pages, total_pages, version)
           values (1, 'OPSITEM2', 'preserved fulltext', 18, 18, 1, 1, 11);"""
    )
    start_xotero()
    assert migration_state() == expected_state, "v13 upgrade must reach current schema"
    items = get_json("/users/101/items?itemKey=OPSITEM2", historical)
    assert [i["data"]["title"] for i in items] == ["Preserved book"], (
        f"historical key reads v13 item: {items}"
    )
    settings = get_json("/users/101/settings", recovery)
    assert settings["tagColors"]["value"] == [{"name": "kept", "color": "#ff0000"}], (
        f"v13 setting must survive the upgrade: {settings}"
    )
    fulltext = get_json("/users/101/items/OPSITEM2/fulltext", historical)
    assert fulltext["content"] == "preserved fulltext", (
        f"v13 fulltext survives: {fulltext}"
    )

with subtest("failed migration stops the unit before it listens"):
    machine.succeed("systemctl stop xotero.service")
    psql("update _sqlx_migrations set checksum = '\\x00'::bytea where version = 1")
    cursor = journal_cursor()
    machine.fail("systemctl start xotero.service")
    machine.succeed("systemctl stop xotero.service")
    journal = unit_journal(cursor)
    for expected in (
        "apply migrations",
        "Control process exited, code=exited, status=1",
        "Failed with result 'exit-code'",
    ):
        assert expected in journal, f"journal must contain {expected!r}:\n{journal}"
    assert "xotero listening" not in journal, (
        f"server must not listen after a failed migrate:\n{journal}"
    )
    assert_port_closed()
