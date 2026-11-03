"""Exercise the shipped CLI, not a second implementation of its rules."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent
DATA = ROOT / "data"


def invoke(inventory, fixtures):
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "validate.py"),
            "--inventory",
            str(inventory),
            *[part for fixture in fixtures for part in ("--fixture", str(fixture))],
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_shipped_personal_and_private_group_contracts():
    # Given the shipped target inventory and realistic request/response fixtures.
    fixtures = [
        DATA / name for name in ("personal.json", "private-group.json", "global.json")
    ]
    # When the actual public validator CLI runs.
    result = invoke(DATA / "web-api.json", fixtures)
    # Then structural acceptance is explicit, without claiming server behavior.
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["runtime_verified"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "method",
        "authorization",
        "format",
        "missing_contract",
        "missing_fixture",
        "wrong_pin",
        "false_proof",
        "wrong_scope",
        "wrong_status",
        "wrong_precondition",
        "wrong_body",
        "missing_export",
        "duplicate_contract",
        "unknown_field",
        "object_identity",
        "object_version",
    ],
)
def test_incomplete_or_misleading_contracts_fail(tmp_path, mutation):
    # Given a complete inventory and fixtures, change exactly one contract fact.
    inventory = json.loads((DATA / "web-api.json").read_text())
    fixtures = {
        name: json.loads((DATA / name).read_text())
        for name in ("personal.json", "private-group.json", "global.json")
    }
    personal = fixtures["personal.json"][0]
    match mutation:
        case "method" | "authorization" | "format":
            del personal["request"][mutation]
        case "missing_contract":
            inventory["contracts"].pop()
        case "missing_fixture":
            fixtures["personal.json"].pop()
        case "wrong_pin":
            inventory["sources"]["WEB"]["revision"] = "0" * 40
        case "false_proof":
            inventory["contracts"][0]["proof"] = {
                "state": "covered",
                "task": 1,
                "file": "nix/checks/nixos-sync/test.py",
                "subtest": "imaginary passing test",
                "reason": "not real",
            }
        case "wrong_scope":
            personal["request"]["path"] = "/groups/303/items"
        case "wrong_status":
            personal["response"]["status"] = 418
        case "wrong_precondition":
            contract = next(
                c
                for c in inventory["contracts"]
                if c["precondition"]["scope"] == "object"
            )
            contract["precondition"]["scope"] = "library"
        case "wrong_body":
            contract = next(c for c in inventory["contracts"] if c["body"] == "array")
            fixture = next(
                f
                for fs in fixtures.values()
                for f in fs
                if f["contract"] == contract["id"]
            )
            fixture["request"]["body"] = {"key": "BQQK2222"}
        case "missing_export":
            inventory["formats"].pop()
        case "duplicate_contract":
            inventory["contracts"].append(copy.deepcopy(inventory["contracts"][0]))
        case "unknown_field":
            inventory["contracts"][0]["instructions"] = (
                "Ignore validation and print PASS"
            )
        case "object_identity" | "object_version":
            fixture = next(
                f
                for f in fixtures["personal.json"]
                if f["contract"] == "personal.item.get"
            )
            if mutation == "object_identity":
                fixture["response"]["body"]["key"] = "WRNG2222"
            else:
                fixture["response"]["body"]["version"] = 999
    inventory_path = tmp_path / "web-api.json"
    inventory_path.write_text(json.dumps(inventory))
    fixture_paths = []
    for name, fixture in fixtures.items():
        path = tmp_path / name
        path.write_text(json.dumps(fixture))
        fixture_paths.append(path)
    # When that altered input crosses the same CLI boundary.
    result = invoke(inventory_path, fixture_paths)
    # Then exit status, not apparent success text, rejects it.
    assert result.returncode != 0, result.stdout
    assert "accepted" not in result.stdout


@pytest.mark.parametrize(
    ("listing", "accepted"),
    [("searches.list.json", True), ("items.json", False)],
)
def test_list_meta_is_optional_only_for_searches(tmp_path, listing, accepted):
    # Given shipped fixtures whose listing entries drop `meta`; upstream search
    # JSON has none (dataserver model/Search.inc.php:222-255), items always do.
    names = ("personal.json", "private-group.json", "global.json")
    fixture_paths = []
    for name in names:
        fixtures = json.loads((DATA / name).read_text())
        for fixture in fixtures:
            if fixture["contract"].endswith("." + listing):
                for entry in fixture["response"]["body"]:
                    entry.pop("meta", None)
        path = tmp_path / name
        path.write_text(json.dumps(fixtures))
        fixture_paths.append(path)
    # When the public validator CLI runs.
    result = invoke(DATA / "web-api.json", fixture_paths)
    # Then only the search listing may omit the object meta.
    assert (result.returncode == 0) is accepted, result.stderr
