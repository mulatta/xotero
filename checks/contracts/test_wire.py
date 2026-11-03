"""Exercise wire invariants independently of the copied coverage floor."""

import json

import pytest
from fixtures import ContractError, validate_fixture
from models import Contract, Fixture
from test_validator import DATA


def write_case(scope="personal"):
    """Build expected output from submitted data, not the shipped response."""
    source = next(
        c
        for c in json.loads((DATA / "web-api.json").read_text())["contracts"]
        if c["id"] == scope + ".items.bulk.create-no-condition"
    )
    contract = Contract.model_validate(source)
    item = {"key": "ABCD2222", "version": 0, "itemType": "book", "title": "Research"}
    canonical = {**item, "version": 18}
    fixture = Fixture.model_validate(
        {
            "contract": contract.id,
            "scope": scope,
            "kind": "expected-contract",
            "request": {
                "method": "POST",
                "path": "/users/101/items"
                if scope == "personal"
                else "/groups/303/items",
                "authorization": contract.authorization.model_dump(),
                "format": "json",
                "query": {},
                "headers": {},
                "body": [item],
            },
            "response": {
                "status": 200,
                "headers": contract.headers,
                "body": {
                    "success": {"0": item["key"]},
                    "successful": {
                        "0": {
                            "key": item["key"],
                            "version": 18,
                            "data": canonical,
                            "links": {},
                            "meta": {},
                        }
                    },
                    "unchanged": {},
                    "failed": {},
                },
            },
        }
    )
    return contract, fixture


@pytest.mark.parametrize("scope", ["personal", "private-group"])
@pytest.mark.parametrize("forbidden", ["O", "0", "1"])
@pytest.mark.parametrize(
    "location",
    [
        "path",
        "submitted",
        "canonical",
        "selection",
        "parent",
        "collection",
        "tombstone",
    ],
)
def test_forbidden_object_key_rejected(scope, forbidden, location):
    # Given a coherent write, change one key-bearing position independently.
    contract, original = write_case(scope)
    raw = original.model_dump()
    bad_key = forbidden + "BCD2222"
    match location:
        case "path":
            path = raw["request"]["path"] + "/" + bad_key + "/children"
            contract = contract.model_copy(
                update={
                    "path": path,
                    "method": "GET",
                    "body": "none",
                    "envelope": "list",
                }
            )
            raw["request"].update(path=path, method="GET", body=None)
            raw["response"]["body"] = [raw["response"]["body"]["successful"]["0"]]
        case "submitted":
            raw["request"]["body"][0]["key"] = bad_key
        case "canonical":
            raw["response"]["body"]["successful"]["0"]["data"]["key"] = bad_key
        case "selection":
            contract = contract.model_copy(update={"query": {"itemKey": bad_key}})
            raw["request"]["query"] = {"itemKey": bad_key}
        case "parent":
            raw["request"]["body"][0]["parentItem"] = bad_key
        case "collection":
            raw["request"]["body"][0]["collections"] = [bad_key]
        case "tombstone":
            path = raw["request"]["path"].rsplit("/", 1)[0] + "/deleted"
            contract = contract.model_copy(
                update={
                    "path": path,
                    "method": "GET",
                    "body": "none",
                    "envelope": "deleted",
                }
            )
            raw["request"].update(path=path, method="GET", body=None)
            raw["response"]["body"] = {
                "items": [bad_key],
                "collections": [],
                "searches": [],
                "tags": [],
                "settings": [],
            }
    altered = Fixture.model_validate(raw)
    # When the real fixture boundary sees it, without floor comparison.
    with pytest.raises(ContractError):
        validate_fixture(contract, altered)


@pytest.mark.parametrize("scope", ["personal", "private-group"])
@pytest.mark.parametrize(
    "change",
    ["key", "title", "version", "note", "annotation", "trash", "index", "overlap"],
)
def test_successful_write_must_match_submitted_object(scope, change):
    # Given a coherent successful write and one contradicted result fact.
    contract, original = write_case(scope)
    raw = original.model_dump()
    submitted = raw["request"]["body"][0]
    returned = raw["response"]["body"]["successful"]["0"]
    match change:
        case "key":
            raw["response"]["body"]["success"]["0"] = "EFGH2222"
            returned["key"] = returned["data"]["key"] = "EFGH2222"
        case "title":
            submitted["title"] = "Changed title"
        case "version":
            returned["version"] = returned["data"]["version"] = 0
        case "note":
            submitted.update(itemType="note", note="<p>New note</p>")
        case "annotation":
            submitted.update(
                itemType="annotation", annotationType="highlight", annotationText="New"
            )
        case "trash":
            submitted["deleted"] = 1
        case "index":
            raw["response"]["body"]["successful"]["1"] = raw["response"]["body"][
                "successful"
            ].pop("0")
            raw["response"]["body"]["success"]["1"] = raw["response"]["body"][
                "success"
            ].pop("0")
        case "overlap":
            raw["response"]["body"]["failed"]["0"] = {
                "key": submitted["key"],
                "code": 400,
            }
    altered = Fixture.model_validate(raw)
    # When the same boundary sees it, response agreement alone is insufficient.
    with pytest.raises(ContractError):
        validate_fixture(contract, altered)


def test_failed_object_does_not_become_successful():
    # Given separate submitted objects with a success and a per-object failure.
    contract, original = write_case()
    raw = original.model_dump()
    raw["request"]["body"].append({"key": "EFGH2222", "version": 0})
    raw["response"]["body"]["failed"]["1"] = {"key": "EFGH2222", "code": 400}
    # When the actual boundary checks this report, HTTP success is not all-object success.
    assert validate_fixture(contract, Fixture.model_validate(raw)) is None


@pytest.mark.parametrize("scope", ["personal", "private-group"])
@pytest.mark.parametrize("family", ["collections", "searches"])
def test_keys_format_rejects_json_mime_even_when_contract_agrees(scope, family):
    # Given a keys fixture whose contract and response both advertise wrong MIME.
    contract, original = write_case(scope)
    path = original.request.path.rsplit("/", 1)[0] + "/" + family
    headers = {"Content-Type": "application/json"}
    contract = contract.model_copy(
        update={
            "path": path,
            "method": "GET",
            "body": "none",
            "envelope": "keys",
            "format": "keys",
            "headers": headers,
        }
    )
    raw = original.model_dump()
    raw["request"].update(method="GET", path=path, format="keys", body=None)
    raw["response"].update(headers=headers, body="ABCD2222\n")
    # When the boundary checks wire semantics independently of copied values.
    with pytest.raises(ContractError):
        validate_fixture(contract, Fixture.model_validate(raw))
