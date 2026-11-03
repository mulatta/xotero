# /// script
# requires-python = ">=3.12"
# dependencies = ["pydantic>=2,<3", "typer>=0.12,<1"]
# ///
# How to run: python checks/contracts/validate.py --inventory checks/contracts/data/web-api.json
"""Validate complete selected API targets and fixtures without executing a server."""

import json
from pathlib import Path
from typing import Annotated

import typer
from fixtures import ContractError, require, validate_fixture
from models import Fixture, Inventory
from pydantic import TypeAdapter, ValidationError

ROOT = Path(__file__).parent
DATA = ROOT / "data"
app = typer.Typer()


def validate(inventory: Inventory, fixtures: list[Fixture]) -> None:
    """Check independent coverage floor, provenance and realistic wire shapes."""
    floor = json.loads((DATA / "coverage.json").read_text())
    require(inventory.base == floor["base"], "base revision drift")
    require(
        {key: value.model_dump() for key, value in inventory.sources.items()}
        == floor["sources"],
        "pinned source/lock/gitlink drift",
    )
    require(
        {f.key: (f.mime, f.translator, f.extension) for f in inventory.formats}
        == {
            f["key"]: (f["mime"], f["translator"], f["extension"])
            for f in floor["formats"]
        }
        and len(inventory.formats) == len(floor["formats"]),
        "export allowlist incomplete or altered",
    )
    contracts = {contract.id: contract for contract in inventory.contracts}
    require(len(contracts) == len(inventory.contracts), "duplicate contract")
    require(
        set(contracts) == set(floor["contracts"]),
        "selected contract coverage incomplete",
    )
    require(
        {d.id for d in inventory.discrepancies} == set(floor["discrepancies"]),
        "source discrepancies incomplete",
    )
    require(inventory.assets == floor["assets"], "asset consumer mapping incomplete")
    require(
        inventory.requirements == floor["requirements"],
        "fixed application requirements incomplete",
    )
    cases = {fixture.contract: fixture for fixture in fixtures}
    require(len(cases) == len(fixtures), "duplicate fixture")
    require(set(cases) == set(contracts), "fixture coverage incomplete")
    for identity, contract in contracts.items():
        # The coverage floor is separate from caller input. Removing a row, query
        # variant or security field cannot turn a plausible subset into success.
        expected = floor["contracts"][identity]
        for field in (
            "origin",
            "method",
            "path",
            "scope",
            "query",
            "body",
            "envelope",
            "precondition",
            "authorization",
            "status",
            "headers",
            "format",
            "sources",
        ):
            require(
                contract.model_dump()[field] == expected[field],
                f"{identity}: selected {field} contract changed",
            )
        for citation in contract.sources:
            require(citation.source in inventory.sources, f"{identity}: unknown source")
            require(
                ".." not in Path(citation.path).parts, f"{identity}: unsafe source path"
            )
        proof = contract.proof
        if proof.state in {"covered", "partial"}:
            if (
                proof.file not in {"checks/sync-test.py", "checks/key-auth-test.py"}
                or proof.file is None
            ):
                raise ContractError(f"{identity}: unsupported proof file")
            source = (ROOT.parent.parent / proof.file).read_text()
            require(
                f'with subtest("{proof.subtest}"):' in source,
                f"{identity}: nonexistent proving subtest",
            )
        require(
            proof.state != "covered" or expected["covered_subtest"] == proof.subtest,
            f"{identity}: unsubstantiated implementation claim",
        )
        require(
            proof.state != "pending" or proof.task > 1,
            f"{identity}: pending task missing",
        )
        validate_fixture(contract, cases[identity])


@app.command()
def main(
    inventory: Annotated[Path, typer.Option()] = DATA / "web-api.json",
    fixture: Annotated[list[Path] | None, typer.Option()] = None,
) -> None:
    """Accept a complete inventory and all fixtures, or exit nonzero."""
    paths = (
        fixture
        if fixture is not None
        else [
            inventory.parent / name
            for name in ("personal.json", "private-group.json", "global.json")
        ]
    )
    try:
        target = Inventory.model_validate_json(inventory.read_text())
        adapter = TypeAdapter(list[Fixture])
        cases = [
            case for path in paths for case in adapter.validate_json(path.read_text())
        ]
        validate(target, cases)
    except (OSError, ValidationError, ContractError, json.JSONDecodeError) as error:
        typer.echo(f"invalid contracts: {error}", err=True)
        raise typer.Exit(1) from error
    typer.echo(
        json.dumps(
            {
                "accepted": True,
                "contracts": len(target.contracts),
                "fixtures": len(cases),
                "formats": len(target.formats),
                "runtime_verified": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    app()
