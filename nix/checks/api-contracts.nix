{ pkgs }:
let
  python = pkgs.python3.withPackages (p: [
    p.mypy
    p.pydantic
    p.pytest
    p.typer
  ]);
in
pkgs.runCommand "xotero-api-contracts"
  {
    nativeBuildInputs = [ python ];
    src = ../..;
  }
  ''
    cp -r "$src" source
    chmod -R u+w source
    cd source
    export PYTHONDONTWRITEBYTECODE=1
    python checks/contracts/validate.py
    mypy checks/contracts/models.py checks/contracts/wire.py checks/contracts/fixtures.py checks/contracts/validate.py
    pytest -p no:cacheprovider checks/contracts/test_validator.py checks/contracts/test_wire.py -q
    mkdir -p "$out"
    cp checks/contracts/data/*.json "$out/"
  ''
