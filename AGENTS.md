# Local agent instructions

## Documentation commit policy

- Documentation is public. `README.md`, `AGENTS.md`, and `docs/**` are committed.
- Commit documentation separately from code, configuration, migrations, and
  tests.
- Before committing documentation, check it for secrets, private hostnames, and
  local paths.

## Documentation layout

- `docs/DESIGN.md` describes what exists. Keep plans out of it.
- `docs/API.md` holds the wire contract.
- `docs/ROADMAP.md` holds plans, current work, and technical debt.
- `docs/TASK.md` holds the order and dependencies of open tasks.
- `docs/TESTING.md` holds verification tiers.
- `docs/adr/` holds the reasons for accepted decisions.

## Code commit policy

- Commit code, configuration, migrations, and tests in logical, atomic units.
- Each commit must have one coherent purpose and include the tests or fixtures
  needed to verify that purpose.
- Do not mix unrelated cleanup, dependency upgrades, refactors, or behavior
  changes in one commit.
- Before committing, inspect both the working tree and staged diff, then stage
  only the files and hunks belonging to that unit.
- Run verification proportional to the change before creating the commit.
- Keep all documentation changes out of code commits.

## Remote repository policy

- Do not run `git push` or otherwise update remote Git refs unless the user asks
  for that action in the current request.
- Merge to `main` only through a pull request and the `gitea-mq` queue. Use a
  merge commit for stacked pull requests so commit hashes stay stable.
- Land stacked pull requests bottom-up, one at a time.
- Enable auto-merge on a stacked pull request only after its parent has merged
  and its base is `main`. Only `main` requires the nixbot checks, so `gitea-mq`
  would merge into any other base without them.

## Agent coordination

- The root agent owns production code, documentation synthesis, integration,
  staging, and commits.
- Give every subagent a base commit, one bounded slice, explicit read scope, an
  exclusive write allowlist, the expected red/green result, and a verification
  tier.
- Only one agent may write a path. Run research and review in parallel.
- Subagents never stage, commit, amend, rebase, reset, or push.
- Handoffs contain: scope, base, evidence, observed contract, xotero gap, files
  touched, verification command/task ID/exit status, risks, and next atom.

## Verification

- Canonical automated integration is the x86_64-linux NixOS checks. See
  `docs/TESTING.md` for the tiers.
- Use real PostgreSQL and RustFS. Attachment downloads follow RustFS pre-signed
  URLs.
- Web Library is the only supported client. Never launch or modify an installed
  Zotero app or a normal profile or data directory.
- Build temporary runtimes from a `git+file://` flake so ignored Cargo targets
  and other scratch files never enter the Nix source closure.
- Cleanup requires confirmed results and exact recorded pueue task IDs. Never use
  a group-wide kill or broad deletion.
