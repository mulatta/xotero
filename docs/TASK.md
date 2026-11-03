# Task order

This file holds the order and dependencies of the open tasks. Task scope and
acceptance live in `docs/ROADMAP.md`; tasks here are referenced by number only.

Dependencies are inferred from each task's acceptance criteria. Confirm an edge
against the code when the task starts, and update this file when it changes.

## Graph

```
                          main
                            |
                 +----------+----------+
                 | P1 pin RustFS        |
                 | P2 move VM scripts   |  (decision pending)
                 | P3 report upstream   |  (independent)
                 +----------+----------+
                            |
       +--------------------+--------------------+
       v                    v                    v
   Lane API             Lane packaging       Lane operations
   (Wave D)                                  (Wave F)

   22a listings/paging  27 translation-srv   33 migrate
    |                    |                    |
    v                    |                    v
   22b query filters     |                   34 single process
    :                    |
    v                    |
   22c full text, groups |
    |                    |
    v                    |
   23 conditional CRUD   |
    |                    |
    v                    |                   35 SIGTERM
   26 file URL/range     |                    :
    |                    |                    v
    v                    |                   36 liveness/readiness
   24 children/tree      |  <-- 22a, 22b
    |                    |
    v                    |
   25 settings <..23     |
    |                    |
    |                    +----> 28 export <-- 22a
    |
    |                   29 web-library assets
    |                    |
    |                    v
    +...............>   30 session gateway
                         |
                         +----> 32 browser gate
                         |
                         +----> 31 deploy surface <-- 27
                         |       |
                         |       v
                         |      38 release checks
                         |
                         +----> 37 backup/restore <-- 33, 26

   28, 32, Wave D ----> 39 Web workflows ----> 40 ledger ----> F1-F4

   ---->  hard dependency: the target needs the source merged
   ....>  soft dependency: shared code, or needed for the target to work end to end
```

## Prerequisite cleanup

- P1. Pin RustFS to its own nixpkgs input so nixpkgs bumps stop rebuilding the
  patched fixture. Remove the input and the patch once an upstream release
  emits StorageClass in multipart listings.
- P2. Decide whether VM test scripts move from `checks/*.py` to
  `nix/checks/<name>/`. Do it before Task 22 or after Task 26, since every
  Wave D task edits `checks/sync-test.py`.
- P3. Report the missing StorageClass in ListMultipartUploads to RustFS.

## Lanes

- API: 22a, 22b, 22c, 23, 26, 24, 25, one at a time. Each edits
  `checks/sync-test.py` and `checks/contracts`, and only one agent may write a
  path. 22b filters the listings 22a builds; 22c shares only the `versions`
  format with them. Split contract data into `checks/contracts/data/` with 22a.
- Packaging: 27 and 29 can run beside the API lane.
- Operations: 33 then 34, 35 then 36. They can run beside the other lanes.
  The first of these tasks creates the `nixos-operations` check.

## Join points

- 24 needs 22a and 22b.
- 28 needs 22a and 27.
- 30 needs 29. It needs Wave D to work end to end, and it creates the
  `nixos-web-library` check.
- 31 needs 27 and 30. 38 needs 31.
- 32 needs 30.
- 37 needs 33, 26 and 30.
- 39 needs 28, 32 and Wave D. 40 follows 39, and F1 to F4 follow 40.

## Unconfirmed edges

- 28 on 22a: assumes export rides on the item listing (`format=` on `/items`).
- 26 independent of 22: inferred from acceptance text only.
- 24 on 22a and 22b: its publications tag listing uses the 22b tag filters.
