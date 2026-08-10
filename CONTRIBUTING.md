# Contributing to MakopaOS

MakopaOS advances through small pull requests with reproducible evidence. A
clean checkout must explain how to build, test, and review every change without
depending on private notes or local state.

## Sources of truth

When tracked sources disagree, use this order and surface the conflict in the
pull request:

1. `docs/architecture/overview.md` for product and architecture constraints;
2. `docs/roadmap/implementation-roadmap.md` for sequencing and acceptance;
3. accepted decisions under `docs/architecture/decisions/` when present;
4. code and tests for current behavior;
5. supporting documentation.

## Change contract

Keep one roadmap work item or one bounded correction in each pull request.
Before editing, record these points in the issue or pull-request description:

- scope and non-scope;
- acceptance criteria;
- affected requirements and risks;
- expected paths;
- validation commands.

Proposed roadmap work is not implementation approval. Consequential changes to
the architecture require an accepted decision record before implementation.

## Validation

For the current boot sector:

```sh
python -m unittest discover -s tests -v
nasm -Wall -Werror -f bin -o boot.bin boot.asm
python scripts/verify_boot.py boot.bin
```

Run the narrowest relevant check first, then the complete documented suite.
Never describe an unexecuted check as passing; record unavailable tools and
residual risk in the pull request.

## Repository hygiene

- Do not commit generated disk images, credentials, private paths, transcripts,
  or machine-local state.
- Keep privileged code small and explain every unsafe boundary.
- Pin build and workflow dependencies when practical.
- Preserve compatibility intentionally; document any break in the architecture
  and roadmap.
- Prefer terse commits that describe the engineering outcome.
