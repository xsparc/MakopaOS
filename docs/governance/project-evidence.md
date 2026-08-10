# Project evidence

The project evidence registry is a derived traceability index. It connects
objectives, requirements, roadmap work, implementation, verification,
validation, and risk without replacing the documents or code that define them.

## Authority boundary

When sources disagree, the order in `CONTRIBUTING.md` applies:

1. architecture;
2. roadmap;
3. accepted decisions;
4. code and tests;
5. supporting documentation.

`project-evidence.toml` is not an additional authority. Repair the authoritative
source first, then synchronize the registry. Machine-local state, private paths,
and untracked notes are not valid evidence. Every local evidence path must be
present in the repository's Git index.

## Registry records

- **Objectives** state durable outcomes and link to their source and validation.
- **Requirements** link objectives to roadmap, design, implementation,
  verification, validation, and risk.
- **Work items** record bounded delivery state, approval, acceptance, and
  evidence.
- **Research decisions** record only explicitly accepted dispositions with
  review dates and public sources.
- **Review dates** make staleness observable without changing static structure.

Planned requirements need roadmap and design references. Implemented
requirements additionally need implementation, verification, validation, and
risk evidence. Deferred requirements require both a reason and a trigger for
reconsideration.

## Validation

Run the static structural gate without network access:

```sh
python scripts/check_project_evidence.py
```

Run the closure gate with the current date:

```sh
python scripts/check_project_evidence.py --as-of YYYY-MM-DD --strict
```

The command emits stable JSON and exits with code `2` for structural failures.
Without `--strict`, overdue reviews produce a warning and exit successfully;
strict mode treats warnings as a failed closure gate.

The checker rejects malformed records, unknown IDs, unsafe or missing local
references, untracked files, missing Markdown anchors or Python symbols,
unindexed accepted decisions, and incomplete evidence for implemented
requirements. Accepted decisions may express their status as `Status: Accepted`
or as a `Status` Markdown heading whose next non-empty line is `Accepted`.

## Maintenance

Update the registry when a requirement changes state, a bounded work item is
approved or verified, an architecture decision is accepted, research is
explicitly adopted or rejected, or referenced evidence moves. Review the full
index at each phase gate and at least monthly while the project is active.
