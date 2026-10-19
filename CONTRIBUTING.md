# Contributing to icepick

Thanks for your interest in contributing to icepick!

## Getting Started

Prerequisites:
- Python **3.11+**
- [`uv`](https://docs.astral.sh/uv/) for environment management

No IDA Pro installation is required to run the bridge test suite: `icepick` is stdlib-only and isolates all IDA imports inside deferred functions in `icepick.extract`, verified by `tests/test_no_ida_imports.py`.

```bash
git clone https://github.com/walkthestars/icepick.git
cd icepick
uv sync --locked --dev
uv run pytest -p no:faulthandler
```

## Architectural Invariants

1. **Stdlib-only runtime**: `src/icepick` must not depend on any third-party packages. `tests/test_no_ida_imports.py` AST-checks every file in `src/` and fails on non-stdlib imports.
2. **Deferred IDA imports in `extract.py` only**: Only `src/icepick/extract.py` may reference `idapro`, `idaapi`, `idc`, `idautils`, or `ida_*`, and those imports must remain deferred inside functions (never at module top level).
3. **No hard-coded toolchain paths**: Never embed `ida64.exe`, `idat.exe`, or install paths in `src/`. All IDA path resolution flows through `icepick.extract.resolve_ida_home`.
4. **Deterministic output**: All emitted JSON documents must be sorted, bounded by `--top-k`, and byte-identical across repeated runs.

## Sign Your Work (DCO)

icepick uses the [Developer Certificate of Origin](DCO) **and** a Contributor License Agreement ([CLA.md](CLA.md)). They do different jobs and neither replaces the other: the DCO certifies **where the code came from** (every commit, `Signed-off-by`), while the CLA grants the project's maintainer the relicensing rights described in [CLA.md](CLA.md) (once per contributor). You retain copyright in your contribution under both.

Add a `Signed-off-by` line to each commit certifying that you wrote the code (or otherwise have the right to submit it) and are contributing it under AGPL-3.0-only and the terms of `CLA.md`. Pass `-s` to `git commit`:

```bash
git commit -s -m "feat(schema): ..."
```

## Contributor License Agreement (CLA)

In addition to the DCO, icepick asks first-time contributors to accept the [Contributor License Agreement](CLA.md) — **once, ever**, not per pull request. It grants the Project Owner the right to license your contribution as part of the project under other terms (such as a commercial or enterprise license), while your contribution itself remains public under AGPL-3.0-only as part of the open-source repository.

**How to sign:** on your first pull request, the CLA Assistant bot will comment with instructions. Read [CLA.md](CLA.md), then comment this exact phrase on the pull request:

```text
I have read the CLA Document and I hereby sign the CLA
```

The bot records your signature on the `cla-signatures` branch and marks the check green for all present and future pull requests.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(<scope>): ...`
- `fix(<scope>): ...`
- `docs(<scope>): ...`
- `test(<scope>): ...`
- `chore(<scope>): ...`

## Pull Request Checklist

- [ ] `uv run pytest -p no:faulthandler` passes cleanly
- [ ] `tests/test_no_ida_imports.py` passes (stdlib-only, no top-level IDA imports)
- [ ] New features include deterministic offline tests under `tests/`
- [ ] Documentation (`README.md`, `docs/`) is updated if CLI flags or schema fields changed
- [ ] `CHANGELOG.md` is updated
- [ ] Every commit carries a valid `Signed-off-by` trailer (`git commit -s`) and the [CLA](CLA.md) is signed (first-time contributors)
