<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPLv3-blue" alt="License: AGPL-3.0-only"></a>
  <img src="https://img.shields.io/badge/IDA%20Pro-9.4%2B-orange" alt="IDA Pro 9.4+">
  <img src="https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen" alt="Dependencies: stdlib only">
</p>

<h1 align="center">icepick</h1>

<p align="center">A deterministic IDA Pro extraction gateway in pure Python.<br>
Batch-extracts IDA databases into versioned, provenance-tagged JSON and ingests them into SQLite.</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#cli-reference">CLI</a> ·
  <a href="docs/SCHEMA.md">Schema Reference</a> ·
  <a href="docs/OPERATIONS.md">Operations Guide</a>
</p>

---

`icepick` sits between IDA Pro 9.4+ and downstream analysis databases (including [`toothpick`](https://github.com/walkthestars/toothpick)). Instead of letting agents or scripts query a live, single-threaded IDA process with unbounded dumps, `icepick` runs batch extraction inside isolated worker processes, emits deterministic `schema-v1` JSON documents (sorted, top-K capped, SHA-256 digested), and ingests them idempotently into SQLite.

The bridge package (`src/icepick`) uses the Python standard library exclusively and contains zero top-level IDA imports, so `ingest`, `ingest-manual`, `show`, and `diff-import` run on any machine without IDA installed.

## Quick start

### Prerequisites

- **Python**: 3.11+ managed by [`uv`](https://docs.astral.sh/uv/)
- **For `icepick extract` only**: IDA Pro 9.4+ (`idalib` or `idat`) licensed on the extraction host. No IDA binaries, wheels, or signatures are bundled in this repository.
  To enable the `idalib` backend on Windows, install the wheel shipped with your IDA distribution into your Python environment:
  ```powershell
  uv pip install "C:\Program Files\IDA Professional 9.5\idalib\python\idapro-0.0.10-py3-none-any.whl"
  ```

### Installation

```bash
git clone https://github.com/walkthestars/icepick.git
cd icepick
uv sync --locked
```

### Core workflow

```bash
# 1. Extract a deterministic schema-v1 inventory from a binary or IDB
uv run icepick extract target.exe --backend idalib \
  --ida-home "C:\Program Files\IDA Professional 9.5" \
  --out extract.json

# 2. Ingest the extract document into SQLite (exactly-once, idempotent)
uv run icepick ingest analysis.db extract.json

# 3. Overlay hand-authored symbols or format labels (outranks IDA hints)
uv run icepick ingest-manual analysis.db external_labels.json

# 4. Inspect database counts and ingestion provenance
uv run icepick show analysis.db

# 5. Convert a Diaphora SQLite diff export into ranked rebase candidates
uv run icepick diff-import diaphora_diff.sqlite --min-score 0.85 --out candidates.json
```

## Architecture

```text
  [Target Binary / IDB]
           │
           ▼
  ┌────────────────────────────────────────────────────────┐
  │  icepick extract (1 worker process per IDB)            │
  │  Backends: idalib (headless) | idat -A -S (autonomous) │
  │  Explicit IDADIR pinning · read-only (save=False)      │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
                ida_extract.v1.json (sorted, top-K capped)
                             │
         ┌───────────────────┴───────────────────┐
         ▼                                       ▼
  ┌─────────────────────────┐           ┌─────────────────────────┐
  │ icepick ingest          │           │ toothpick ingest-ida    │
  │ → analysis.db           │           │ → toothpick.db          │
  └────────────┬────────────┘           └─────────────────────────┘
               ▲
               │
  ┌────────────┴────────────┐
  │ icepick ingest-manual   │
  │ (external_labels.json)  │
  │ source='manual' > 'ida' │
  └─────────────────────────┘
```

### Key design guarantees

1. **One worker process per IDB**: `idalib` is single-threaded and supports one active database per process. `icepick.queue` spawns a dedicated child process per extraction job and reaps the full process tree (`taskkill /T` on Windows, `killpg` on POSIX) on timeout.
2. **Explicit `IDADIR` resolution**: Worker supervisors never trust an inherited shell `IDADIR` unless `--trust-env-idadir` is explicitly passed. The IDA installation path is resolved from `--ida-home`, `~/.idapro/ida-config.json` (`Paths.ida-install-dir`), or standard platform install directories.
3. **Containment-mapped call graph**: Call cross-references inside basic blocks are mapped back to their containing function start addresses and inverted so both `callers` and `callees` are guaranteed to be canonical function entry points.
4. **Provenance lattice**: `ingest` tags symbols with `source='ida'`. `ingest-manual` tags hand-authored symbols with `source='manual'`. Re-ingesting an IDA extract never overwrites a `manual` label.

## CLI reference

See [docs/CLI.md](docs/CLI.md) for the full option reference and exit codes.

| Command | Input → Output | Description |
|---------|----------------|-------------|
| `icepick extract <input>` | Binary/IDB → `schema-v1` JSON | Runs IDA auto-analysis (`idalib` or `idat`), applies optional FLIRT `--sigs`, extracts functions, blocks, callers, callees, xrefs, RTTI refs, and Hex-Rays pseudocode capped at `--top-k` (default `500`). |
| `icepick ingest <db> <doc...>` | Extract JSON → SQLite `DB` | Validates and ingests one or more `ida_extract.v1` documents. Re-running an identical digest is a no-op (`already-ingested`) unless `--force` is passed. Supports `--dry-run` and `--json`. |
| `icepick ingest-manual <db> <doc...>` | Labels JSON → SQLite `DB` | Validates and ingests `external_labels.v1` documents (`source='manual'`), outranking IDA-generated names. |
| `icepick show <db>` | SQLite `DB` → Summary | Prints function, edge, label, and per-document provenance counts (`--json` for machine output). |
| `icepick diff-import <sqlite>` | Diaphora DB → Candidates JSON | Reads a Diaphora SQLite export (`results` table) and emits ranked rebase candidate records (`--min-score`, `--limit`, `--out`). |

## Supervised batch queue (`icepick.queue`)

To extract multiple binaries or IDBs concurrently with strict timeout and license gating, use `icepick.queue.run_queue` or `Supervisor`:

```python
from icepick.queue import Job, run_queue

jobs = [
    Job(target="bin/client_v1.exe", out="out/client_v1.json", backend="idalib", timeout=600),
    Job(target="bin/client_v2.exe", out="out/client_v2.json", backend="idalib", timeout=600),
]

results = run_queue(jobs, max_workers=2, result_path="out/batch_report.json")
for res in results:
    print(res.job_id, res.ok, res.error_code, res.elapsed)
```

Every `JobResult` reports a deterministic `error_code` on failure: `IDA_LICENSE_ABSENT`, `IDA_HOME_UNRESOLVED`, `IDA_BUSY`, `TIMEOUT`, `DECOMPILE_FAILED`, `WORKER_FAILED`, `WORKER_NO_RESULT`, or `LAUNCH_FAILED`.

## Output bounding (`icepick.trim` & `skills/`)

When operating a live IDAPython or `ida-mcp` session inside a VM, `icepick.trim` provides Unicode-safe two-axis truncation (`truncate_text`, `cap_sequence`, `candidate_card`) enforcing `DEFAULT_MAX_LINES = 200`, `DEFAULT_MAX_CHARS = 8000`, and `DEFAULT_MAX_ITEMS = 50`. Ready-to-paste bounded IDAPython snippets are included in [`skills/ida-extract.md`](skills/ida-extract.md) and [`skills/ida-domain.md`](skills/ida-domain.md).

## Development

```bash
uv sync --locked --dev
uv run pytest -p no:faulthandler
```

All 263 unit and integration tests run offline without IDA installed (live `idalib` extraction tests automatically skip when `idapro` is absent).

## Security & known limitations

- **Run `extract` in a disposable VM**: IDA Pro loaders and processor modules parse untrusted binary headers with full user privileges. Always run `icepick extract` inside a snapshotted VM with no host credentials. See [SECURITY.md](SECURITY.md).
- **Encrypted or packed `.text` sections**: Running static IDA auto-analysis on an executable whose `.text` section is encrypted on disk (entropy near `8.0` bits/byte) produces spurious function boundaries and empty call graphs. Check section entropy first; for runtime-decrypted binaries, capture a memory dump and extract from the reconstructed image. See [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Two things are asked of contributors: a `Signed-off-by` line on every commit (the [Developer Certificate of Origin](DCO), `git commit -s`; CI checks it), and a one-time acceptance of the [Contributor License Agreement](CLA.md) on a contributor's first pull request.

## License

AGPL-3.0-only, with commercial/enterprise dual licensing available. See [LICENSE](LICENSE), [COPYRIGHT](COPYRIGHT), and [CLA.md](CLA.md).

Running unmodified icepick locally places no obligations on your own code or analysis artifacts. Modifying icepick, distributing modified versions, or operating a modified icepick over a network triggers the AGPL-3.0 copyleft/network provisions — offer those modifications under the same license, or contact the Project Owner (`walkthestars`) for a commercial enterprise license.
