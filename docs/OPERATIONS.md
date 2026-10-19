# icepick Operations Guide

End-user instructions for configuring IDA Pro 9.4+, running batch extractions safely, handling packed/encrypted binaries, and connecting `icepick` outputs to downstream tools.

---

## 1. Setting Up IDA Pro 9.4+ and `idalib`

`icepick` supports two IDA Pro execution backends:

- **`idalib` (recommended)**: Uses Hex-Rays' headless Python library (`idapro` wheel).
- **`idat`**: Spawns IDA's autonomous text-mode executable (`idat.exe` / `idat64.exe` with `-A -S<bootstrap>`).

### Installing the `idapro` wheel into your `uv` environment

IDA Pro ships the `idapro` wheel inside `<IDADIR>/idalib/python/`. Install it into the `icepick` virtual environment:

```powershell
# Windows (PowerShell)
uv pip install --python .venv/Scripts/python.exe "C:\Program Files\IDA Professional 9.5\idalib\python\idapro-0.0.10-py3-none-any.whl"
```

```bash
# Linux / macOS
uv pip install --python .venv/bin/python "/opt/idapro-9.5/idalib/python/idapro-0.0.10-py3-none-any.whl"
```

### How `icepick` resolves `IDADIR`

To prevent stale shell environment variables from pointing `idapro` at an outdated IDA installation, `icepick` resolves the IDA home directory in this exact order:

1. Explicit `--ida-home <DIR>` CLI flag (or `Job(ida_home=...)` in `icepick.queue`).
2. `Paths.ida-install-dir` inside `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` (Windows) or `~/.idapro/ida-config.json` (Linux/macOS).
3. Standard platform installation paths (e.g., `C:\Program Files\IDA Professional 9.5`), selecting the highest version containing a valid `idalib` / `idat` binary.
4. Inherited `IDADIR` environment variable **only** when `--trust-env-idadir` is explicitly passed.

---

## 2. Pre-Extraction Check: Encrypted or Packed `.text` Sections

Static IDA auto-analysis on a binary whose `.text` section is encrypted on disk (for example, SteamStub or custom runtime protectors) will finish without an IDA error, but produces unusable results:

- `.text` byte entropy near `7.9–8.0` bits/byte (compiled native code typically measures `6.0–6.8`).
- High function count created from `.pdata` exception records, but near-zero call edges (`edges << functions`) and zero FLIRT library hits.

**Handling procedure:**
1. Check `.text` entropy before running a full batch extraction (for example, with `toothpick triage <binary>`).
2. If `.text` is encrypted on disk, launch the binary inside an isolated VM until the stub decrypts `.text` in memory, capture a process memory dump, reconstruct the PE headers (`toothpick unpack dump.bin --reconstruct-pe --oep <hex> --out dump_fixed.exe`), and run `icepick extract` on the reconstructed dump.

---

## 3. Running Supervised Batch Queues (`icepick.queue`)

Because `idalib` is single-threaded and supports only one open database per process, never call `idapro.open_database` concurrently across threads in a single Python process. Instead, use `icepick.queue.Supervisor` or `run_queue`, which isolates each IDB inside its own child worker process:

```python
from pathlib import Path
from icepick.queue import Job, run_queue

jobs = [
    Job(
        target=Path("samples/engine_v1.dll"),
        out=Path("extracts/engine_v1.json"),
        backend="idalib",
        ida_home=Path(r"C:\Program Files\IDA Professional 9.5"),
        top_k=500,
        sigs=("vc64rtf",),
        timeout=900.0,
    ),
    Job(
        target=Path("samples/engine_v2.dll"),
        out=Path("extracts/engine_v2.json"),
        backend="idalib",
        ida_home=Path(r"C:\Program Files\IDA Professional 9.5"),
        top_k=500,
        sigs=("vc64rtf",),
        timeout=900.0,
    ),
]

results = run_queue(jobs, max_workers=2, result_path="extracts/queue_report.json")
for r in results:
    if not r.ok:
        print(f"[FAIL] {r.job_id}: {r.error_code} ({r.error})")
    else:
        print(f"[OK]   {r.job_id} -> {r.out} in {r.elapsed:.1f}s")
```

### Worker Error Codes (`ErrorCode`)

| Code | Meaning & Resolution |
|------|----------------------|
| `IDA_HOME_UNRESOLVED` | Could not locate a valid IDA installation. Pass `--ida-home` or configure `ida-config.json`. |
| `IDA_LICENSE_ABSENT` | `idapro` could not be imported or no active IDA license was found. |
| `IDA_BUSY` | The target `.i64`/`.idb` is locked by another running IDA instance. Close the GUI or give each job its own working copy. |
| `TIMEOUT` | Worker exceeded `timeout` seconds; the supervisor terminated the entire worker process tree. |
| `DECOMPILE_FAILED` | Fatal Hex-Rays decompiler error across the job. |
| `WORKER_FAILED` | Worker exited non-zero (`r.stderr` contains the capped diagnostic tail). |
| `WORKER_NO_RESULT` | Worker exited `0` without producing the expected `--out` JSON file. |

---

## 4. Feeding `icepick` Extracts into Toothpick

`icepick` emits `schema-v1` JSON documents that [`toothpick`](https://github.com/walkthestars/toothpick) consumes directly:

```bash
# 1. Extract from IDA Pro via icepick
uv run icepick extract target.exe --backend idalib \
  --ida-home "C:\Program Files\IDA Professional 9.5" \
  --out ida_extract.v1.json

# 2. Ingest into Toothpick's SQLite graph
uv run toothpick ingest-ida ida_extract.v1.json --db toothpick.db
```

If you also diffed two versions of the binary with Diaphora:

```bash
# 3. Export ranked Diaphora match candidates
uv run icepick diff-import diaphora.sqlite --min-score 0.85 --out candidates.json

# 4. Pass as priors to Toothpick's structural rebase engine
uv run toothpick rebase <old_sha> <new_sha> --db toothpick.db \
  --priors candidates.json --out offset_map.json
```
