# icepick CLI Reference

`icepick` can be invoked either as `icepick <command>` (installed console script) or `python -m icepick <command>`.

---

## Global Options & Exit Codes

- `--version` — Print `icepick <version> (schema v1)` and exit.
- `-h`, `--help` — Show command help and exit.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Validation error, database error, or IDA extraction failure (details printed to `stderr`; database left unmodified) |
| `2` | Command-line usage error |

---

## 1. `icepick extract`

Extracts a deterministic `schema-v1` JSON inventory from an input binary or `.i64`/`.idb` database using IDA Pro (`idalib` or `idat`).

```bash
icepick extract <INPUT> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<INPUT>` | **required** | Path to the input binary or IDB to analyze |
| `-o`, `--out <PATH>` | `stdout` | Write the `schema-v1` JSON document to `<PATH>` |
| `--top-k <N>` | `500` | Maximum entries per caller, callee, xref, and basic-block list |
| `--backend idalib\|idat` | `idalib` | Provenance backend tag (`idalib` standalone or `idat` autonomous batch mode) |
| `--ida-home <DIR>` | auto-resolved | Explicit IDA Pro installation directory to pin as `IDADIR` |
| `--trust-env-idadir` | `false` | Trust an inherited `IDADIR` environment variable (ignored by default to prevent stale environment pins) |
| `--sigs <SIG>` | — | Private FLIRT `.sig` name or path to apply before extraction (repeatable, best-effort) |
| `--quiet` | `false` | Suppress summary messages when writing `--out` |

> **Note**: `--apply-names` is intentionally refused with exit code `1`. `icepick extract` is strictly read-only and never modifies or saves changes back into the source IDB.

### Example

```bash
uv run icepick extract target.exe \
  --backend idalib \
  --ida-home "C:\Program Files\IDA Professional 9.5" \
  --top-k 500 \
  --sigs vc64rtf \
  --out extract.json
```

---

## 2. `icepick ingest`

Validates and ingests one or more `ida_extract.v1` JSON documents into a SQLite analysis database.

```bash
icepick ingest <DB> <DOCUMENT...> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<DB>` | **required** | Path to the SQLite analysis database (created if absent) |
| `<DOCUMENT...>` | **required** | One or more `schema-v1` extract JSON files |
| `--kind extract\|labels` | `extract` | Force document kind instead of using the subcommand default |
| `--force` | `false` | Re-apply a document even if its SHA-256 digest is already recorded in `ingests` |
| `--dry-run` | `false` | Validate documents and compute counts without writing to `<DB>` |
| `--json` | `false` | Emit machine-readable JSON status reports |
| `--quiet` | `false` | Print nothing on success |

### Example

```bash
uv run icepick ingest analysis.db extract.json --json
```

---

## 3. `icepick ingest-manual`

Validates and ingests one or more hand-authored `external_labels.v1` JSON documents into a SQLite analysis database with `source='manual'`. Manual labels outrank `source='ida'` labels and are never overwritten by subsequent IDA extract ingests.

```bash
icepick ingest-manual <DB> <DOCUMENT...> [options]
```

Accepts the same options as `icepick ingest` (`--force`, `--dry-run`, `--json`, `--quiet`).

### Example

```bash
uv run icepick ingest-manual analysis.db external_labels.json
```

---

## 4. `icepick show`

Summarizes the contents and ingestion provenance of a SQLite analysis database.

```bash
icepick show <DB> [--json]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<DB>` | **required** | Path to the SQLite analysis database |
| `--json` | `false` | Emit the summary and provenance records as JSON |

### Example output

```text
analysis.db: edges=50005, functions=23397, ingests=2, labels=2522
  extract 8f3a1c90e4b2 source=ida backend=idalib ida=9.5 funcs=23397 edges=50005 labels=2500
  labels  41d902b7a11c source=manual backend=manual ida=n/a funcs=0 edges=0 labels=22
```

---

## 5. `icepick diff-import`

Reads a Diaphora SQLite diff export (`results` table) and converts matched function pairs into ranked rebase candidate JSON records.

```bash
icepick diff-import <DIFF_SQLITE> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<DIFF_SQLITE>` | **required** | Path to the Diaphora `.sqlite` diff database |
| `-o`, `--out <PATH>` | `stdout` | Write candidate JSON to `<PATH>` |
| `--min-score <FLOAT>` | `0.5` | Minimum similarity ratio (`0.0`–`1.0`) required to include a match |
| `--limit <N>` | `500` | Maximum number of candidate pairs to emit (sorted by descending score, then `old_ea`) |
| `--quiet` | `false` | Suppress summary output when writing `--out` |

### Example

```bash
uv run icepick diff-import patch_diff.sqlite --min-score 0.90 --limit 250 --out candidates.json
```
