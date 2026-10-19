# icepick Schema & Database Reference

`icepick` defines two versioned JSON document schemas (`SCHEMA_VERSION = "v1"`) and one SQLite analysis database schema.

---

## 1. Extract Document (`ida_extract.v1.json`)

Produced by `icepick extract` and consumed by `icepick ingest` (or `toothpick ingest-ida`).

```json
{
  "schema_version": "v1",
  "provenance": {
    "ida_version": "9.5",
    "idb_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "auto_analysis": true,
    "backend": "idalib",
    "generator": "icepick-extract/0.1.0",
    "sigs_applied": ["vc64rtf"]
  },
  "functions": [
    {
      "ea": 5368713216,
      "name": "sub_140001000",
      "name_source": "ida",
      "demangled": null,
      "prototype": "__int64 __fastcall sub_140001000(__int64 a1)",
      "flags": 5120,
      "size": 144,
      "block_eas": [5368713216, 5368713264, 5368713312],
      "callers": [5368717312],
      "callees": [5368713600],
      "xrefs_to": [5368717340],
      "xrefs_from": [5368713248],
      "decompiled": "__int64 __fastcall sub_140001000(__int64 a1)\n{\n  return sub_140001180(a1);\n}\n",
      "decompile_status": "ok",
      "rtti_refs": [],
      "pdb_type": null
    }
  ],
  "edges": [
    {
      "src": 5368713216,
      "dst": 5368713600,
      "kind": "call"
    }
  ]
}
```

### Field Invariants

- **Addresses (`ea`, `src`, `dst`, `callers`, `callees`, `block_eas`, `xrefs_*`)**: Non-negative integers (hex strings such as `"0x140001000"` are also accepted on ingest and normalized to `int`).
- **Callers and callees are function starts**: Every entry in `callers` and `callees` is mapped via basic-block containment to the start address of the calling or called function, sorted in ascending order, and capped at `--top-k`.
- **Decompile status**: Either `"ok"` (when Hex-Rays decompilation succeeded) or `"DECOMPILE_FAILED(<reason>)"` (e.g., `"DECOMPILE_FAILED(hexrays_unavailable)"`), never an unhandled exception.
- **Provenance**:
  - `idb_sha256`: 64-character lowercase hex SHA-256 of the analyzed binary or IDB.
  - `backend`: `"idalib"` or `"idat"`.
  - `sigs_applied`: Sorted list of FLIRT signature names applied during the session.

---

## 2. Manual Labels Document (`external_labels.v1.json`)

Consumed by `icepick ingest-manual` to attach hand-authored reverse-engineering symbols, custom format recovery results, or analyst annotations.

```json
{
  "schema_version": "v1",
  "kind": "labels",
  "source": "manual",
  "generator": "analyst-labels",
  "labels": [
    {
      "ea": "0x140001000",
      "name": "Entity_Alloc",
      "kind": "func",
      "prototype": "Entity *__fastcall Entity_Alloc(Pool *pool, uint32_t flags)",
      "comment": "Primary entity allocator"
    },
    {
      "ea": "0x140050000",
      "name": "g_EntityPool",
      "kind": "data"
    }
  ]
}
```

### Provenance Precedence

`icepick` enforces a strict source hierarchy in `analysis.db`:

1. `source = "manual"` (from `ingest-manual`)
2. `source = "ida"` (from `ingest`)

When `icepick ingest` loads a new IDA extract into an existing database, any address that already holds a `source = "manual"` label retains its manual `name` and `prototype`.

---

## 3. SQLite Database Schema (`analysis.db`)

Created and maintained by `icepick.ingest`:

| Table | Primary Key | Columns |
|-------|-------------|---------|
| `functions` | `ea` | `ea`, `name`, `name_source`, `demangled`, `prototype`, `flags`, `size`, `block_eas_json`, `callers_json`, `callees_json`, `xrefs_to_json`, `xrefs_from_json`, `decompiled`, `decompile_status`, `rtti_refs_json`, `pdb_type`, `doc_id` |
| `edges` | `(src, dst, kind)` | `src`, `dst`, `kind` |
| `labels` | `ea` | `ea`, `name`, `kind`, `prototype`, `comment`, `source`, `doc_id` |
| `ingests` | `doc_id` | `doc_id` (SHA-256 digest), `doc_kind`, `doc_source`, `ida_version`, `idb_sha256`, `backend`, `generator`, `funcs`, `edges`, `labels` |
