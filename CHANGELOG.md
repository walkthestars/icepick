# Changelog

All notable changes to icepick will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-18

### Added

- Deterministic `schema-v1` JSON validation, edge derivation, and SHA-256 document digesting (`icepick.schema`).
- Batch IDA Pro extraction lane (`icepick extract`) supporting both `idalib` and autonomous `idat` backends with explicit `IDADIR` pinning, containment-mapped function-start caller/callee edges, optional FLIRT `.sig` application (`--sigs`), Hex-Rays decompilation capture, and top-K list bounding (`--top-k`).
- Idempotent SQLite ingestion (`icepick ingest` and `icepick ingest-manual`) with provenance lattice enforcement (`manual` labels outranking `ida` hints) and database inspection (`icepick show`).
- Diaphora SQLite diff export converter (`icepick diff-import`) emitting ranked rebase candidate JSON.
- Process-isolated worker queue supervisor (`icepick.queue`) enforcing one process per IDB, explicit `IDADIR` resolution, pre-flight license checks, process-tree timeout termination, and typed fault codes (`IDA_BUSY`, `TIMEOUT`, `IDA_LICENSE_ABSENT`, `DECOMPILE_FAILED`).
- Unicode-safe two-axis output bounding helpers (`icepick.trim`) and live-lane agent skill recipes (`skills/`).
