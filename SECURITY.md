# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Use [GitHub Private Vulnerability Reporting](https://github.com/walkthestars/icepick/security/advisories/new)
to submit a report privately to the maintainer. Include:

- The affected module or command (`icepick extract`, `icepick ingest`, `icepick.queue`, `icepick.schema`).
- A minimal reproducer input or command sequence.
- Impact assessment.

You will receive an acknowledgment within 72 hours and a coordinated remediation timeline once the issue is reproduced.

## Security Model & Operating Boundaries

1. **IDA Pro is not a security boundary**: Opening untrusted binaries or `.i64`/`.idb` databases in IDA Pro (`icepick extract`) invokes native file loaders, processor modules, and embedded database metadata. Always run `icepick extract` against untrusted targets inside a snapshotted, disposable virtual machine with no host credentials or writable mounts.
2. **Read-only extraction**: `icepick extract` opens IDBs in read-only mode (`save=False`) and refuses `--apply-names`.
3. **Zero bundled IDA components**: `icepick` ships zero IDA binaries, wheels, or signature files, and `src/icepick` has zero third-party runtime dependencies outside the Python standard library (`tests/test_no_ida_imports.py`).
