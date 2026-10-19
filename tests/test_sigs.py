"""Sig-application recording tests — pure, no IDA runtime.

Covers the ``--sigs`` lane contract: names are always recorded in
``provenance.sigs_applied``; application itself is best-effort and degrades
to record-only without raising.
"""

from __future__ import annotations

from icepick import extract, schema


class _HookWorld:
    """Fake world honouring the optional ``apply_sigs`` hook."""

    def __init__(self) -> None:
        self.applied: list[str] | None = None

    def apply_sigs(self, sig_files: list[str]) -> int:
        self.applied = list(sig_files)
        return len(sig_files)

    def func_eas(self) -> list[int]:
        return [0x1000]

    def func_flags(self, ea: int) -> int:
        return 0

    def block_eas(self, ea: int) -> list[int]:
        return [ea]

    def xrefs_to(self, ea: int) -> list[tuple[int, str]]:
        return []

    def xrefs_from(self, ea: int) -> list[tuple[int, str]]:
        return []

    def func_name(self, ea: int) -> str:
        return "sub_1000"

    def func_size(self, ea: int) -> int:
        return 10


class _PlainWorld(_HookWorld):
    """Fake world without the hook: record-only, never raising."""

    apply_sigs = None  # type: ignore[assignment]


class _RaisingWorld(_HookWorld):
    """Fake world whose hook explodes: still record-only, never raising."""

    def apply_sigs(self, sig_files: list[str]) -> int:
        raise RuntimeError("boom")


def test_hook_world_is_called_and_counted() -> None:
    world = _HookWorld()
    assert extract._apply_sigs_best_effort(world, ["a.sig", "b.sig"]) == 2
    assert world.applied == ["a.sig", "b.sig"]


def test_plain_world_degrades_to_record_only() -> None:
    assert extract._apply_sigs_best_effort(_PlainWorld(), ["a.sig"]) == 0


def test_raising_hook_degrades_to_zero() -> None:
    assert extract._apply_sigs_best_effort(_RaisingWorld(), ["a.sig"]) == 0


def test_emit_records_sig_names() -> None:
    document = extract.emit(_HookWorld(), sigs=["iw8.sig", "common.sig"])
    entries = document["provenance"]["sigs_applied"]
    assert entries == [{"name": "iw8.sig"}, {"name": "common.sig"}]
    assert schema.validate_extract(document) == []


def test_emit_without_sigs_has_empty_list() -> None:
    document = extract.emit(_PlainWorld())
    assert document["provenance"]["sigs_applied"] == []
    assert schema.validate_extract(document) == []
