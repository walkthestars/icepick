"""Call-graph correctness — containment mapping + inversion (pure, no IDA runtime).

Regression for the Selaco shakedown finding: ``callers``/``callees`` must hold
*function starts* (a call site lives mid-function), and ``callees`` must be
completed by inversion because entry-address xrefs can never see mid-function
calls. Raw instruction-level detail always stays in ``xrefs_to``/``xrefs_from``.
"""

from __future__ import annotations

from icepick import extract, schema


class _FakeWorld:
    """Three functions; A calls B mid-function, B calls C, plus noise."""

    FUNCS = {0x1000: ("a", 0x50), 0x2000: ("b", 0x50), 0x3000: ("c", 0x50)}
    TO = {
        0x2000: [(0x1010, "call")],  # call inside A, far from A's entry
        0x3000: [(0x2010, "call"), (0x9999, "call")],  # padding xref must drop
        0x1000: [(0x2008, "data")],
    }
    FROM = {
        0x1000: [(0x2008, "data")],
    }

    def func_eas(self) -> list[int]:
        return sorted(self.FUNCS)

    def func_flags(self, ea: int) -> int:
        return 0

    def block_eas(self, ea: int) -> list[int]:
        return [ea]

    def xrefs_to(self, ea: int) -> list[tuple[int, str]]:
        return list(self.TO.get(ea, []))

    def xrefs_from(self, ea: int) -> list[tuple[int, str]]:
        return list(self.FROM.get(ea, []))

    def func_name(self, ea: int) -> str:
        return self.FUNCS[ea][0]

    def func_size(self, ea: int) -> int:
        return self.FUNCS[ea][1]


def _doc() -> dict:
    return extract.emit(_FakeWorld())


def test_callers_hold_function_starts_not_sites() -> None:
    funcs = {f["ea"]: f for f in _doc()["funcs"]}
    assert funcs[0x2000]["callers"] == [0x1000]  # not [0x1010]
    assert funcs[0x3000]["callers"] == [0x2000]  # 0x9999 padding dropped
    assert funcs[0x1000]["callers"] == []


def test_callees_completed_by_inversion() -> None:
    funcs = {f["ea"]: f for f in _doc()["funcs"]}
    assert funcs[0x1000]["callees"] == [0x2000]  # mid-A call, invisible at entry
    assert funcs[0x2000]["callees"] == [0x3000]
    assert funcs[0x3000]["callees"] == []


def test_edges_cover_every_caller_pair() -> None:
    pairs = {
        (e["src"], e["dst"]) for e in _doc()["edges"] if e["kind"] == "call"
    }
    assert (0x1000, 0x2000) in pairs
    assert (0x2000, 0x3000) in pairs


def test_raw_xref_detail_preserved() -> None:
    funcs = {f["ea"]: f for f in _doc()["funcs"]}
    assert (0x1010, "call") in [
        (x["ea"], x["kind"]) for x in funcs[0x2000]["xrefs_to"]
    ]


def test_callgraph_document_validates() -> None:
    assert schema.validate_extract(_doc()) == []
