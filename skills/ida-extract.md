---
name: ida-extract
description: Bounded-emit IDAPython recipes for Code-Mode agents driving icepick's live lane — top-K, max-lines, IDs-not-blobs, bulk through `icepick ingest`.
---

# IDA extract — bounded emission (live lane)

You are a Code-Mode agent with IDAPython in a *live* IDA session (idalib worker or
hosted IDA). The lane is **fenced**: what you print to your own transcript is
context you will never get back, and what you paste into a report is a blob a
reviewer has to scroll past. Every snippet below therefore emits **small,
identified, bounded** results — counts first, IDs next, text last.

Bulk data never crosses this boundary. It goes out as a schema-v1 JSON document
that `icepick ingest` loads into the analysis database. Your transcript carries
IDs and answers, not inventories.

## The five rules

1. **Top-K, always.** Every enumeration is `sorted(...)[:K]` with an explicit
   `K` (default `20`). "All callers of this function" is an unbounded answer; a
   `K=20` answer plus a count is an answer.
2. **IDs, not blobs.** Print `0x{ea:x}` (or `name = 0x{ea:x}`) — never a
   disassembly listing, never a `str(cfunc)` dump, never a vtable's contents.
   A separate follow-up call, on the one ID you actually need, is cheap.
3. **Max-lines on any text.** Any decompiler/pseudocode/listing you do emit goes
   through a hard line *and* character cap, with a visible truncation marker.
   Use the same defaults as the library: `MAX_LINES = 200`, `MAX_CHARS = 8000`
   (`icepick.trim.DEFAULT_MAX_LINES` / `DEFAULT_MAX_CHARS`).
4. **Counts before contents.** Realise `len(...)` first; if the count is large,
   *say so* and stop. `block_count=4213` is the finding; the 4213 addresses are
   not.
5. **Bulk goes through `icepick ingest`.** The full inventory is a file, written
   by the extractor and loaded with `icepick ingest analysis.db extract.json`.
   Your lane never writes the whole inventory into a transcript.

Non-negotiable safety: the lane is **read-only** (`save=False`), it runs in a
**VM snapshot**, and no IDAPython snippet here writes the IDB, applies names, or
patches bytes.

## Snippet 0 — the fence preamble (paste once, per session)

```python
import idaapi, idautils, idc

TOP_K      = 20      # entries per list
MAX_LINES  = 200     # lines per text blob
MAX_CHARS  = 8000    # characters per text blob (marker included)
MARK       = "\u2026"  # visible truncation marker

def ea(n):  return f"0x{int(n):x}"
def cap(seq, k=TOP_K):
    seq = list(seq)
    return seq[:k], len(seq) > k
def clip(text, lines=MAX_LINES, chars=MAX_CHARS):
    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    ls = text.splitlines()
    cut = len(ls) > lines
    text = "\n".join(ls[:lines])
    if len(text) > chars:
        text, cut = text[:max(0, chars - len(MARK))] + MARK, True
    return text, cut
```

`cap` and `clip` mirror `icepick.trim.cap_sequence` / `icepick.trim.truncate_text`
— same axes, same order (lines then characters), same marker. When the pure
library is importable in your process, prefer it over the local copies:

```python
try:
    from icepick.trim import truncate_text, cap_sequence, candidate_card
except ImportError:      # IDA's bundled Python has no icepick on sys.path
    pass                 # fall back to the preamble above
```

## Snippet 1 — inventory: counts first, IDs only

```python
funcs = sorted(int(f) for f in idautils.Functions())
print(f"functions={len(funcs)}")
shown, more = cap(funcs)
for f in shown:
    print(f"{ea(f)}  {idaapi.get_func_name(f) or ''}")
if more:
    print(f"... {len(funcs) - len(shown)} more function IDs (run `icepick extract` for all)")
```

Never `for f in Functions(): print(hex(f), disasm(f))`. The listing is the blob.

## Snippet 2 — one function's neighbourhood

```python
def neighbourhood(fea):
    callers = sorted({int(x.frm) for x in idautils.XrefsTo(fea, 0)})
    callees = sorted({int(x.to)  for x in idautils.XrefsFrom(fea, 0)})
    shown_in, more_in   = cap(callers)
    shown_out, more_out = cap(callees)
    print(f"target={ea(fea)} name={idaapi.get_func_name(fea)}")
    print(f"callers={len(callers)} callees={len(callees)}")
    print("in :", " ".join(ea(a) for a in shown_in)  + (" ..." if more_in else ""))
    print("out:", " ".join(ea(a) for a in shown_out) + (" ..." if more_out else ""))
```

## Snippet 3 — decompile exactly one function, capped

```python
import ida_hexrays

def decompile_capped(fea):
    if not ida_hexrays.init_hexrays_plugin():
        return f"DECOMPILE_FAILED(hexrays_unavailable)"
    try:
        cf = ida_hexrays.decompile(int(fea))
    except Exception as exc:                       # never let one func kill the run
        return f"DECOMPILE_FAILED({type(exc).__name__.lower()})"
    if cf is None:
        return "DECOMPILE_FAILED(decompile_returned_none)"
    text, cut = clip(str(cf))
    return text + ("\n" + MARK + " truncated" if cut else "")

print(decompile_capped(0x140001000))
```

Rules that make this safe to run repeatedly: one address per call, the
`init_hexrays_plugin()` result is checked (a missing decompiler is a sentinel,
never a traceback), and the text is clipped *before* it is printed. Never print
`str(ida_hexrays.decompile(fea))` bare — one large function can be megabytes.

## Snippet 4 — bulk: write the document, ingest it, report the counts

The whole inventory belongs in a file, not in your transcript. Prefer the CLI,
which already applies every cap and is deterministic (byte-identical across two
runs):

```bash
# 1. full inventory → schema-v1 JSON (sorted, capped at --top-k per list)
icepick extract target.exe --out extract.json --top-k 500

# 2. load it (exactly-once; re-running reports already-ingested)
icepick ingest analysis.db extract.json
```

Do **not** hand-roll `json.dump` of an unbounded dict from IDAPython: the CLI
lane is the one with the validation, the provenance block and the IDB digest.
If you must emit JSON from inside IDA, cap every list with `cap()` and every
text with `clip()` before serialising, and say what you capped in a
`"truncated": [...]` field.

## Snippet 5 — reporting a cut honestly

When you cap, say so, with the numbers:

```python
shown, more = cap(all_callers)
print(f"callers: showing {len(shown)}/{len(all_callers)} (top-K={TOP_K})")
```

A capped answer that names its cap is usable. A capped answer that looks
complete is a trap: the reviewer cannot tell "no more callers" from "I stopped
printing". The corresponding library contract is
`icepick.trim.truncate_text(s, max_lines, max_chars) -> (text, truncated_bool)`:
always forward the boolean, never drop it.

## Card shape (when you hand a finding to a human)

`icepick.trim.candidate_card()` produces the bounded card the fence expects:
`id`, `old_ea`, `new_ea`, `old_name`, `new_name`, `score`, `ratio`,
`address_shift`, `decompile` + `pseudocode` (capped), `counts` (pre-cap sizes),
`truncated` (which fields were cut) and `omitted_signals` (which nested values
were dropped, by name). Use it rather than inventing a shape; the ID is what
follow-up calls reference.

## Anti-patterns (each one is a context fire)

| Anti-pattern | Bounded replacement |
| --- | --- |
| `for f in Functions(): print(hex(f), idc.GetDisasm(f))` | counts + top-K IDs (snippet 1) |
| `print(str(ida_hexrays.decompile(fea)))` | `decompile_capped(fea)` (snippet 3) |
| pasting all of a vtable's slots | print `ea(vtable)` and the slot count |
| `json.dump(all_xrefs, open(..., "w"))` from a snippet | `icepick extract` → `icepick ingest` |
| printing an empty result silently | print `callers=0` — absence is a finding |
| retry loops that re-print the same dump | cap once, report the cap, move on |

## Sandbox rule

The live lane runs in a **VM only** (`skills/ida-domain.md`, Hex-Rays warning):
IDA executes input as data, not as a security boundary, and IDAPython can run
arbitrary code inside the analysis process. Budget the caps, keep the write
surface read-only, and treat every IDB as hostile input.
