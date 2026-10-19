"""Test-suite plumbing: put ``src/`` on ``sys.path`` (no install step needed)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DATA = ROOT / "tests" / "data"

for candidate in (str(SRC),):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

FIXTURE_EXTRACT = DATA / "ida_extract.v1.json"
