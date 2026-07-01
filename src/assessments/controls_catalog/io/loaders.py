"""JSON loading helpers for catalog payloads."""

from __future__ import annotations

import json
from pathlib import Path


def load_json_file(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
