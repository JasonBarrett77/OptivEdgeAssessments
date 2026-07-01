"""Seed-file registry helpers for bundled catalogs."""

from __future__ import annotations

from pathlib import Path

from assessments.controls_catalog.io.loaders import load_json_file
from assessments.controls_catalog.schemas import validate_catalog_seed_payload


CATALOG_SEED_PATH = Path(__file__).resolve().parent / "catalogs" / "seed.json"


def load_seed_payload() -> dict:
    return validate_catalog_seed_payload(load_json_file(CATALOG_SEED_PATH))
