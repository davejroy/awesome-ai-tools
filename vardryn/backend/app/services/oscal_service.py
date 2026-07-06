"""
OSCAL / SCF control parsing utilities.

The ingest_oscal.py script calls these functions to populate the controls
table from a downloaded NIST OSCAL JSON catalog.

OSCAL catalog schema reference:
  https://pages.nist.gov/OSCAL/reference/latest/catalog/json-reference/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator


def iter_controls(catalog_path: Path) -> Iterator[dict]:
    """Yields normalized control dicts from an OSCAL JSON catalog file."""
    with catalog_path.open() as f:
        catalog = json.load(f)

    for group in catalog.get("catalog", {}).get("groups", []):
        yield from _controls_from_group(group, framework_tag=catalog.get("metadata", {}).get("title", ""))


def _controls_from_group(group: dict, framework_tag: str) -> Iterator[dict]:
    for control in group.get("controls", []):
        yield _normalize(control, framework_tag)
        # Recurse into sub-controls
        for sub in control.get("controls", []):
            yield _normalize(sub, framework_tag)

    for subgroup in group.get("groups", []):
        yield from _controls_from_group(subgroup, framework_tag)


def _normalize(control: dict, framework_tag: str) -> dict:
    title = ""
    description = ""

    for prop in control.get("parts", []):
        if prop.get("name") == "statement":
            description = _prose(prop)
            break

    title = control.get("title", control.get("id", ""))

    return {
        "scf_id": control.get("id"),
        "title": title,
        "description": description,
        "frameworks": [framework_tag] if framework_tag else [],
        "domain": control.get("class", ""),
        "status": "not_met",
    }


def _prose(part: dict) -> str:
    if "prose" in part:
        return part["prose"]
    return " ".join(_prose(p) for p in part.get("parts", []))
