"""in-toto statement parsing and validation helpers."""

from __future__ import annotations

import json
from typing import Any

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
INTOTO_STATEMENT_TYPE_V1 = "https://in-toto.io/Statement/v1"


def parse_statement(raw: Any) -> tuple[dict | None, list[str]]:
    errors = []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            return None, [f"invalid JSON: {exc}"]
    if not isinstance(raw, dict):
        return None, ["attestation is not an object"]
    stype = raw.get("_type")
    if stype not in (INTOTO_STATEMENT_TYPE, INTOTO_STATEMENT_TYPE_V1):
        errors.append(f"unexpected statement type: {stype!r}")
    if not isinstance(raw.get("subject"), list) or not raw["subject"]:
        errors.append("statement has no subjects")
    else:
        for subj in raw["subject"]:
            if not isinstance(subj, dict):
                errors.append("subject is not an object")
                continue
            if "name" not in subj:
                errors.append("subject missing name")
            dig = subj.get("digest")
            if not isinstance(dig, dict) or "sha256" not in dig:
                errors.append("subject missing sha256 digest")
    predicate_type = raw.get("predicateType")
    if not predicate_type:
        errors.append("statement missing predicateType")
    return raw, errors


def extract_subjects(statement: dict) -> list[dict]:
    return list(statement.get("subject") or [])


def match_subject_digest(statement: dict, actual_digest: str) -> bool:
    actual = actual_digest.lower().removeprefix("sha256:")
    for subj in extract_subjects(statement):
        dig = (subj.get("digest") or {}).get("sha256")
        if isinstance(dig, str) and dig.lower() == actual:
            return True
    return False
