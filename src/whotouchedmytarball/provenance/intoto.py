"""in-toto statement parsing and validation helpers."""

from __future__ import annotations

import json
from typing import Any

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v0.1"
INTOTO_STATEMENT_TYPE_V1 = "https://in-toto.io/Statement/v1"
# npm attests sha512, PyPI sha256; anything weaker is not accepted as a binding.
SUBJECT_DIGEST_ALGOS = ("sha256", "sha512")


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
            if not isinstance(dig, dict) or not any(a in dig for a in SUBJECT_DIGEST_ALGOS):
                errors.append("subject missing sha256/sha512 digest")
    predicate_type = raw.get("predicateType")
    if not predicate_type:
        errors.append("statement missing predicateType")
    return raw, errors


def extract_subjects(statement: dict) -> list[dict]:
    return list(statement.get("subject") or [])


def match_subject_digest(statement: dict, actual: str | dict[str, str]) -> bool:
    """True if a subject's digest equals the artifact's digest for the same algorithm.

    ``actual`` is a sha256 hex string or a mapping ``{algorithm: hex}``.
    """
    if isinstance(actual, str):
        actual = {"sha256": actual.lower().removeprefix("sha256:")}
    for subj in extract_subjects(statement):
        digests = subj.get("digest") or {}
        for algo in SUBJECT_DIGEST_ALGOS:
            dig, have = digests.get(algo), actual.get(algo)
            if isinstance(dig, str) and have and dig.lower() == have.lower():
                return True
    return False
