"""SLSA provenance predicate extraction helpers."""

from __future__ import annotations

from typing import Any

SLSA_PREDICATE_V02 = "https://slsa.dev/provenance/v0.2"
SLSA_PREDICATE_V1 = "https://slsa.dev/provenance/v1"


def predicate_type(statement: dict) -> str | None:
    return statement.get("predicateType")


def is_slsa(statement: dict) -> bool:
    return predicate_type(statement) in (SLSA_PREDICATE_V02, SLSA_PREDICATE_V1)


def extract_slsa(statement: dict) -> dict:
    pred = statement.get("predicate") or {}
    out: dict[str, Any] = {"predicate_type": statement.get("predicateType")}
    # Build
    build = pred.get("buildDefinition") or {}
    run = build.get("buildType") or pred.get("buildType")
    out["build_type"] = run
    invocation = pred.get("invocation") or build.get("externalParameters") or {}
    out["build_parameters"] = invocation
    # builder
    builder = pred.get("builder") or build.get("resolvedDependencies")
    if isinstance(builder, dict):
        out["builder_id"] = builder.get("id") or builder.get("uri")
    else:
        out["builder_id"] = None
    # materials / source
    materials = pred.get("materials") or build.get("resolvedDependencies") or []
    sources = []
    for m in materials if isinstance(materials, list) else []:
        uri = m.get("uri") if isinstance(m, dict) else None
        digest = m.get("digest") if isinstance(m, dict) else None
        sources.append({"uri": uri, "digest": digest})
    out["materials"] = sources
    # metadata
    metadata = pred.get("metadata") or {}
    out["build_invocation_id"] = metadata.get("buildInvocationId")
    out["build_started_on"] = metadata.get("buildStartedOn")
    out["build_finished_on"] = metadata.get("buildFinishedOn")
    return out


def find_source_repo(slsa: dict, source_repo_hint: str | None = None) -> str | None:
    for m in slsa.get("materials", []):
        uri = m.get("uri")
        if isinstance(uri, str) and ("github.com" in uri or "gitlab.com" in uri or uri.startswith("git+")):
            return uri
    return source_repo_hint
