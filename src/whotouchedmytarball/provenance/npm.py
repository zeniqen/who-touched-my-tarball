"""npm provenance attestation retrieval."""

from __future__ import annotations

import httpx

NPM_REGISTRY = "https://registry.npmjs.org"


def retrieve_attestations(client: httpx.Client, name: str, version: str) -> tuple[bool, dict | None, list[str]]:
    """Retrieve attestations for an npm package version.

    Tries the npm registry's published attestation endpoint and falls back to package metadata.
    Returns (found, data, errors). Never invents data.
    """
    errors: list[str] = []
    # Candidate endpoint (registry may vary). Query package metadata first.
    try:
        resp = client.get(f"{NPM_REGISTRY}/{name}/{version}", timeout=30)
    except httpx.HTTPError as exc:
        return False, None, [f"npm registry request failed: {exc}"]
    if resp.status_code == 404:
        return False, None, []
    if resp.status_code != 200:
        return False, None, [f"npm registry returned {resp.status_code}"]
    try:
        meta = resp.json()
    except ValueError as exc:
        return False, None, [f"malformed npm metadata: {exc}"]
    if not isinstance(meta, dict):
        return False, None, ["npm metadata is not an object"]
    # Attestations URL may be present in dist or top-level.
    data = None
    attestations_url = None
    dist = meta.get("dist") or {}
    if isinstance(dist, dict):
        attestations_url = dist.get("attestations") or dist.get("provenance")
    if attestations_url is None:
        attestations_url = meta.get("attestations")
    if isinstance(attestations_url, str) and attestations_url:
        try:
            aresp = client.get(attestations_url, timeout=30)
            if aresp.status_code == 200:
                try:
                    data = aresp.json()
                except ValueError as exc:
                    errors.append(f"malformed npm attestation payload: {exc}")
            elif aresp.status_code == 404:
                errors.append("npm attestation endpoint returned 404")
            else:
                errors.append(f"npm attestation endpoint returned {aresp.status_code}")
        except httpx.HTTPError as exc:
            errors.append(f"npm attestation request failed: {exc}")
    # Some registries embed attestations directly.
    if data is None and isinstance(meta.get("attestations"), (dict, list)):
        data = meta.get("attestations")
    found = data is not None
    return found, data, errors
