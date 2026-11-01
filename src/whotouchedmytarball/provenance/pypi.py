"""PyPI provenance attestation retrieval using the Integrity API."""

from __future__ import annotations

import httpx

PYPI_BASE = "https://pypi.org"


def retrieve_attestation(client: httpx.Client, project: str, version: str, filename: str) -> tuple[bool, dict | None, list[str]]:
    """Retrieve provenance for one distribution via the Integrity API."""
    url = f"{PYPI_BASE}/integrity/{project}/{version}/{filename}/provenance"
    try:
        resp = client.get(url, timeout=30)
    except httpx.HTTPError as exc:
        return False, None, [f"PyPI integrity request failed: {exc}"]
    if resp.status_code == 404:
        return False, None, []
    if resp.status_code != 200:
        return False, None, [f"PyPI integrity API returned {resp.status_code}"]
    try:
        data = resp.json()
    except ValueError as exc:
        return False, None, [f"malformed PyPI integrity response: {exc}"]
    if not isinstance(data, dict):
        return False, None, ["PyPI integrity response is not an object"]
    # Supported envelope usually has an "attestation" or "attestations" field.
    if "attestation" in data or "attestations" in data:
        return True, data, []
    return False, data, ["PyPI integrity response lacks attestation data"]
