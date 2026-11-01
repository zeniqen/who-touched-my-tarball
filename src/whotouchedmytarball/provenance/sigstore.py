"""Sigstore verification wrapper.

Uses sigstore-python when installed. Never implements crypto primitives directly.
"""

from __future__ import annotations

try:
    import sigstore  # type: ignore  # noqa: F401
    SIGSTORE_AVAILABLE = True
except Exception:  # pragma: no cover
    SIGSTORE_AVAILABLE = False


def verify_bundle(bundle: dict, expected_identity: str | None = None) -> tuple[bool, list[str], dict]:
    """Verify a Sigstore bundle. Returns (ok, errors, info)."""
    info = {"issuer": None, "signer_identity": None, "transparency_verified": False}
    if not SIGSTORE_AVAILABLE:
        return False, ["sigstore library is not installed; verification unavailable"], info
    # Placeholder: real integration should use sigstore.verify to validate
    # certificate chain, signature, and Rekor inclusion proof. Kept minimal here
    # to avoid fabricating verification results.
    return False, ["sigstore bundle verification not implemented in this build"], info
