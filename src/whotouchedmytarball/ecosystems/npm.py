"""npm registry adapter."""

from __future__ import annotations

import base64
import json
from urllib.parse import quote

import httpx

from ..models import Provenance
from ..sources import normalize_repo_url
from .base import Ecosystem, RegistryError, ReleaseInfo, sri_to_hex

REGISTRY = "https://registry.npmjs.org"


class NpmEcosystem(Ecosystem):
    name = "npm"

    def _packument(self, client: httpx.Client, package: str) -> dict:
        resp = client.get(f"{REGISTRY}/{quote(package, safe='@')}")
        if resp.status_code == 404:
            raise RegistryError(f"npm package not found: {package}")
        resp.raise_for_status()
        return resp.json()

    def latest_version(self, client: httpx.Client, package: str) -> str:
        doc = self._packument(client, package)
        return doc.get("dist-tags", {}).get("latest") or sorted(doc.get("versions", {}))[-1]

    def resolve(self, client: httpx.Client, package: str, version: str | None, dist: str = "auto") -> ReleaseInfo:
        doc = self._packument(client, package)
        version = version or doc.get("dist-tags", {}).get("latest")
        versions = doc.get("versions", {})
        if version not in versions:
            raise RegistryError(f"{package}@{version} is not published (it may have been unpublished)")
        meta = versions[version]
        dist_info = meta.get("dist", {})
        tarball = dist_info.get("tarball")
        if not tarball:
            raise RegistryError(f"{package}@{version} has no tarball")

        repo = meta.get("repository") or doc.get("repository")
        repo_url, repo_dir = None, None
        if isinstance(repo, dict):
            repo_url, repo_dir = repo.get("url"), repo.get("directory")
        elif isinstance(repo, str):
            repo_url = repo
        ref = normalize_repo_url(repo_url)

        digests: dict[str, str] = {}
        sri = sri_to_hex(dist_info.get("integrity", ""))
        if sri:
            digests[sri[0]] = sri[1]
        elif dist_info.get("shasum"):
            digests["sha1"] = dist_info["shasum"]

        return ReleaseInfo(
            ecosystem=self.name,
            name=package,
            version=version,
            artifact_url=tarball,
            artifact_filename=tarball.rsplit("/", 1)[-1],
            repository_url=ref.url if ref else repo_url,
            repository_directory=repo_dir or (ref.subdirectory if ref else None),
            git_head=meta.get("gitHead"),
            expected_digests=digests,
            previous_version=self._previous(doc, version),
            raw={"dist": dist_info},
        )

    @staticmethod
    def _previous(doc: dict, version: str) -> str | None:
        times = doc.get("time", {})
        versions = [v for v in doc.get("versions", {}) if v in times]
        if version not in times:
            return None
        is_pre = "-" in version
        older = [v for v in versions if times[v] < times[version] and (is_pre or "-" not in v)]
        if not older:
            return None
        return max(older, key=lambda v: times[v])

    def provenance(self, client: httpx.Client, release: ReleaseInfo) -> Provenance:
        attestations = release.raw.get("dist", {}).get("attestations")
        if not attestations or not attestations.get("url"):
            return Provenance(available=False, note="No npm provenance attestation was published for this version")
        try:
            resp = client.get(attestations["url"])
            resp.raise_for_status()
            return parse_npm_attestations(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            return Provenance(available=False, note=f"Attestation listed but could not be fetched: {exc}")

    def tag_candidates(self, package: str, version: str) -> list[str]:
        short = package.split("/")[-1]
        return [f"v{version}", version, f"{package}@{version}", f"{short}@{version}", f"{short}-v{version}",
                f"{short}-{version}", f"release-{version}", f"release/{version}"]


def parse_npm_attestations(doc: dict) -> Provenance:
    for att in doc.get("attestations", []):
        if "slsa.dev/provenance" not in att.get("predicateType", ""):
            continue
        envelope = att.get("bundle", {}).get("dsseEnvelope", {})
        try:
            statement = json.loads(base64.b64decode(envelope.get("payload", "")))
        except (ValueError, json.JSONDecodeError):
            continue
        predicate = statement.get("predicate", {})
        build = predicate.get("buildDefinition", {})
        workflow = build.get("externalParameters", {}).get("workflow", {})
        repo = workflow.get("repository")
        commit, ref = None, workflow.get("ref")
        for dep in build.get("resolvedDependencies", []):
            digest = dep.get("digest", {})
            if digest.get("gitCommit"):
                commit = digest["gitCommit"]
                uri = dep.get("uri", "")
                if not repo and uri:
                    repo = uri.split("@", 1)[0]
                if "@" in uri and not ref:
                    ref = uri.split("@", 1)[1]
                break
        ref_url = normalize_repo_url(repo)
        return Provenance(
            available=True,
            kind="npm SLSA provenance (Sigstore)",
            repository=ref_url.url if ref_url else repo,
            commit=commit,
            ref=ref,
            workflow=workflow.get("path"),
            note="Attestation published by the npm registry. Its Sigstore signature is verified by npm at publish "
            "time; this tool reads the claims and checks them against the source it compares.",
        )
    return Provenance(available=False, note="Attestations exist but none is a SLSA provenance statement")
