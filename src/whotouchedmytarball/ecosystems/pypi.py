"""PyPI adapter."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote

import httpx

from ..models import Provenance
from ..sources import normalize_repo_url
from .base import Ecosystem, RegistryError, ReleaseInfo

PYPI = "https://pypi.org"
SOURCE_KEYS = ("source", "source code", "repository", "code", "github", "git", "homepage", "home", "issues",
               "bug tracker", "tracker", "changelog", "documentation")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class PyPIEcosystem(Ecosystem):
    name = "pypi"

    def _json(self, client: httpx.Client, url: str) -> dict:
        resp = client.get(url)
        if resp.status_code == 404:
            raise RegistryError(f"not found on PyPI: {url}")
        resp.raise_for_status()
        return resp.json()

    def latest_version(self, client: httpx.Client, package: str) -> str:
        return self._json(client, f"{PYPI}/pypi/{quote(package)}/json")["info"]["version"]

    def resolve(self, client: httpx.Client, package: str, version: str | None, dist: str = "auto") -> ReleaseInfo:
        project = self._json(client, f"{PYPI}/pypi/{quote(package)}/json")
        version = version or project["info"]["version"]
        data = self._json(client, f"{PYPI}/pypi/{quote(package)}/{quote(version)}/json")
        files = [f for f in data.get("urls", []) if not f.get("yanked")] or data.get("urls", [])
        chosen = self._choose_file(files, dist)
        if not chosen:
            raise RegistryError(f"{package}=={version} has no {dist} distribution files")

        repo_url = find_repository(data["info"])
        ref = normalize_repo_url(repo_url)
        return ReleaseInfo(
            ecosystem=self.name,
            name=data["info"]["name"],
            version=version,
            artifact_url=chosen["url"],
            artifact_filename=chosen["filename"],
            repository_url=ref.url if ref else repo_url,
            repository_directory=ref.subdirectory if ref else None,
            expected_digests={"sha256": chosen["digests"]["sha256"]} if chosen.get("digests") else {},
            previous_version=self._previous(project, version),
            raw={"file": chosen},
        )

    @staticmethod
    def _choose_file(files: list[dict], dist: str) -> dict | None:
        sdists = [f for f in files if f.get("packagetype") == "sdist"]
        wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
        wheels.sort(key=lambda f: ("none-any" not in f["filename"], f["filename"]))
        if dist == "sdist":
            return sdists[0] if sdists else None
        if dist == "wheel":
            return wheels[0] if wheels else None
        return (sdists or wheels or [None])[0]

    @staticmethod
    def _previous(project: dict, version: str) -> str | None:
        releases = project.get("releases", {})

        def uploaded(v: str) -> str:
            files = releases.get(v) or []
            return min((f.get("upload_time_iso_8601") or "" for f in files), default="")

        current = uploaded(version)
        if not current:
            return None
        is_pre = bool(re.search(r"(a|b|rc|dev)\d*$", version))
        older = [v for v in releases if releases[v] and uploaded(v) < current
                 and (is_pre or not re.search(r"(a|b|rc|dev)\d*$", v))]
        return max(older, key=uploaded) if older else None

    def provenance(self, client: httpx.Client, release: ReleaseInfo) -> Provenance:
        url = (f"{PYPI}/integrity/{quote(normalize_name(release.name))}/{quote(release.version)}/"
               f"{quote(release.artifact_filename)}/provenance")
        try:
            resp = client.get(url, headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
        except httpx.HTTPError as exc:
            return Provenance(available=False, note=f"Could not query the PyPI integrity API: {exc}")
        if resp.status_code == 404:
            return Provenance(available=False, note="No PEP 740 attestation was published for this file")
        if resp.status_code != 200:
            return Provenance(available=False, note=f"PyPI integrity API returned {resp.status_code}")
        try:
            return parse_pypi_provenance(resp.json(), release.artifact_filename)
        except ValueError as exc:
            return Provenance(available=False, note=f"Could not parse PyPI provenance: {exc}")

    def tag_candidates(self, package: str, version: str) -> list[str]:
        names = {package, package.lower(), normalize_name(package), package.replace("-", "_")}
        tags = [f"v{version}", version]
        for n in sorted(names):
            tags += [f"{n}-{version}", f"{n}-v{version}", f"{n}@{version}", f"{n}/{version}", f"{n}/v{version}"]
        tags += [f"release-{version}", f"release/{version}", f"rel-{version}"]
        return list(dict.fromkeys(tags))


def find_repository(info: dict) -> str | None:
    urls = {k.lower(): v for k, v in (info.get("project_urls") or {}).items() if v}
    for key in SOURCE_KEYS:
        if key in urls and normalize_repo_url(urls[key]):
            return urls[key]
    for value in urls.values():
        if normalize_repo_url(value):
            return value
    for key in ("home_page", "download_url"):
        if info.get(key) and normalize_repo_url(info[key]):
            return info[key]
    return None


def parse_pypi_provenance(doc: dict, filename: str) -> Provenance:
    bundles = doc.get("attestation_bundles") or []
    if not bundles:
        return Provenance(available=False, note="Provenance object has no attestation bundles")
    bundle = bundles[0]
    publisher = bundle.get("publisher") or {}
    subject_ok = None
    for att in bundle.get("attestations", []):
        statement_b64 = att.get("envelope", {}).get("statement")
        if not statement_b64:
            continue
        try:
            statement = json.loads(base64.b64decode(statement_b64))
        except (ValueError, json.JSONDecodeError):
            continue
        subject_ok = any(s.get("name") == filename for s in statement.get("subject", []))
        break
    repo = publisher.get("repository")
    host = "https://github.com/" if publisher.get("kind", "").lower() == "github" else ""
    repo_url = normalize_repo_url(host + repo if repo and host else repo)
    note = "PEP 740 attestation from a Trusted Publisher, verified by PyPI at upload time."
    if subject_ok is False:
        note += " Warning: attestation subject does not name this file."
    return Provenance(
        available=True,
        kind=f"PyPI PEP 740 attestation ({publisher.get('kind', 'unknown')} trusted publisher)",
        repository=repo_url.url if repo_url else repo,
        workflow=publisher.get("workflow"),
        note=note,
    )
