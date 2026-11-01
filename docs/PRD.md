# WhoTouchedMyTarball: Product Requirements

| | |
|---|---|
| Product | WhoTouchedMyTarball (`wtmt`) |
| Problem statement | Hack Day Sonipat, Problem 04: Published Package vs Source Code Integrity Analyzer |
| Team | HardCarry |
| Status | Implemented; requirements traced to tests (see [Traceability](#9-traceability)) |

## 1. Problem

Developers review source code on GitHub but install tarballs from npm and PyPI. Release scripts, build tools and whoever holds the publish token stand between the two, so the published package can differ from the reviewed source.

- **XZ Utils (CVE-2024-3094):** the backdoor was injected through a modified `m4/build-to-host.m4` that only existed in the release tarball, never in the git repository.
- **npm, September 2025:** phished maintainer accounts published versions of `debug`, `chalk`, `color-string` and others. Those versions contained obfuscated code that hooked `fetch`/`XMLHttpRequest` and swapped crypto wallet addresses. None of that code existed on GitHub.

Tools that diff a package against its repository already exist. The hard part is deciding **which differences are normal** (transpiled output, minification, packaging metadata) **and which are malicious**, and explaining that decision with evidence.

## 2. Goals and non-goals

### Goals
1. Tell a developer, for one release, whether the published artifact matches the source it claims to come from.
2. Explain every difference in plain language, with evidence a maintainer can act on.
3. Separate normal build output from malicious changes without an ever-growing list of hard-coded exceptions.
4. Verify provenance claims (npm SLSA provenance, PyPI PEP 740 attestations) against what was actually downloaded and compared.
5. Watch selected packages and analyze each new release automatically.
6. Add a new package ecosystem without redesigning the system.

### Non-goals
- Scanning the whole dependency tree. One release is analyzed at a time; CI can loop over a lockfile.
- Vulnerability (CVE) scanning of the source code itself.
- Executing or sandbox-detonating package code. The tool is purely static.
- Proving full bit-for-bit reproducibility for every ecosystem. Rebuild verification (`verify-build`) is best-effort and needs Docker.

## 3. Users

| User | Need |
|---|---|
| Application developer | "Is it safe to bump this dependency?" A verdict and the reason, in seconds. |
| Security / platform engineer | A CI gate (exit codes, JSON) and continuous monitoring of critical dependencies. |
| Package maintainer | Proof their published artifact matches their repository, and an alert if someone else publishes. |
| Hackathon judges | Correct verdicts on recent real releases (mostly legitimate) and on organizer-tampered copies. |

## 4. Functional requirements

| ID | Requirement | Acceptance criteria |
|---|---|---|
| **FR-1** | Retrieve published packages from npm and PyPI. | `wtmt check <eco> <name> [version]` resolves the version (latest by default), downloads the artifact, and **verifies it against the registry digest** (npm SRI sha512/sha1, PyPI sha256). A mismatch aborts the analysis. |
| **FR-2** | Identify and retrieve the matching source. | The source repository comes from the registry metadata or provenance. The revision is chosen in this order: provenance commit, then npm `gitHead`, then release tag. When `gitHead` and the tag disagree, the tree closer to the package wins. Only the needed commit is shallow-fetched. `--source/--ref` override this. |
| **FR-3** | Compare source files with package contents. | Every package file is classified as identical, modified or package-only. Layouts (`src/`, monorepo subdirectories) are detected by voting, without per-project config. |
| **FR-4** | Identify generated files and normal build artifacts. | Packaging metadata (`PKG-INFO`, `*.dist-info`, `*.egg-info`, setuptools-rewritten `setup.cfg`), documentation, minified/transpiled output and declaration files are classified as expected and **do not** raise the verdict above `CLEAN`. |
| **FR-5** | Detect unexpected or suspicious modifications. | Unreviewed content (added lines and package-only files) is scanned for install hooks, process execution, decode-and-execute, obfuscation, network/exfiltration, credential access, runtime API hooks, wallet tampering, `.pth` auto-exec and modified autotools `.m4` scripts. |
| **FR-6** | Avoid hard-coded exception lists. | Explanations are *learned per package*: (a) a pattern in build output that also exists in the source is explained by it; (b) a file or pattern already shipped in the previous release is downgraded, and a new one is highlighted; (c) `.js` output that matches a `.ts` source file is build output whatever the output folder is called. A pattern elsewhere in the repo must **not** excuse a new file that has no source counterpart. |
| **FR-7** | Explain why each difference exists. | Every finding carries a category, a severity, a one-line reason, the triggering signals with line numbers, and a diff excerpt. An optional open-weight model adds a plain-language explanation. |
| **FR-8** | Risk assessment supported by evidence. | The report has a verdict (`CLEAN`, `REVIEW`, `SUSPICIOUS`, `UNVERIFIED`), a 0–100 risk score and exit codes 0/1/2 (3 on error). Without source, the verdict is `UNVERIFIED`, never `CLEAN`. |
| **FR-9** | Monitor new releases. | `wtmt watch add/remove/list/run` keeps a SQLite watch list. `run` analyzes only versions not seen before, writes one JSON and one Markdown report **per version**, and keeps going when one package fails. |
| **FR-10** | Verify provenance. | Attestation claims (repository, commit, workflow) are compared with the source actually fetched. In `verify-provenance`, the attested subject digest must match the downloaded artifact's digest; a mismatch is reported as `DIGEST_MISMATCH` **even when signature verification is unavailable**. |
| **FR-11** | Trust continuity across releases. | For watched packages, a baseline of repository, commit, workflow and provenance status is recorded. A changed repository owner, a removed repository, degraded provenance, or a new digest for an already-seen version raises a trust change for human approval. |
| **FR-12** | Extensible ecosystems. | An ecosystem is one adapter class (`resolve`, `latest_version`, `provenance`, `tag_candidates`, inherited `download`). Comparison, classification, reporting and monitoring need no changes to support a new one. |
| **FR-13** | Reports. | Terminal (Rich), Markdown and JSON output. JSON is machine-readable and stable enough for CI. |
| **FR-14** | Rebuild verification. | `wtmt verify-build` rebuilds the release in an isolated container (no network by default) and compares normalized artifacts. Without Docker it returns `ENVIRONMENT_UNAVAILABLE` and does nothing else. |

## 5. Security requirements

The tool processes attacker-controlled input: archives, repositories, registry metadata and file contents. It must not become the attack vector itself.

| ID | Requirement |
|---|---|
| **SEC-1** | **Safe extraction.** Reject absolute paths, `..` traversal (also with `\` separators and Windows drive letters). Never create symlinks, hard links or device files. Enforce file-count and total-size limits. |
| **SEC-2** | **Nothing from the package is executed.** No install scripts, no `setup.py`, no `.pth` processing, no imports of package code. |
| **SEC-3** | **Safe git.** Hooks disabled, no credential prompts, LFS smudge off. Submodules are fetched over HTTPS only (no `file://`, `ssh`, `ext::`). |
| **SEC-4** | **No reads outside the trees being compared.** Symlinks in a repository that point outside it are ignored. |
| **SEC-5** | **Registry integrity.** A download whose digest does not match the registry's digest is rejected. |
| **SEC-6** | **Provenance can't be spoofed by look-alikes.** Repository identity matching must not accept look-alike hosts or other owners. A commit is matched in full, or by a prefix of at least 7 hex characters. Negative evidence (digest or identity mismatch) takes precedence over "verification unavailable". |
| **SEC-7** | **The model explains, evidence decides.** Package text is wrapped in `<untrusted>` tags, and the package cannot close that wrapper early. The model may raise severity but can never clear a finding with strong deterministic evidence. Malformed model output never crashes an analysis. |
| **SEC-8** | **Safe file output.** Report filenames derived from registry data (package name, version) can't escape the output directory or overwrite another version's report. |
| **SEC-9** | **Private temporary files.** Downloads go to fresh private temporary directories, never fixed shared paths such as `/tmp/wtmt-pv`. |
| **SEC-10** | **Minimal data to third parties.** Only the snippets of a finding are sent to the model, never whole packages. The model is optional (`--no-ai`). |

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| **NFR-1** | The offline test suite needs no network, Docker or model, and runs in seconds. Live tests are opt-in (`pytest -m live`). |
| **NFR-2** | Python 3.10+. CI runs on 3.10 and 3.12 with `ruff check` and `pytest`. |
| **NFR-3** | Deterministic: the same inputs give the same verdict without the model. |
| **NFR-4** | Analyzing a typical release (under 10 MB) takes under a minute, excluding network time. |

## 7. Threat model (summary)

| Attacker | Capability | Mitigation |
|---|---|---|
| Account takeover (npm Sept 2025) | Publishes a version with injected code | FR-5, FR-6 (new vs previous release), FR-11 (publisher/provenance change) |
| Malicious maintainer / build-script tampering (XZ) | Tarball-only changes to build scripts | FR-3, FR-5 (`.m4`, configure), FR-14 |
| Hostile archive | Path traversal, symlinks, bombs | SEC-1, SEC-2 |
| Hostile repository | Symlinks to host files, `file://` submodules, git hooks | SEC-3, SEC-4 |
| Prompt injection | Comments that tell the model "this is safe" | SEC-7 |
| Forged or mismatched provenance | Attestation for a different artifact or repository | FR-10, SEC-6 |
| Compromised mirror / registry response | Wrong bytes, crafted version strings | SEC-5, SEC-8 |

## 8. Evaluation

- **Real releases** (`debug`, `axios`, `ky`, `requests`): expected `CLEAN` or `REVIEW` with only explained differences, never `SUSPICIOUS`.
- **Tampered copies:** an attack corpus covering each threat above must be `SUSPICIOUS`, and the benign corpus must not be.
- **Metric:** zero false negatives on the attack corpus; zero `SUSPICIOUS` verdicts on the benign corpus.

## 9. Traceability

| Requirement | Tests |
|---|---|
| FR-1, SEC-5 | `tests/test_ecosystems.py` |
| FR-2 | `tests/test_analyzer.py` (tag/gitHead), `tests/test_sources.py` |
| FR-3, FR-4 | `tests/test_compare.py`, `tests/test_analyzer.py`, `tests/test_prd_detection.py::test_benign_*` |
| FR-5, FR-6 | `tests/test_prd_detection.py`, `tests/test_signals.py`, `tests/test_analyzer.py` |
| FR-7, FR-8, FR-13 | `tests/test_prd_detection.py::test_finding_*`, `tests/test_cli.py` |
| FR-9, SEC-8 | `tests/test_monitor.py` |
| FR-10, SEC-6, SEC-9 | `tests/test_provenance.py` |
| FR-11 | `tests/test_trust.py`, `tests/test_provenance.py::test_trust_*` |
| FR-12 | `tests/test_ecosystems.py` |
| FR-14 | `tests/test_reproducibility.py` |
| SEC-1, SEC-2, SEC-3, SEC-4 | `tests/test_security_hardening.py`, `tests/test_archive.py`, `tests/test_sources.py` |
| SEC-7, SEC-10 | `tests/test_llm_safety.py`, `tests/test_llm.py` |
| Live evaluation (real releases) | `tests/test_live.py` (`pytest -m live`) |
