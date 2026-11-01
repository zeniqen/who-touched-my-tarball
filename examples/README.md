# Examples

Every report in this folder was produced by running WhoTouchedMyTarball. Each one lists the command (input) that produced it, and the outputs are the actual `.md` and `.json` reports the tool wrote.

## 1. Offline demo: a simulated account takeover

The input is [`offline-demo/source/`](offline-demo/source/), a tiny npm library, plus two package files built from it by [`offline-demo/make_demo.py`](offline-demo/make_demo.py):

- `clean.tgz` is what `npm pack` publishes from the source.
- `tampered.tgz` is the same release after a simulated account takeover, modelled on the September 2025 `debug`/`chalk` compromise:
  - code appended to `index.js` that requires `child_process`, `eval`s a base64 payload and replaces `window.fetch` when a crypto wallet is present
  - a new `postinstall` hook
  - a new install script that references `NPM_TOKEN` and a raw-IP endpoint

All of it is inert: the payload decodes to a `console.log`, and the endpoint is a TEST-NET address that is never contacted.

| Command | Verdict | Report |
|---|---|---|
| `wtmt diff examples/offline-demo/clean.tgz examples/offline-demo/source --no-ai` | CLEAN (exit 0) | [md](offline-demo/report-clean.md), [json](offline-demo/report-clean.json) |
| `wtmt diff examples/offline-demo/tampered.tgz examples/offline-demo/source --no-ai` | SUSPICIOUS (exit 2) | [md](offline-demo/report-tampered.md), [json](offline-demo/report-tampered.json) |
| `wtmt diff examples/offline-demo/tampered.tgz examples/offline-demo/source` (AI on, `beam:cloud`) | SUSPICIOUS (exit 2) | [md](offline-demo/report-tampered-ai.md), [json](offline-demo/report-tampered-ai.json) |

CI runs the two `--no-ai` commands on every pull request.

With AI on, the verdict is the same, because the evidence decides it. What the model adds is a plain-language explanation for each finding: it judged the injected `index.js` code and the new `postinstall` hook malicious, and `scripts/setup.js` suspicious. In that last case it noticed that the demo payload only logs the token and doesn't send it.

## 2. Real releases from npm and PyPI

These were downloaded live from the registries. The tool fetched the matching source commit or tag from GitHub and compared the two.

| Command | What it shows | Verdict | Report |
|---|---|---|---|
| `wtmt check npm debug 4.4.1` | Last clean release before the Sept 2025 compromise. Source pinned by npm `gitHead`; all 7 files byte-identical. | CLEAN | [md](real-releases/npm-debug-4.4.1.md), [json](real-releases/npm-debug-4.4.1.json) |
| `wtmt check npm axios 1.7.9` | npm SLSA provenance read; the commit it names is the one compared; provenance matches the source. | CLEAN | [md](real-releases/npm-axios-1.7.9.md), [json](real-releases/npm-axios-1.7.9.json) |
| `wtmt check npm ky 1.7.4` | TypeScript package: 60 compiled files in `distribution/` recognised as build output by matching them to `.ts` sources, with no hard-coded folder names. | CLEAN | [md](real-releases/npm-ky-1.7.4.md), [json](real-releases/npm-ky-1.7.4.json) |
| `wtmt check pypi requests 2.32.3` | sdist: `PKG-INFO`, `egg-info` and setuptools' rewritten `setup.cfg` recognised as packaging metadata; symlinked test certificates resolved. | CLEAN | [md](real-releases/pypi-requests-2.32.3-sdist.md), [json](real-releases/pypi-requests-2.32.3-sdist.json) |
| `wtmt check pypi requests 2.32.3 --dist wheel` | Wheel: `src/` layout detected automatically; only `.dist-info` differs. | CLEAN | [md](real-releases/pypi-requests-2.32.3-wheel.md), [json](real-releases/pypi-requests-2.32.3-wheel.json) |

The compromised versions themselves (for example `debug@4.4.2`) were removed from npm, so they cannot be downloaded any more. The offline demo reproduces their pattern instead.

The reports above were generated with `--no-ai` (deterministic checks only). This one was run with the model on:

| Command | What it shows | Verdict | Report |
|---|---|---|---|
| `wtmt check npm ky 1.7.4` (AI on, `beam:cloud`) | The model reads the compiled `distribution/` files and explains each one as normal build output (`.js`, `.d.ts` and `.map` files generated from the TypeScript source). The verdict is unchanged. By default the model gets the top 12 findings (`--max-ai`), and the report says so. | CLEAN | [md](real-releases/npm-ky-1.7.4-ai.md), [json](real-releases/npm-ky-1.7.4-ai.json) |

To run the model yourself, start Ollama with `beam:cloud` available and leave out `--no-ai`. Model answers can vary slightly between runs (for example, a confidence of 75% one time and 85% the next), but they never decide the verdict on their own.
