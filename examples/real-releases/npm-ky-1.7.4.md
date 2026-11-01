# WhoTouchedMyTarball report: `npm:ky@1.7.4`

**Verdict: CLEAN** (OK) | risk score 10/100

3 of 63 published files are byte-identical to the source; 0 differ and 60 exist only in the package. Every difference is explained by normal packaging or build steps.

| | |
|---|---|
| Artifact | https://registry.npmjs.org/ky/-/ky-1.7.4.tgz |
| Integrity | verified against registry digest (sha512) |
| Source | https://github.com/sindresorhus/ky @ `4a427011ad7b4ab98bb5f02ecaa5375fba5addca` |
| Resolved by | commit recorded by the registry/provenance (cached) |
| Provenance | No npm provenance attestation was published for this version |
| Baseline | previous release 1.7.3 |
| Files | 63 in package, 3 identical, 0 modified, 60 package-only, 46 source-only |

## Findings

| Severity | File | Category | Reason |
|---|---|---|---|
| low | `distribution/core/Ky.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/core/Ky.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/core/Ky.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/core/constants.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/core/constants.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/core/constants.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/errors/HTTPError.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/errors/HTTPError.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/errors/HTTPError.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/errors/TimeoutError.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/errors/TimeoutError.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/errors/TimeoutError.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/index.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/index.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/index.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/ResponsePromise.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/ResponsePromise.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/ResponsePromise.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/common.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/common.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/common.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/hooks.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/hooks.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/hooks.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/ky.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/ky.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/ky.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/options.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/options.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/options.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/request.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/request.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/request.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/response.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/response.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/response.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/retry.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/retry.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/types/retry.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/delay.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/delay.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/delay.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/is.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/is.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/is.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/merge.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/merge.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/merge.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/normalize.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/normalize.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/normalize.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/options.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/options.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/options.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/timeout.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/timeout.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/timeout.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/types.d.ts` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/types.js` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |
| low | `distribution/utils/types.js.map` | build_output (package_only) | Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3 |

_Generated by WhoTouchedMyTarball 0.1.0_
