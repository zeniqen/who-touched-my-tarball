# WhoTouchedMyTarball report: `npm:ky@1.7.4`

**Verdict: CLEAN** (OK) | risk score 10/100

3 of 63 published files are byte-identical to the source; 0 differ and 60 exist only in the package. Every difference is explained by normal packaging or build steps.

| | |
|---|---|
| Artifact | https://registry.npmjs.org/ky/-/ky-1.7.4.tgz |
| Integrity | verified against registry digest (sha512) |
| Source | https://github.com/sindresorhus/ky @ `4a427011ad7b4ab98bb5f02ecaa5375fba5addca` |
| Resolved by | commit recorded by the registry/provenance |
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

## Evidence

### `distribution/core/Ky.d.ts` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (98%). This is a generated TypeScript declaration file for the published package and contains only public/private type signatures for the Ky class. No executable code, install hooks, network calls, or obfuscation are present.

```diff
--- /dev/null
+++ package/distribution/core/Ky.d.ts
+import type { Input, InternalOptions, Options } from '../types/options.js';
+import { type ResponsePromise } from '../types/ResponsePromise.js';
+export declare class Ky {
+    static create(input: Input, options: Options): ResponsePromise;
+    request: Request;
+    protected abortController?: AbortController;
+    protected _retryCount: number;
+    protected _input: Input;
+    protected _options: InternalOptions;
+    constructor(input: Input, options?: Options);
+    protected _calculateRetryDelay(error: unknown): number;
+    protected _decorateResponse(response: Response): Response;
+    protected _retry<T extends (...arguments_: any) => Promise<any>>(function_: T): Promise<ReturnType<T> | void>;
+    protected _fetch(): Promise<Response>;
+    protected _stream(response: Response, onDownloadProgress: Options['onDownloadProgress']): Response;
+}
```

### `distribution/core/Ky.js` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (95%). This is a normal build artifact for the ky HTTP client, with standard request construction, retry, response handling, and hooks. No install-time execution, obfuscation, credential access, or unexpected network behavior is visible in the excerpt.

```diff
--- /dev/null
+++ package/distribution/core/Ky.js
+import { HTTPError } from '../errors/HTTPError.js';
+import { TimeoutError } from '../errors/TimeoutError.js';
+import { mergeHeaders, mergeHooks } from '../utils/merge.js';
+import { normalizeRequestMethod, normalizeRetryOptions } from '../utils/normalize.js';
+import timeout from '../utils/timeout.js';
+import delay from '../utils/delay.js';
+import { findUnknownOptions } from '../utils/options.js';
+import { maxSafeTimeout, responseTypes, stop, supportsAbortController, supportsFormData, supportsResponseStreams, supportsRequestStreams, } from './constants.js';
+export class Ky {
+    static create(input, options) {
+        const ky = new Ky(input, options);
+        const function_ = async () => {
+            if (typeof ky._options.timeout === 'number' && ky._options.timeout > maxSafeTimeout) {
+                throw new RangeError(`The \`timeout\` option cannot be greater than ${maxSafeTimeout}`);
+            }
+            // Delay the fetch so that body method shortcuts can set the Accept header
+            await Promise.resolve();
+            let response = await ky._fetch();
+            for (const hook of ky._options.hooks.afterResponse) {
+                // eslint-disable-next-line no-await-in-loop
+                const modifiedResponse = await hook(ky.request, ky._options, ky._decorateResponse(response.clone()));
+                if (modifiedResponse instanceof globalThis.Response) {
+                    response = modifiedResponse;
+                }
+            }
+            ky._decorateResponse(response);
+            if (!response.ok && ky._options.throwHttpErrors) {
+                let error = new HTTPError(response, ky.request, ky._options);
+                for (const hook of ky._options.hooks.beforeError) {
+                    // eslint-disable-next-line no-await-in-loop
+                    error = await hook(error);
+                }
+                throw error;
+            }
+            // If `onDownloadProgress` is passed, it uses the stream API internally
+            /* istanbul ignore next */
+            if (ky._options.onDownloadProgress) {
+                if (typeof ky._options.onDownloadProgress !== 'function') {
```

### `distribution/core/Ky.js.map` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (95%). This is a standard generated source map for the published Ky.js bundle, referencing the TypeScript source and containing only normal mappings. No install scripts, network calls, obfuscation, or other suspicious content are present in the excerpt.

```diff
--- /dev/null
+++ package/distribution/core/Ky.js.map
+{"version":3,"file":"Ky.js","sourceRoot":"","sources":["../../source/core/Ky.ts"],"names":[],"mappings":"AAAA,OAAO,EAAC,SAAS,EAAC,MAAM,wBAAwB,CAAC;AACjD,OAAO,EAAC,YAAY,EAAC,MAAM,2BAA2B,CAAC;AASvD,OAAO,EAAC,YAAY,EAAE,UAAU,EAAC,MAAM,mBAAmB,CAAC;AAC3D,OAAO,EAAC,sBAAsB,EAAE,qBAAqB,EAAC,MAAM,uBAAuB,CAAC;
```

### `distribution/core/constants.d.ts` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (98%). This is a generated TypeScript declaration file for ky's constants module, with no executable code or suspicious behavior. Its contents match expected public constants and type registries.

```diff
--- /dev/null
+++ package/distribution/core/constants.d.ts
+import { type KyOptionsRegistry } from '../types/options.js';
+import { type RequestInitRegistry } from '../types/request.js';
+export declare const supportsRequestStreams: boolean;
+export declare const supportsAbortController: boolean;
+export declare const supportsResponseStreams: boolean;
+export declare const supportsFormData: boolean;
+export declare const requestMethods: readonly ["get", "post", "put", "patch", "head", "delete"];
+export declare const responseTypes: {
+    readonly json: "application/json";
+    readonly text: "text/*";
+    readonly formData: "multipart/form-data";
+    readonly arrayBuffer: "*/*";
+    readonly blob: "*/*";
+};
+export declare const maxSafeTimeout = 2147483647;
+export declare const stop: unique symbol;
+export declare const kyOptionKeys: KyOptionsRegistry;
+export declare const requestOptionsRegistry: RequestInitRegistry;
```

### `distribution/core/constants.js` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (95%). The file contains ordinary ky feature-detection constants and request/response option registries. Its Request constructor usage is local feature detection, not a network request, and the no-op validate call is harmless build output. No install hooks, obfuscation, credential access, or suspicious network behavior is present.

```diff
--- /dev/null
+++ package/distribution/core/constants.js
+export const supportsRequestStreams = (() => {
+    let duplexAccessed = false;
+    let hasContentType = false;
+    const supportsReadableStream = typeof globalThis.ReadableStream === 'function';
+    const supportsRequest = typeof globalThis.Request === 'function';
+    if (supportsReadableStream && supportsRequest) {
+        try {
+            hasContentType = new globalThis.Request('https://empty.invalid', {
+                body: new globalThis.ReadableStream(),
+                method: 'POST',
+                // @ts-expect-error - Types are outdated.
+                get duplex() {
+                    duplexAccessed = true;
+                    return 'half';
+                },
+            }).headers.has('Content-Type');
+        }
+        catch (error) {
+            // QQBrowser on iOS throws "unsupported BodyInit type" error (see issue #581)
+            if (error instanceof Error && error.message === 'unsupported BodyInit type') {
+                return false;
+            }
+            throw error;
+        }
+    }
+    return duplexAccessed && !hasContentType;
+})();
+export const supportsAbortController = typeof globalThis.AbortController === 'function';
+export const supportsResponseStreams = typeof globalThis.ReadableStream === 'function';
+export const supportsFormData = typeof globalThis.FormData === 'function';
+export const requestMethods = ['get', 'post', 'put', 'patch', 'head', 'delete'];
+const validate = () => undefined;
+validate();
+export const responseTypes = {
+    json: 'application/json',
+    text: 'text/*',
+    formData: 'multipart/form-data',
+    arrayBuffer: '*/*',
```

### `distribution/core/constants.js.map` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (95%). This is a generated source map for a normal build artifact and its mappings point to the expected TypeScript source. No install scripts, network calls, obfuscation, or other suspicious behavior are present in the excerpt.

```diff
--- /dev/null
+++ package/distribution/core/constants.js.map
+{"version":3,"file":"constants.js","sourceRoot":"","sources":["../../source/core/constants.ts"],"names":[],"mappings":"AAIA,MAAM,CAAC,MAAM,sBAAsB,GAAG,CAAC,GAAG,EAAE;IAC3C,IAAI,cAAc,GAAG,KAAK,CAAC;IAC3B,IAAI,cAAc,GAAG,KAAK,CAAC;IAC3B,MAAM,sBAAsB,GAAG,OAAO,UAAU,CAAC,cAAc,KAAK,UAAU,CAAC;IAC/E,MAAM,eAA
```

### `distribution/errors/HTTPError.d.ts` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (98%). This is a generated TypeScript declaration file for ky's HTTPError class and matches the expected public API shape. No install scripts, network calls, obfuscation, or suspicious behavior are present.

```diff
--- /dev/null
+++ package/distribution/errors/HTTPError.d.ts
+import type { NormalizedOptions } from '../types/options.js';
+import type { KyRequest } from '../types/request.js';
+import type { KyResponse } from '../types/response.js';
+export declare class HTTPError<T = unknown> extends Error {
+    response: KyResponse<T>;
+    request: KyRequest;
+    options: NormalizedOptions;
+    constructor(response: Response, request: Request, options: NormalizedOptions);
+}
```

### `distribution/errors/HTTPError.js` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (95%). This is a normal build artifact defining HTTPError with expected request/response metadata and no install scripts, network calls, or obfuscation. It matches ky's documented error behavior and contains only standard error construction logic.

```diff
--- /dev/null
+++ package/distribution/errors/HTTPError.js
+export class HTTPError extends Error {
+    response;
+    request;
+    options;
+    constructor(response, request, options) {
+        const code = (response.status || response.status === 0) ? response.status : '';
+        const title = response.statusText || '';
+        const status = `${code} ${title}`.trim();
+        const reason = status ? `status code ${status}` : 'an unknown error';
+        super(`Request failed with ${reason}: ${request.method} ${request.url}`);
+        this.name = 'HTTPError';
+        this.response = response;
+        this.request = request;
+        this.options = options;
+    }
+}
+//# sourceMappingURL=HTTPError.js.map
```

### `distribution/errors/HTTPError.js.map` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (95%). This is a standard source map generated from the TypeScript source during the package build; it contains no executable code or install-time behavior.

```diff
--- /dev/null
+++ package/distribution/errors/HTTPError.js.map
+{"version":3,"file":"HTTPError.js","sourceRoot":"","sources":["../../source/errors/HTTPError.ts"],"names":[],"mappings":"AAIA,MAAM,OAAO,SAAuB,SAAQ,KAAK;IACzC,QAAQ,CAAgB;IACxB,OAAO,CAAY;IACnB,OAAO,CAAoB;IAElC,YAAY,QAAkB,EAAE,OAAgB,EAAE,OAA0B;QAC3E,MAAM,IAAI,GAAG,CAAC,QAAQ,CAAC,MAAM,IAAI,QAAQ,CAAC,MAA
```

### `distribution/errors/TimeoutError.d.ts` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (98%). This is a TypeScript declaration file generated as build output and contains only type information, with no executable code or install-time behavior.

```diff
--- /dev/null
+++ package/distribution/errors/TimeoutError.d.ts
+import type { KyRequest } from '../types/request.js';
+export declare class TimeoutError extends Error {
+    request: KyRequest;
+    constructor(request: Request);
+}
```

### `distribution/errors/TimeoutError.js` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (98%). This is a straightforward build-output file defining the expected TimeoutError class with no network, credential, or obfuscation behavior.

```diff
--- /dev/null
+++ package/distribution/errors/TimeoutError.js
+export class TimeoutError extends Error {
+    request;
+    constructor(request) {
+        super(`Request timed out: ${request.method} ${request.url}`);
+        this.name = 'TimeoutError';
+        this.request = request;
+    }
+}
+//# sourceMappingURL=TimeoutError.js.map
```

### `distribution/errors/TimeoutError.js.map` (low)

Build output produced at publish time (no direct source counterpart); also shipped in 1.7.3

- **AI (beam:cloud)**: benign (95%). This is a generated source map for a published build artifact and contains only normal mapping metadata. No install scripts, network calls, obfuscation, or suspicious behavior are evident from the provided excerpt.

```diff
--- /dev/null
+++ package/distribution/errors/TimeoutError.js.map
+{"version":3,"file":"TimeoutError.js","sourceRoot":"","sources":["../../source/errors/TimeoutError.ts"],"names":[],"mappings":"AAEA,MAAM,OAAO,YAAa,SAAQ,KAAK;IAC/B,OAAO,CAAY;IAE1B,YAAY,OAAgB;QAC3B,KAAK,CAAC,sBAAsB,OAAO,CAAC,MAAM,IAAI,OAAO,CAAC,GAAG,EAAE,CAAC,CAAC;QAC7D,IAAI,CAAC,IAAI,GAAG,cAAc,CAAC;Q
```

## Notes

- AI explanations limited to the top 12 of 60 findings

_Generated by WhoTouchedMyTarball 0.1.0_
