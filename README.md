# Helpr

**Helpr — Your Personal Security Helper** is a modular, Proxy-only Burp Suite extension built with Java and the Montoya API. It observes eligible traffic captured by Burp Proxy and runs selected security tests against the captured requests.

## Requirements

- JDK 21 or newer (the build targets Java 21 bytecode)
- Windows PowerShell 5.1 or PowerShell 7
- Internet access on the first build to download the Montoya API dependency, or place the dependency JAR in `lib/`
- Burp Suite with Montoya extension support

Helpr does not require Gradle or Maven.

## Build on Windows

Open PowerShell in the Helpr project directory and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

The build script downloads `montoya-api-2026.7.jar` into `lib/` if it is not already present, compiles the source for Java 21, and creates `dist\helpr.jar`.

## Load in Burp Suite

1. Open **Extensions → Installed → Add**.
2. Select **Java** as the extension type.
3. Choose `dist\helpr.jar`.
4. Open the **Helpr** suite tab.
5. Select the desired test cases and configure their options.
6. Enable monitoring when ready to browse the target application.

## How traffic is processed

- Helpr registers Burp Proxy request and response handlers. Repeater, Intruder, Scanner, and other tool traffic do not seed tests.
- A test context is created from a completed, in-scope Proxy request/response exchange observed while monitoring is enabled, after endpoint exclusions and ignored-extension filters are applied.
- Helpr does not crawl the application or independently discover endpoint URLs. Captured Proxy traffic is the source of endpoint and request data.
- Each enabled test module receives the captured request as its starting point. Modules may analyse it directly or create a modified copy for a test replay.
- Test replays use the Montoya HTTP API rather than the Proxy listener, preventing Helpr's own replays from recursively becoming new Proxy inputs.
- The original Proxy request and response are retained unchanged. Test results retain the original exchange and the relevant test request/response evidence.
- Requests admitted while monitoring is enabled are allowed to complete even if monitoring is disabled before the response arrives.
- Burp Target Scope is used directly; Helpr does not maintain a separate scope configuration.
- No deduplication is performed during traffic collection or test execution. Repeated eligible Proxy exchanges can therefore produce repeated test executions. Report-generation options control how those results are exported.

## Test cases

The Test Cases tab contains selectable test modules. The currently implemented modules are described below.

### 1. Missing Authentication

- Starts with each eligible captured Proxy request.
- Removes the configured authentication header names from a derived request and replays it.
- Default authentication header names are `Authorization`, `Cookie`, and `X-Auth-Token`.
- The shared **Exclude Headers** configuration controls which headers this test removes.
- The original request is not modified. The original and unauthenticated replay evidence are retained in the result.

### 2. HTTP Methods

HTTP Methods is one selectable test case. It probes the configured methods against the endpoint represented by the captured Proxy request.

- `OPTIONS`, `GET`, and `HEAD` are enabled by default.
- `POST`, `PUT`, `PATCH`, `DELETE`, `TRACE`, and `CONNECT` are opt-in.
- For `OPTIONS`, the configured test condition is identified when the response is successful and includes an `Allow` header. A successful response without `Allow`, or an HTTP `405` / `501`, is classified as False. No response is Undetermined.
- For other methods, a `2xx` or `3xx` response identifies that the method responded; `405` / `501` indicates rejection; other responses may be Undetermined.
- When an opt-in state-changing method is enabled, Helpr may reuse the captured request body. Enable these methods only when the target and operation are safe and authorized.
- In the HTML report, all method checks are grouped under one collapsible **HTTP Methods — target-host** entry. Each method has its own status and request/response evidence.

### 3. CORS Misconfiguration

CORS is one selectable test case. Its individual checks are grouped under one collapsible **CORS Misconfiguration — target-host** entry in the HTML report.

The current checks are:

- **Arbitrary / Wildcard Origin Acceptance** — sends an untrusted origin (`https://helpr-untrusted-origin.invalid`) and checks whether the response returns `Access-Control-Allow-Origin: *` or reflects that exact untrusted origin.
- **Credentialed CORS with Untrusted Origin** — reuses the untrusted-origin probe and checks whether the exact untrusted origin is reflected together with `Access-Control-Allow-Credentials: true`. A wildcard response does not satisfy this check.
- **Null Origin Acceptance** — sends `Origin: null` and checks whether the response explicitly allows `null`.
- **Improper Subdomain Trust** — derives candidate origins from the actual endpoint host and checks a candidate subdomain, a deceptive suffix, and a substring-lookalike origin. The report lists these as separate sub-checks.
- **Insecure CORS Cache Handling** — checks whether an untrusted origin is dynamically reflected without `Vary: Origin`. This is an indicator requiring confirmation of shared-cache behaviour; it is not, by itself, proof of exploitable cache impact.

CORS probes are currently limited to captured `GET` and `HEAD` requests. Other captured methods produce an Undetermined result indicating that the probes were skipped to avoid replaying state-changing requests. Preflight Policy and Exposed Response Headers are not separate checks in the current implementation.

CORS acceptance indicators are not automatically proof of a vulnerability. Review the endpoint's sensitivity, browser credential behaviour, origin trust requirements, and complete HTTP evidence before drawing conclusions.

### 4. HTTP Header Manipulation

- Enable **HTTP Header Manipulation** to replay each configured **Include Headers** entry as an independent request against each eligible captured Proxy exchange.
- Configure one `Header-Name: value` entry per line. For example:

  ```http
  Accept: text/plain
  Accept: application/json
  Accept: application/xml
  ```

  These entries generate three separate replays. They are not combined into one request containing multiple configured values.
- Each replay starts from the unchanged original request and applies the configured header variant. Other original headers and the request body are retained.
- Each replay has its own request/response evidence and standard test status.
- An empty Include Headers list means there are no header variants to send.

## Configuration

The **Configuration** tab contains these sections:

### Endpoint Exclusions

- Add one URL path pattern per line, for example `/api/auth/*`.
- Wildcard `*` and single-character `?` matching are supported.
- Matching requests are skipped by all test modules.

### Ignored Extensions

- Configure one file extension per line.
- Common static resources are ignored by default, including `.css`, `.js`, image formats, `.map`, `.woff`, `.woff2`, `.ttf`, and `.eot`.
- Matching requests continue through Burp normally but are skipped by Helpr's test scheduling.

### Headers

The shared header configuration contains:

- **Include Headers** — header name/value variants used by HTTP Header Manipulation.
- **Exclude Headers** — header names removed by Missing Authentication and other applicable tests.

Configuration is stored in `~/.helpr.properties`.

## HTML report

Helpr generates an HTML report containing **Security Findings / Test Results**. It does not include a separate captured Proxy traffic history section.

### Report hierarchy

- Results are grouped endpoint-first by original HTTP method, host (including port), and exact path.
- Query strings do not split endpoint groups. Different original HTTP methods remain separate endpoints.
- Endpoint groups are collapsed by default.
- CORS and HTTP Methods each appear as one collapsible test case under the endpoint.
- Individual CORS checks and HTTP method checks are nested inside their parent test case. Each nested check has its own status and expandable HTTP evidence.
- Other test modules appear as their own collapsible test-case entries.
- HTTP evidence includes the original request/response and the test request/response, together with timestamp, status, and observation.

### Unique results versus all executions

When generating a report, Helpr displays **Generate all results (include repeated test executions)**. It is unchecked by default.

- **Unchecked (default):** include the first recorded result for each endpoint and named test check. This produces a concise report without repeated executions.
- **Checked:** include every execution and its evidence, including repeated visits to the same endpoint.
- This option affects report output only. It does not delete, deduplicate, or alter captured traffic or in-memory test results.
- The status shown on a collapsed test/check row reflects the latest execution included in the report. Expand the row to inspect the included evidence.

## Result classification

Every test module uses exactly three result statuses:

- **True** — sufficient evidence that the tested condition was identified. This does not necessarily mean the condition is a confirmed vulnerability.
- **False** — the test completed and the tested condition was not identified.
- **Undetermined** — there was insufficient evidence for a reliable conclusion, or the probe could not be completed.

A successful HTTP response or an `Allow` header alone must not be treated as proof of a vulnerability. Interpret each result according to its test objective and review the associated evidence.

## Evidence and session handling

- Captured traffic and test evidence are held in memory for the current Helpr session.
- Use **Clear Evidence** to clear current-session captured traffic and test results.
- Export reports periodically during large assessments if you need to retain evidence.
- HTML reports may contain credentials, cookies, tokens, personal data, and other sensitive information. Store and share them securely.

## Safety and authorization

Use Helpr only against systems for which you have explicit authorization. State-changing HTTP method probes are opt-in and may reuse the captured request body. Review the target and request before enabling them. Automated test statuses are indicators; validate findings manually before reporting them.
