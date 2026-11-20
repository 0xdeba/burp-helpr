# Helpr

**Helpr — Your Personal Security Helper** is a modular, Proxy-only Burp Suite extension built with Java and the Montoya API.

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

The script downloads `montoya-api-2026.7.jar` into `lib/` if it is not already present, compiles the source against Java 21, and creates `dist\helpr.jar`.

## Load in Burp

1. Open **Extensions → Installed → Add**.
2. Select **Java** as the extension type.
3. Choose `dist\helpr.jar`.
4. Open the **Helpr** suite tab.
5. Enable monitoring when ready.

## Proxy-history-driven testing

- Helpr registers Burp Proxy request and response handlers only. Repeater, Intruder, Scanner, and other tool traffic do not seed tests.
- A test context is created only after Helpr observes a completed, in-scope Proxy request/response exchange while monitoring is enabled and after exclusions are checked. This is the source traffic represented in Burp Proxy HTTP history; Helpr does not crawl, discover, or independently seed endpoint URLs.
- Each test module starts from that captured Proxy request. It creates a modified copy when needed and sends the replay through Montoya's HTTP API.
- Replays are sent outside the Proxy listener, so they do not recursively trigger Helpr or become new Proxy-history seeds. Burp may show API-generated traffic in other applicable logging views, but Helpr does not treat its own replays as new input.
- The original Proxy request and response are retained unchanged as evidence. Every test result stores the original pair and its own modified/replayed request and response.
- Requests already admitted while Helpr was ON are completed even if monitoring is switched OFF before the response arrives.
- Burp Target Scope is used directly; Helpr does not implement a second scope system.
- Endpoint exclusions and ignored file extensions are checked before test scheduling. Static resources such as `.css`, `.js`, `.png`, `.svg`, `.ttf`, `.woff`, and `.woff2` are ignored by default. The extension list is configurable.
- Original Proxy messages are never modified.
- No deduplication is performed during collection or test execution. Every eligible completed Proxy exchange is passed independently to each enabled test module.

## Initial test modules

### Missing Authentication

- Uses each eligible captured Proxy request as its starting point.
- Removes the configured header names from a derived request (defaults: `Authorization`, `Cookie`, `X-Auth-Token`).
- Replays the modified request and records the original and replayed HTTP evidence.

### HTTP Methods

- Probes configured methods against the endpoint from the captured Proxy request.
- OPTIONS, GET and HEAD are enabled by default.
- POST, PUT, PATCH, DELETE, TRACE and CONNECT are opt-in.
- State-changing method probes may reuse the captured body. Enable them only when the target and operation are safe and authorized.

## HTML report

- The report contains **Security Findings / Test Results only**. It does not include a separate captured Proxy traffic history section.
- Results are grouped endpoint-first by original HTTP method + host (including port) + exact path. Query strings do not split endpoint groups; different HTTP methods remain separate.
- Endpoint groups are collapsed by default. Test cases inside them are also collapsed by default. HTTP evidence is shown only after expanding the relevant endpoint and test case.
- Each test case includes the complete original request/response, modified/replayed request/response, timestamp, status, and observation.
- The report duplicate option affects exported evidence only. It does not deduplicate or delete collected traffic or test executions.

## Configuration and evidence

- Configuration is stored in `~/.helpr.properties`.
- Session evidence is held in memory. Export reports periodically during large assessments.
- The **Clear Evidence** action clears current-session evidence.
- HTML reports may contain credentials, cookies, tokens, and personal data. Store and share them securely.
- Detection labels are automated indicators, not confirmed vulnerabilities. Review the complete evidence manually.

## Safety

Use Helpr only against systems for which you have authorization. POST, PUT, PATCH, DELETE, TRACE, and CONNECT probes are opt-in because they can have side effects.


## Global test result classification

Every current and future test module must return exactly one `TestStatus` value:

- `TRUE` — sufficient evidence that the tested security issue exists.
- `FALSE` — the test completed and did not detect the issue.
- `UNDETERMINED` — evidence is insufficient for a reliable conclusion.

`TestResult.status` is an enum rather than a free-form string, preventing modules from introducing additional labels. A successful HTTP status or an `Allow` header alone must not be treated as proof of a vulnerability.


### HTML report status display

Each collapsed security test-case row displays one status badge (True, False, or Undetermined) next to the test-case name. Execution-count labels are omitted from endpoint and test-case headings. When duplicate executions are included, the row badge reflects the latest included execution; individual execution evidence remains expandable below it. The overall report summary retains the True, False, and Undetermined totals.

## Shared header inputs and HTTP Header Manipulation

The Test Cases tab contains shared **Include Headers** and **Exclude Headers** inputs.

- Enable **HTTP Header Manipulation** to replay each configured Include Headers line as an independent request against every eligible captured Proxy exchange.
- Use one `Header-Name: value` entry per line. For example, `Accept: text/plain` and `Accept: application/json` generate two separate replays from the same original captured request; values are never combined into a single request.
- Each replay starts from the unchanged original request and replaces/adds only the configured header for that variant. Other original headers and the request body are retained.
- The **Exclude Headers** list is shared with tests that need to remove headers. Missing Authentication uses it to remove configured authentication headers from its cloned request.
- The two panels are saved together using **Save Shared Header Inputs**. An empty Include Headers list means the HTTP Header Manipulation test has no variants to send.
- Every replay stores its own request/response evidence and receives the standard True / False / Undetermined result.

Header manipulation is now a selectable test case; it is not a separate manual request picker or Replay button.


## UI layout update

The suite tab now has three top-level tabs: Dashboard, Test Cases, and Configuration. Configuration contains nested sections for Request / Response inspection, Endpoint Exclusions, Ignored Extensions, and shared Header Inputs. The Request / Response section lists captured Proxy exchanges and displays the selected original request and response; this traffic viewer is not added to the HTML report.
