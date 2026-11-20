package com.helpr.reporting;

import com.helpr.model.TestResult;
import com.helpr.model.TestStatus;
import com.helpr.model.TrafficRecord;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class HtmlReportGenerator {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());

    /**
     * @param includeDuplicateOccurrences true keeps every test execution;
     *                                    false keeps the first execution of each test case
     *                                    for each endpoint group. Traffic is used by the analyzer,
     *                                    but is intentionally not included in the report.
     */
    public void write(Path path, List<TrafficRecord> traffic, List<TestResult> results,
                      boolean includeDuplicateOccurrences) throws IOException {
        Map<EndpointKey, EndpointGroup> groups = new LinkedHashMap<>();

        // The report is findings-focused: captured Proxy traffic is deliberately omitted.
        // Endpoint groups are created only for endpoints with executed test cases.
        List<TestResult> orderedResults = new ArrayList<>(results);
        orderedResults.sort(Comparator.comparing(TestResult::timestamp));
        for (TestResult result : orderedResults) {
            EndpointKey key = EndpointKey.of(result.sourceMethod(), result.endpoint());
            groups.computeIfAbsent(key, EndpointGroup::new).results.add(result);
        }

        StringBuilder h = new StringBuilder(96_000);
        h.append("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
         .append("<title>Helpr Security Assessment Report</title><style>")
         .append("*{box-sizing:border-box}body{font:14px/1.55 system-ui,Arial,sans-serif;margin:0;background:#f4f6fa;color:#172033}header{background:#111827;color:#fff;padding:28px 5vw}main{max-width:1500px;margin:24px auto;padding:0 20px}.cards{display:flex;gap:12px;flex-wrap:wrap}.card,section{background:#fff;border:1px solid #dce1ea;border-radius:10px;padding:16px;margin:12px 0}.card{min-width:145px}.n{font-size:26px;font-weight:700}.endpoint{border:1px solid #d6deea;border-radius:10px;margin:14px 0;background:#fff;overflow:hidden}.endpoint>summary{cursor:pointer;padding:15px 18px;font-weight:700;background:#f9fbfe}.endpoint-body{padding:14px 18px}.testcase{border:1px solid #e1e6ef;border-radius:8px;margin:10px 0;background:#fff}.testcase>summary{cursor:pointer;padding:12px;font-weight:650;display:flex;align-items:center;gap:10px;flex-wrap:wrap}.testcase-name{flex:1;min-width:180px}.cors-check{border-top:1px solid #e8edf3;margin:0 12px}.cors-check>summary{cursor:pointer;padding:10px 12px;font-weight:600;display:flex;gap:10px;align-items:center}.status-pill{margin-left:0}.occurrence{border-top:1px solid #e8edf3;padding:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101827;color:#e5edf8;padding:14px;border-radius:8px;max-height:620px;overflow:auto;font:12px/1.5 ui-monospace,Consolas,monospace}.pill{display:inline-block;padding:2px 8px;border-radius:20px;background:#e8edf5;font-size:12px;margin-left:6px}.True{background:#dcfce7;color:#166534}.False{background:#fee2e2;color:#991b1b}.Undetermined{background:#fef3c7;color:#92400e}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.muted{color:#657086;font-size:12px}.meta{color:#657086;font-size:12px}.section-title{margin:22px 0 8px}@media(max-width:850px){.grid{grid-template-columns:1fr}}</style></head><body>")
         .append("<header><h1>Helpr</h1><div>Security Assessment Report · Generated ").append(esc(TIME.format(Instant.now()))).append("</div>")
         .append("<p>Endpoint-first security findings report. Test results are grouped by HTTP method, host and exact path; query strings are not used as endpoint identity. Each test includes its original and modified HTTP evidence.</p>")
         .append("<p class='muted'>This report may contain authentication tokens, cookies, credentials and personal data. Store and share it securely.</p></header><main>");

        List<TestResult> visibleResults = new ArrayList<>();
        for (EndpointGroup group : groups.values()) {
            for (List<TestResult> executions : groupByTestCase(group.results, includeDuplicateOccurrences).values()) {
                visibleResults.addAll(executions);
            }
        }
        long trueCount = visibleResults.stream().filter(r -> r.status() == TestStatus.TRUE).count();
        long falseCount = visibleResults.stream().filter(r -> r.status() == TestStatus.FALSE).count();
        long undeterminedCount = visibleResults.stream().filter(r -> r.status() == TestStatus.UNDETERMINED).count();
        h.append("<div class='cards'>");
        metric(h, "Unique endpoints", groups.size());
        metric(h, "True", trueCount);
        metric(h, "False", falseCount);
        metric(h, "Undetermined", undeterminedCount);
        h.append("</div><section><h2>Endpoint results</h2>")
         .append("<p class='muted'>Duplicate filter: ").append(includeDuplicateOccurrences ? "all test executions included" : "first occurrence per endpoint/test case only").append(".</p>");

        if (groups.isEmpty()) {
            h.append("<p>No security test results were recorded.</p>");
        }

        int endpointNumber = 0;
        for (EndpointGroup group : groups.values()) {
            endpointNumber++;
            Map<String, List<TestResult>> byTest = groupByTestCase(group.results, includeDuplicateOccurrences);
            h.append("<details class='endpoint'><summary>Endpoint ").append(endpointNumber).append(" — ")
             .append(esc(group.key.display())).append("</summary><div class='endpoint-body'>");

            h.append("<h3 class='section-title'>Security test cases</h3>");
            if (byTest.isEmpty()) h.append("<p class='muted'>No test results recorded for this endpoint.</p>");
            // CORS and HTTP Methods are each represented as one collapsible test case.
            Map<String, List<TestResult>> corsChecks = new LinkedHashMap<>();
            Map<String, List<TestResult>> methodChecks = new LinkedHashMap<>();
            for (Map.Entry<String, List<TestResult>> entry : byTest.entrySet()) {
                List<TestResult> values = entry.getValue();
                if (values.isEmpty()) continue;
                String testId = values.get(0).testId();
                if ("CORS-MISCONFIGURATION".equals(testId)) {
                    corsChecks.put(entry.getKey(), values);
                } else if (testId.startsWith("HTTP-METHODS-")) {
                    methodChecks.put(entry.getKey(), values);
                } else {
                    renderTestCase(h, values);
                }
            }
            if (!corsChecks.isEmpty()) {
                String corsHost = group.key.authority();
                h.append("<details class='testcase'><summary><span class='testcase-name'>CORS Misconfiguration — ")
                 .append(esc(corsHost)).append("</span></summary>");
                for (List<TestResult> checks : corsChecks.values()) {
                    String checkName = checks.get(0).testName().replaceFirst("^CORS Misconfiguration\\s*—\\s*", "");
                    renderNestedCheck(h, checkName, checks);
                }
                h.append("</details>");
            }
            if (!methodChecks.isEmpty()) {
                h.append("<details class='testcase'><summary><span class='testcase-name'>HTTP Methods — ")
                 .append(esc(group.key.authority())).append("</span></summary>");
                for (List<TestResult> checks : methodChecks.values()) {
                    String checkName = checks.get(0).testName().replaceFirst("^HTTP Method:\\s*", "");
                    renderNestedCheck(h, checkName, checks);
                }
                h.append("</details>");
            }

            h.append("</div></details>");
        }

        h.append("</section><p class='muted'>True, False and Undetermined are automated test outcomes. Review the included HTTP evidence before drawing final conclusions.</p></main></body></html>");
        Files.writeString(path, h.toString(), StandardCharsets.UTF_8);
    }

    private static void renderNestedCheck(StringBuilder h, String checkName, List<TestResult> checks) {
        TestResult latest = checks.get(checks.size() - 1);
        h.append("<details class='cors-check'><summary><span class='testcase-name'>")
         .append(esc(checkName)).append("</span><span class='pill status-pill ")
         .append(css(latest.status().label())).append("'>").append(esc(latest.status().label()))
         .append("</span></summary>");
        renderEvidence(h, checks);
        h.append("</details>");
    }

    private static void renderTestCase(StringBuilder h, List<TestResult> executions) {
        if (executions == null || executions.isEmpty()) return;
        TestResult first = executions.get(0);
        TestResult latest = executions.get(executions.size() - 1);
        h.append("<details class='testcase'><summary><span class='testcase-name'>")
         .append(esc(first.testName())).append("</span><span class='pill status-pill ")
         .append(css(latest.status().label())).append("'>").append(esc(latest.status().label()))
         .append("</span></summary>");
        renderEvidence(h, executions);
        h.append("</details>");
    }

    private static void renderEvidence(StringBuilder h, List<TestResult> executions) {
        for (TestResult result : executions) {
            h.append("<div class='occurrence'><p><b>Status:</b> <span class='pill ").append(css(result.status().label())).append("'>")
             .append(esc(result.status().label())).append("</span> <b>Probe method:</b> ").append(esc(result.testMethod()))
             .append(" <b>Time:</b> ").append(esc(TIME.format(result.timestamp()))).append("</p>")
             .append("<p><b>Observation:</b> ").append(esc(result.observation())).append("</p><div class='grid'>");
            block(h, "Original request", result.originalRequest());
            block(h, "Original response", result.originalResponse());
            block(h, "Test request", result.testedRequest());
            block(h, "Test response", result.testedResponse());
            h.append("</div></div>");
        }
    }

    private static Map<String, List<TestResult>> groupByTestCase(List<TestResult> results, boolean includeDuplicates) {
        Map<String, List<TestResult>> grouped = new LinkedHashMap<>();
        for (TestResult result : results) {
            // A test module may emit multiple named sub-checks under one selectable test ID
            // (for example, the CORS suite). Deduplicate each named check independently so
            // the first-occurrence filter never hides the remaining checks.
            String resultKey = result.testId() + "\u0000" + result.testName();
            List<TestResult> executions = grouped.computeIfAbsent(resultKey, ignored -> new ArrayList<>());
            if (includeDuplicates || executions.isEmpty()) executions.add(result);
        }
        return grouped;
    }

    private static void metric(StringBuilder h, String label, long value) {
        h.append("<div class='card'><div class='n'>").append(value).append("</div><div>").append(esc(label)).append("</div></div>");
    }

    private static void block(StringBuilder h, String title, String value) {
        h.append("<div><h4>").append(esc(title)).append("</h4><pre>").append(esc(value == null ? "" : value)).append("</pre></div>");
    }

    private static String css(String value) { return value == null ? "" : value.replace(' ', '-'); }

    private static String esc(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static final class EndpointGroup {
        private final EndpointKey key;
        private final List<TestResult> results = new ArrayList<>();
        private EndpointGroup(EndpointKey key) { this.key = key; }
    }

}
