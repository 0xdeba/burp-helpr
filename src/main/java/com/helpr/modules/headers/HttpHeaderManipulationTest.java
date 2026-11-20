package com.helpr.modules.headers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.helpr.api.SecurityTest;
import com.helpr.config.AnalyzerConfig;
import com.helpr.model.TestContext;
import com.helpr.model.TestResult;
import com.helpr.model.TestStatus;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Replays one independent request for every configured Include Headers line. */
public final class HttpHeaderManipulationTest implements SecurityTest {
    private final MontoyaApi api;
    private final AnalyzerConfig config;
    private final AtomicBoolean enabled = new AtomicBoolean(false);

    public HttpHeaderManipulationTest(MontoyaApi api, AnalyzerConfig config) {
        this.api = api;
        this.config = config;
    }
    @Override public String id() { return "HTTP-HEADER-MANIPULATION"; }
    @Override public String name() { return "HTTP Header Manipulation"; }
    @Override public String category() { return "HTTP Headers"; }
    @Override public boolean isEnabled() { return enabled.get(); }
    @Override public void setEnabled(boolean value) { enabled.set(value); }

    @Override public void execute(TestContext context, TestResultCallback callback) {
        if (!isEnabled()) return;
        List<String> variants = List.copyOf(config.includeHeaders());
        if (variants.isEmpty()) return;
        for (String line : variants) {
            if (line == null || line.isBlank()) continue;
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String headerName = line.substring(0, colon).trim();
            String headerValue = line.substring(colon + 1).trim();
            if (headerName.isEmpty()) continue;

            // Each configured line produces a separate replay from the original request.
            HttpRequest modified = context.request().withHeader(headerName, headerValue);
            try {
                HttpRequestResponse exchange = api.http().sendRequest(modified);
                String response = exchange.response() == null ? "" : exchange.response().toString();
                int code = exchange.response() == null ? 0 : exchange.response().statusCode();
                TestStatus status = code == 0 ? TestStatus.UNDETERMINED : verboseDisclosure(response)
                        ? TestStatus.TRUE : TestStatus.FALSE;
                String observation = code == 0
                        ? "No response was received for header variant " + headerName + ": " + headerValue
                        : verboseDisclosure(response)
                            ? "The modified " + headerName + " header triggered a response containing verbose diagnostic information. Review the evidence for sensitive disclosure."
                            : "The modified " + headerName + " header (" + headerValue + ") received HTTP " + code + "; no recognized verbose diagnostic disclosure was detected.";
                callback.onResult(new TestResult(context.messageId(), id() + "-" + safeId(headerName + "-" + headerValue),
                        "Header: " + headerName + " = " + headerValue, category(), context.endpoint(), context.method(),
                        "HEADER", status, observation, context.originalRequest(), context.originalResponse(),
                        modified.toString(), response, Instant.now()));
            } catch (Exception e) {
                callback.onResult(new TestResult(context.messageId(), id() + "-" + safeId(headerName + "-" + headerValue),
                        "Header: " + headerName + " = " + headerValue, category(), context.endpoint(), context.method(),
                        "HEADER", TestStatus.UNDETERMINED, "Header variant replay failed: " + e.getClass().getSimpleName(),
                        context.originalRequest(), context.originalResponse(), modified.toString(), "", Instant.now()));
            }
        }
    }

    private static boolean verboseDisclosure(String response) {
        if (response == null || response.isBlank()) return false;
        String value = response.toLowerCase(java.util.Locale.ROOT);
        if (value.contains("stack trace") || value.contains("traceback")
                || value.contains("sqlstate") || value.contains("syntax error at or near")
                || value.contains("/var/www/") || value.contains("debugger")
                || value.contains("development server") || value.contains("exception in thread")) {
            return true;
        }
        return Pattern.compile("(?is)\\bat\\s+[\\w.$]+\\([^\\n]*\\)").matcher(value).find();
    }
    private static String safeId(String value) { return value.replaceAll("[^A-Za-z0-9._-]", "_"); }
}
