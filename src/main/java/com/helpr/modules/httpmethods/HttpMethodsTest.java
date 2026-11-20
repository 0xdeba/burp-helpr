package com.helpr.modules.httpmethods;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.helpr.api.SecurityTest;
import com.helpr.model.TestContext;
import com.helpr.model.TestResult;
import com.helpr.model.TestStatus;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

public final class HttpMethodsTest implements SecurityTest {
    private static final List<String> STATE_CHANGING = List.of("POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT");
    private final MontoyaApi api;
    private final AtomicBoolean enabled = new AtomicBoolean(true);
    private final List<String> methods = new CopyOnWriteArrayList<>(List.of("OPTIONS", "GET", "HEAD"));

    public HttpMethodsTest(MontoyaApi api) { this.api = api; }
    @Override public String id() { return "HTTP-METHODS"; }
    @Override public String name() { return "HTTP Methods"; }
    @Override public String category() { return "HTTP Methods"; }
    @Override public boolean isEnabled() { return enabled.get(); }
    @Override public void setEnabled(boolean value) { enabled.set(value); }
    public List<String> methods() { return List.copyOf(methods); }

    public void setMethodEnabled(String method, boolean value) {
        String normalized = method.toUpperCase();
        if (value && !methods.contains(normalized)) methods.add(normalized);
        if (!value) methods.remove(normalized);
    }

    @Override
    public void execute(TestContext context, TestResultCallback callback) {
        if (!isEnabled()) return;

        for (String method : List.copyOf(methods)) {
            if (method.equalsIgnoreCase(context.method())) continue;

            // Potentially state-changing methods are deliberately opt-in in the UI.
            // When enabled, the captured body is retained so the probe can exercise the method.
            HttpRequest testRequest = context.request().withMethod(method);
            if (List.of("OPTIONS", "GET", "HEAD", "TRACE", "CONNECT").contains(method)) {
                testRequest = testRequest.withBody("");
            }
            final HttpRequest requestToSend = testRequest;

            try {
                HttpRequestResponse exchange = api.http().sendRequest(requestToSend);
                String response = exchange.response() == null ? "" : exchange.response().toString();
                int code = exchange.response() == null ? 0 : exchange.response().statusCode();
                String allow = exchange.response() == null ? "" : exchange.response().headerValue("Allow");
                TestStatus status;
                String observation;
                if (code == 0) {
                    status = TestStatus.UNDETERMINED;
                    observation = "No HTTP response was available, so method availability could not be determined.";
                } else if (code == 405 || code == 501) {
                    status = TestStatus.FALSE;
                    observation = "The server rejected the probed method with HTTP " + code
                            + "; the method was not accepted by this endpoint"
                            + (allow == null || allow.isBlank() ? "." : ". Allow: " + allow);
                } else if (method.equalsIgnoreCase("OPTIONS") && (allow == null || allow.isBlank())) {
                    status = TestStatus.FALSE;
                    observation = "The OPTIONS response did not include an Allow header; the configured OPTIONS test condition was not identified.";
                } else if (method.equalsIgnoreCase("OPTIONS")) {
                    status = TestStatus.TRUE;
                    observation = "The OPTIONS response included an Allow header (" + allow
                            + "); the configured OPTIONS test condition was identified. This does not by itself establish a vulnerability.";
                } else if (code >= 200 && code < 400) {
                    status = TestStatus.TRUE;
                    observation = "The " + method + " method is enabled/responding on this endpoint."
                            + " The server returned HTTP " + code
                            + (allow == null || allow.isBlank() ? "." : "; Allow: " + allow)
                            + ". This identifies method availability and does not by itself establish a vulnerability.";
                } else {
                    status = TestStatus.UNDETERMINED;
                    observation = "The server returned HTTP " + code + " for the " + method
                            + " probe. This response does not reliably establish whether the method is enabled or rejected"
                            + (allow == null || allow.isBlank() ? "." : "; Allow: " + allow);
                }

                callback.onResult(new TestResult(context.messageId(), id() + "-" + method,
                        "HTTP Method: " + method, category(), context.endpoint(), context.method(), method,
                        status, observation, context.originalRequest(), context.originalResponse(),
                        requestToSend.toString(), response, Instant.now()));
            } catch (Exception e) {
                callback.onResult(new TestResult(context.messageId(), id() + "-" + method,
                        "HTTP Method: " + method, category(), context.endpoint(), context.method(), method,
                        TestStatus.UNDETERMINED, "Probe failed: " + e.getClass().getSimpleName(),
                        context.originalRequest(), context.originalResponse(), requestToSend.toString(),
                        "", Instant.now()));
            }
        }
    }

    public static boolean isStateChanging(String method) {
        return STATE_CHANGING.contains(method.toUpperCase());
    }
}
