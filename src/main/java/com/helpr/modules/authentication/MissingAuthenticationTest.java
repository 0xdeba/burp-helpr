package com.helpr.modules.authentication;

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

public final class MissingAuthenticationTest implements SecurityTest {
    private final MontoyaApi api;
    private final AnalyzerConfig config;
    private final AtomicBoolean enabled = new AtomicBoolean(true);

    public MissingAuthenticationTest(MontoyaApi api, AnalyzerConfig config) {
        this.api = api;
        this.config = config;
    }

    @Override public String id() { return "AUTH-MISSING"; }
    @Override public String name() { return "Missing Authentication"; }
    @Override public String category() { return "Authentication"; }
    @Override public boolean isEnabled() { return enabled.get(); }
    @Override public void setEnabled(boolean value) { enabled.set(value); }

    @Override
    public void execute(TestContext context, TestResultCallback callback) {
        if (!isEnabled()) return;

        List<String> configuredHeaders = List.copyOf(config.authHeaders());
        boolean hasConfiguredHeader = configuredHeaders.stream().anyMatch(context.request()::hasHeader);
        if (!hasConfiguredHeader) return;

        HttpRequest modified = context.request();
        for (String header : configuredHeaders) {
            modified = modified.withRemovedHeader(header);
        }
        final HttpRequest unauthenticatedRequest = modified;

        try {
            HttpRequestResponse exchange = api.http().sendRequest(unauthenticatedRequest);
            String response = exchange.response() == null ? "" : exchange.response().toString();
            int statusCode = exchange.response() == null ? 0 : exchange.response().statusCode();

            TestStatus status;
            String observation;
            if (statusCode == 401 || statusCode == 403) {
                status = TestStatus.FALSE;
                observation = "The server denied the request after the configured authentication headers were removed.";
            } else if (statusCode >= 200 && statusCode < 300 && !response.isBlank()
                    && context.originalResponse() != null && !context.originalResponse().isBlank()) {
                String originalBody = responseBody(context.originalResponse());
                String replayBody = responseBody(response);
                if (!originalBody.isBlank() && originalBody.equals(replayBody)) {
                    status = TestStatus.TRUE;
                    observation = "The unauthenticated replay returned a successful response with the same response body as the original authenticated exchange.";
                } else {
                    status = TestStatus.UNDETERMINED;
                    observation = "The unauthenticated replay returned HTTP " + statusCode
                            + ", but the response did not sufficiently match the original authenticated response to establish missing authentication.";
                }
            } else {
                status = TestStatus.UNDETERMINED;
                observation = "The unauthenticated replay did not produce sufficient evidence to determine whether authentication is enforced.";
            }

            callback.onResult(new TestResult(context.messageId(), id(), name(), category(),
                    context.endpoint(), context.method(), context.method(), status, observation,
                    context.originalRequest(), context.originalResponse(), unauthenticatedRequest.toString(),
                    response, Instant.now()));
        } catch (Exception e) {
            callback.onResult(new TestResult(context.messageId(), id(), name(), category(),
                    context.endpoint(), context.method(), context.method(), TestStatus.UNDETERMINED,
                    "Replay failed: " + e.getClass().getSimpleName() + ": " + safe(e.getMessage()),
                    context.originalRequest(), context.originalResponse(), unauthenticatedRequest.toString(),
                    "", Instant.now()));
        }
    }

    private static String responseBody(String raw) {
        if (raw == null) return "";
        int separator = raw.indexOf("\r\n\r\n");
        if (separator >= 0) return raw.substring(separator + 4).trim();
        separator = raw.indexOf("\n\n");
        return separator >= 0 ? raw.substring(separator + 2).trim() : "";
    }

    private static String safe(String value) { return value == null ? "" : value; }
}
