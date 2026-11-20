package com.helpr.modules.cors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.helpr.api.SecurityTest;
import com.helpr.model.TestContext;
import com.helpr.model.TestResult;
import com.helpr.model.TestStatus;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Security-relevant CORS checks grouped under one selectable test case. */
public final class CorsMisconfigurationTest implements SecurityTest {
    private static final String TEST_ID = "CORS-MISCONFIGURATION";
    private static final String ARBITRARY_ORIGIN = "https://helpr-untrusted-origin.invalid";
    private static final String NULL_ORIGIN = "null";
    private final MontoyaApi api;
    private volatile boolean enabled;

    public CorsMisconfigurationTest(MontoyaApi api) { this.api = api; }
    @Override public String id() { return TEST_ID; }
    @Override public String name() { return "CORS Misconfiguration"; }
    @Override public String category() { return "CORS"; }
    @Override public boolean isEnabled() { return enabled; }
    @Override public void setEnabled(boolean value) { enabled = value; }

    @Override public void execute(TestContext context, TestResultCallback callback) {
        if (!isEnabled()) return;
        if (!List.of("GET", "HEAD").contains(context.method().toUpperCase(Locale.ROOT))) {
            emit(context, callback, "CORS checks", TestStatus.UNDETERMINED,
                    "Skipped: CORS probes are limited to captured GET and HEAD requests to avoid replaying state-changing methods.",
                    context.request().toString(), "");
            return;
        }

        String targetHost = targetHost(context.endpoint());
        String baseDomain = baseDomain(targetHost);
        String trustedLookingSubdomain = "https://helpr-test." + baseDomain;
        String deceptiveSuffix = "https://" + baseDomain + ".attacker.invalid";
        String deceptivePrefix = "https://attacker-" + baseDomain;

        // One untrusted-origin request is shared by the combined reflection/wildcard
        // check and the separate credentialed-CORS check.
        Probe untrusted = probe(context, callback, "Arbitrary / Wildcard Origin Acceptance", ARBITRARY_ORIGIN);
        evaluateCredentialedCors(context, callback, untrusted, ARBITRARY_ORIGIN);
        probe(context, callback, "Null Origin Acceptance", NULL_ORIGIN);

        // Validate domain-boundary handling with origins derived from the actual target host.
        probe(context, callback, "Improper Subdomain Trust — candidate subdomain", trustedLookingSubdomain);
        probe(context, callback, "Improper Subdomain Trust — deceptive suffix", deceptiveSuffix);
        probe(context, callback, "Improper Subdomain Trust — substring lookalike", deceptivePrefix);

        String vary = header(untrusted.response, "Vary");
        boolean reflected = sameOrigin(header(untrusted.response, "Access-Control-Allow-Origin"), ARBITRARY_ORIGIN);
        boolean variesByOrigin = containsToken(vary, "Origin");
        TestStatus cacheStatus = untrusted.response == null ? TestStatus.UNDETERMINED
                : reflected && !variesByOrigin ? TestStatus.TRUE : TestStatus.FALSE;
        emit(context, callback, "Insecure CORS Cache Handling", cacheStatus,
                cacheStatus == TestStatus.TRUE
                        ? "The response dynamically reflects an untrusted Origin but does not include Vary: Origin. Confirm shared-cache behaviour before assessing impact."
                        : "No dynamic arbitrary-origin reflection without Vary: Origin was identified. Vary: " + safe(vary) + ".",
                untrusted.request, untrusted.response);
    }

    private Probe probe(TestContext context, TestResultCallback callback, String check, String origin) {
        HttpRequest request = context.request().withHeader("Origin", origin);
        try {
            HttpRequestResponse exchange = api.http().sendRequest(request);
            String response = exchange.response() == null ? null : exchange.response().toString();
            if (response == null) {
                emit(context, callback, check, TestStatus.UNDETERMINED,
                        "No response was received for Origin " + origin + ".", request.toString(), "");
                return new Probe(request.toString(), null);
            }
            String allowOrigin = header(response, "Access-Control-Allow-Origin");
            String allowCredentials = header(response, "Access-Control-Allow-Credentials");
            TestStatus status;
            String observation;
            switch (check) {
                case "Arbitrary / Wildcard Origin Acceptance" -> {
                    boolean wildcard = "*".equals(trim(allowOrigin));
                    boolean reflected = sameOrigin(allowOrigin, origin);
                    status = wildcard || reflected ? TestStatus.TRUE : TestStatus.FALSE;
                    if (wildcard && reflected) {
                        observation = "The response indicates both wildcard and exact-origin acceptance; inspect the raw response for intermediary or duplicate header behaviour. This probe does not by itself establish credentialed access.";
                    } else if (wildcard) {
                        observation = "The response returns Access-Control-Allow-Origin: *. A wildcard alone does not permit credentialed browser access.";
                    } else if (reflected) {
                        observation = "The server reflects the supplied untrusted Origin in Access-Control-Allow-Origin. Assess endpoint sensitivity and credential behaviour.";
                    } else {
                        observation = "Neither wildcard ACAO nor exact reflection of the supplied untrusted Origin was identified. Access-Control-Allow-Origin: " + safe(allowOrigin) + ".";
                    }
                }
                case "Null Origin Acceptance" -> {
                    status = sameOrigin(allowOrigin, origin) ? TestStatus.TRUE : TestStatus.FALSE;
                    observation = status == TestStatus.TRUE
                            ? "The response explicitly allows Origin: null. Assess whether opaque-origin documents can access sensitive resources."
                            : "The null Origin was not explicitly allowed. Access-Control-Allow-Origin: " + safe(allowOrigin) + ".";
                }
                default -> {
                    boolean accepted = sameOrigin(allowOrigin, origin);
                    status = accepted ? TestStatus.TRUE : TestStatus.FALSE;
                    observation = accepted
                            ? "The server accepted this generated origin: " + origin + ". Compare it with the actual target domain " + targetHost(context.endpoint()) + " and verify whether this origin is genuinely trusted."
                            : "The generated origin was not accepted: " + origin + ". Access-Control-Allow-Origin: " + safe(allowOrigin) + ".";
                }
            }
            emit(context, callback, check, status, observation, request.toString(), response);
            return new Probe(request.toString(), response);
        } catch (Exception e) {
            emit(context, callback, check, TestStatus.UNDETERMINED,
                    "Origin probe failed: " + e.getClass().getSimpleName(), request.toString(), "");
            return new Probe(request.toString(), null);
        }
    }

    private void evaluateCredentialedCors(TestContext context, TestResultCallback callback,
                                          Probe probe, String origin) {
        if (probe.response == null) {
            emit(context, callback, "Credentialed CORS with Untrusted Origin", TestStatus.UNDETERMINED,
                    "The shared untrusted-origin probe did not receive a response.", probe.request, "");
            return;
        }
        String allowOrigin = header(probe.response, "Access-Control-Allow-Origin");
        String allowCredentials = header(probe.response, "Access-Control-Allow-Credentials");
        boolean credentialedReflection = sameOrigin(allowOrigin, origin)
                && "true".equalsIgnoreCase(trim(allowCredentials));
        TestStatus status = credentialedReflection ? TestStatus.TRUE : TestStatus.FALSE;
        String observation = credentialedReflection
                ? "The untrusted Origin is reflected and Access-Control-Allow-Credentials: true is returned. Review endpoint sensitivity and browser credential behaviour."
                : "The response did not combine exact reflection of the untrusted Origin with Access-Control-Allow-Credentials: true. Wildcard ACAO does not satisfy this credentialed-origin check.";
        emit(context, callback, "Credentialed CORS with Untrusted Origin", status,
                observation, probe.request, probe.response);
    }

    private record Probe(String request, String response) { }

    private static String targetHost(String endpoint) {
        try {
            String host = URI.create(endpoint).getHost();
            return host == null ? "unknown-target" : host.toLowerCase(Locale.ROOT);
        } catch (Exception ignored) { return "unknown-target"; }
    }

    // Remove a conventional www prefix; retain the target's registered-looking host labels.
    private static String baseDomain(String host) {
        if (host == null || host.isBlank() || "unknown-target".equals(host)) return "helpr-target.invalid";
        String value = host.toLowerCase(Locale.ROOT);
        return value.startsWith("www.") ? value.substring(4) : value;
    }

    private static void emit(TestContext c, TestResultCallback cb, String check, TestStatus status,
                             String observation, String request, String response) {
        cb.onResult(new TestResult(c.messageId(), TEST_ID, "CORS Misconfiguration — " + check,
                "CORS", c.endpoint(), c.method(), "CORS", status, observation,
                c.originalRequest(), c.originalResponse(), request, response == null ? "" : response, Instant.now()));
    }

    private static String header(String raw, String name) {
        if (raw == null) return null;
        Matcher m = Pattern.compile("(?im)^" + Pattern.quote(name) + ":\\s*(.*?)\\s*$").matcher(raw);
        return m.find() ? m.group(1).trim() : null;
    }
    private static boolean containsToken(String value, String token) {
        if (value == null) return false;
        for (String part : value.split(",")) if (part.trim().equalsIgnoreCase(token)) return true;
        return false;
    }
    private static boolean sameOrigin(String actual, String expected) {
        return actual != null && actual.trim().equalsIgnoreCase(expected);
    }
    private static String trim(String value) { return value == null ? "" : value.trim(); }
    private static String safe(String value) { return value == null ? "<missing>" : value; }
}
