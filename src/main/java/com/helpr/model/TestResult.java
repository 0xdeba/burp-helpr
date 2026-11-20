package com.helpr.model;

import java.time.Instant;
import java.util.Objects;

/** One execution of one security test against an observed Proxy endpoint. */
public record TestResult(
        int messageId,
        String testId,
        String testName,
        String category,
        String endpoint,
        String sourceMethod,
        String testMethod,
        TestStatus status,
        String observation,
        String originalRequest,
        String originalResponse,
        String testedRequest,
        String testedResponse,
        Instant timestamp
) {
    public TestResult {
        status = Objects.requireNonNull(status, "Every test result must have a TestStatus");
    }
}
