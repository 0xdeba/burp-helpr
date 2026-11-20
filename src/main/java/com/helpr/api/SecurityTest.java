package com.helpr.api;

import com.helpr.model.TestContext;
import com.helpr.model.TestResult;

/**
 * Extension point for Helpr test modules. Every emitted TestResult must use
 * exactly one of TestStatus.TRUE, FALSE, or UNDETERMINED.
 */
public interface SecurityTest {
    String id();
    String name();
    String category();
    boolean isEnabled();
    void setEnabled(boolean enabled);
    void execute(TestContext context, TestResultCallback callback);

    @FunctionalInterface
    interface TestResultCallback {
        /** Emits a result whose status is constrained by the TestStatus enum. */
        void onResult(TestResult result);
    }
}
