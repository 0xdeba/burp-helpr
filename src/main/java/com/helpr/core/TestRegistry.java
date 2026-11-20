package com.helpr.core;

import com.helpr.api.SecurityTest;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public final class TestRegistry {
    private final List<SecurityTest> tests = new CopyOnWriteArrayList<>();
    public void register(SecurityTest test) { tests.add(test); }
    public List<SecurityTest> all() { return List.copyOf(tests); }
}
