package com.helpr.model;

/** The only permitted result classifications for every Helpr security test. */
public enum TestStatus {
    TRUE("True"), FALSE("False"), UNDETERMINED("Undetermined");
    private final String label;
    TestStatus(String label) { this.label = label; }
    public String label() { return label; }
    @Override public String toString() { return label; }
}
