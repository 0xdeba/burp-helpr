package com.helpr.model;

import java.time.Instant;

/** A completed, eligible request/response exchange observed through Burp Proxy. */
public record TrafficRecord(
        int messageId,
        String endpoint,
        String method,
        String request,
        String response,
        Instant timestamp
) {}
