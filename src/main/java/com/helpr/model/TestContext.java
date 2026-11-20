package com.helpr.model;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Test input created only from a completed exchange observed by Helpr's
 * Burp Proxy response handler. Test modules must not create independent
 * endpoint seeds; they replay this captured Proxy request instead.
 */
public record TestContext(
        int messageId,
        String endpoint,
        String method,
        String originalRequest,
        String originalResponse,
        HttpRequest request
) {}
