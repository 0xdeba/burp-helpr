package com.helpr.reporting;

import java.net.URI;
import java.util.Locale;

/** Report grouping identity: observed method + host (including port) + exact path; query is ignored. */
public record EndpointKey(String method, String authority, String path) {
    public static EndpointKey of(String method, String url) {
        String normalizedMethod = method == null ? "" : method.toUpperCase(Locale.ROOT);
        try {
            URI uri = URI.create(url);
            String host = uri.getHost() == null ? uri.getRawAuthority() : uri.getHost().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            String authority = (host == null ? "" : host) + (port < 0 ? "" : ":" + port);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            return new EndpointKey(normalizedMethod, authority, path);
        } catch (Exception ignored) {
            String raw = url == null ? "" : url;
            int query = raw.indexOf('?');
            if (query >= 0) raw = raw.substring(0, query);
            return new EndpointKey(normalizedMethod, "", raw);
        }
    }

    public String display() {
        return method + " " + authority + path;
    }
}
