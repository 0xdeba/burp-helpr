package com.helpr.config;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public final class AnalyzerConfig {
    private final Path file = Path.of(System.getProperty("user.home"), ".helpr.properties");
    private final Properties properties = new Properties();
    private final List<String> excludedEndpoints = new CopyOnWriteArrayList<>();
    private final List<String> authHeaders = new CopyOnWriteArrayList<>();
    private final List<String> includeHeaders = new CopyOnWriteArrayList<>();
    private final List<String> ignoredExtensions = new CopyOnWriteArrayList<>();

    public AnalyzerConfig() {
        authHeaders.addAll(List.of("Authorization", "Cookie", "X-Auth-Token"));
        excludedEndpoints.addAll(List.of("/api/auth/login", "/api/auth/logout", "/api/auth/refresh"));
        
        ignoredExtensions.addAll(List.of(".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".map"));
        load();
    }

    public synchronized void load() {
        if (Files.exists(file)) {
            try (InputStream in = Files.newInputStream(file)) { properties.load(in); }
            catch (IOException ignored) { }
            replaceList(excludedEndpoints, properties.getProperty("excluded", String.join("\n", excludedEndpoints)));
            replaceList(authHeaders, properties.getProperty("authHeaders", String.join("\n", authHeaders)));
            replaceList(includeHeaders, properties.getProperty("includeHeaders", String.join("\n", includeHeaders)));
            replaceList(ignoredExtensions, properties.getProperty("ignoredExtensions", String.join("\n", ignoredExtensions)));
        }
    }

    public synchronized void save() {
        properties.setProperty("excluded", String.join("\n", excludedEndpoints));
        properties.setProperty("authHeaders", String.join("\n", authHeaders));
        properties.setProperty("includeHeaders", String.join("\n", includeHeaders));
        properties.setProperty("ignoredExtensions", String.join("\n", ignoredExtensions));
        try (OutputStream out = Files.newOutputStream(file)) {
            properties.store(out, "Helpr configuration");
        } catch (IOException ignored) { }
    }

    private static void replaceList(List<String> target, String value) {
        target.clear();
        Arrays.stream(value.split("\\R")).map(String::trim).filter(s -> !s.isEmpty()).forEach(target::add);
    }

    public List<String> excludedEndpoints() { return excludedEndpoints; }
    public List<String> authHeaders() { return authHeaders; }
    public List<String> includeHeaders() { return includeHeaders; }
    public List<String> ignoredExtensions() { return ignoredExtensions; }

    /** True when the URL path ends with a configured static-file extension. */
    public boolean isIgnoredExtension(String url) {
        String path = url == null ? "" : url;
        try {
            java.net.URI uri = java.net.URI.create(path);
            if (uri.getRawPath() != null) path = uri.getRawPath();
        } catch (Exception ignored) {
            int query = path.indexOf('?');
            if (query >= 0) path = path.substring(0, query);
        }
        String candidate = path.toLowerCase(Locale.ROOT);
        for (String extension : ignoredExtensions) {
            String ext = extension.trim().toLowerCase(Locale.ROOT);
            if (ext.isEmpty()) continue;
            if (!ext.startsWith(".")) ext = "." + ext;
            if (candidate.endsWith(ext)) return true;
        }
        return false;
    }

    public boolean isExcluded(String url) {
        String candidate = url == null ? "" : url;
        String path = candidate;
        try {
            java.net.URI uri = java.net.URI.create(candidate);
            if (uri.getRawPath() != null) path = uri.getRawPath();
        } catch (Exception ignored) { }

        for (String rule : excludedEndpoints) {
            String r = rule.trim();
            if (r.isEmpty()) continue;
            String target = r.contains("://") ? candidate : path;
            String matchRule = r.contains("://") ? r : r;
            if (!r.contains("://") && !r.startsWith("/")) matchRule = "/" + r;
            if (globMatches(target, matchRule)) return true;
        }
        return false;
    }

    private static boolean globMatches(String value, String glob) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '*') regex.append(".*");
            else if (c == '?') regex.append('.');
            else regex.append(java.util.regex.Pattern.quote(String.valueOf(c)));
        }
        regex.append("$");
        return java.util.regex.Pattern.compile(regex.toString())
                .matcher(value).matches();
    }
}
