package com.helpr;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.helpr.config.AnalyzerConfig;
import com.helpr.core.AnalyzerEngine;
import com.helpr.core.TestRegistry;
import com.helpr.modules.authentication.MissingAuthenticationTest;
import com.helpr.modules.httpmethods.HttpMethodsTest;
import com.helpr.modules.headers.HttpHeaderManipulationTest;
import com.helpr.modules.cors.CorsMisconfigurationTest;
import com.helpr.ui.AnalyzerPanel;

import javax.swing.SwingUtilities;

public final class Main implements BurpExtension {
    private AnalyzerEngine engine;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Helpr");
        AnalyzerConfig config = new AnalyzerConfig();
        TestRegistry registry = new TestRegistry();
        registry.register(new MissingAuthenticationTest(api, config));
        registry.register(new HttpMethodsTest(api));
        registry.register(new HttpHeaderManipulationTest(api, config));
        registry.register(new CorsMisconfigurationTest(api));

        engine = new AnalyzerEngine(api, config, registry, message ->
                api.logging().logToOutput("[Helpr] " + message));

        // Only Proxy-specific handlers are registered. Repeater, Intruder and Scanner do not trigger Helpr.
        api.proxy().registerRequestHandler(engine.requestHandler());
        api.proxy().registerResponseHandler(engine.responseHandler());

        SwingUtilities.invokeLater(() -> {
            AnalyzerPanel panel = new AnalyzerPanel(engine, config, registry);
            engine.setStatusListener(message -> {
                panel.onStatus(message);
                api.logging().logToOutput("[Helpr] " + message);
            });
            api.userInterface().registerSuiteTab("Helpr", panel);
            api.logging().logToOutput("Helpr loaded. Monitoring is OFF until enabled in the Helpr tab.");
        });

        api.extension().registerUnloadingHandler(() -> {
            if (engine != null) engine.shutdown();
            config.save();
        });
    }
}
