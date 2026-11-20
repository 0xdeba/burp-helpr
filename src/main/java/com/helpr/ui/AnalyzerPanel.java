package com.helpr.ui;

import com.helpr.api.SecurityTest;
import com.helpr.config.AnalyzerConfig;
import com.helpr.core.AnalyzerEngine;
import com.helpr.core.TestRegistry;
import com.helpr.modules.httpmethods.HttpMethodsTest;
import com.helpr.reporting.HtmlReportGenerator;
import com.helpr.model.TestStatus;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Path;
import java.util.List;

public final class AnalyzerPanel extends JPanel {
    private final AnalyzerEngine engine;
    private final AnalyzerConfig config;
    private final TestRegistry registry;
    private final JTextArea activity = new JTextArea();
    private final JLabel trafficCount = new JLabel("0");
    private final JLabel testCount = new JLabel("0");
    private final JLabel trueCount = new JLabel("0");
    private final JLabel falseCount = new JLabel("0");
    private final JLabel undeterminedCount = new JLabel("0");
    private final JLabel state = new JLabel("Disabled");
    private final JButton toggle = new JButton("Enable Monitoring");

    public AnalyzerPanel(AnalyzerEngine engine, AnalyzerConfig config, TestRegistry registry) {
        super(new BorderLayout(8, 8));
        this.engine = engine;
        this.config = config;
        this.registry = registry;
        setBorder(new EmptyBorder(12, 12, 12, 12));

        add(buildHeader(), BorderLayout.NORTH);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Dashboard", dashboard());
        tabs.addTab("Test Cases", testCases());
        tabs.addTab("Configuration", configuration());
        add(tabs, BorderLayout.CENTER);
        refreshCounts();
    }

    private JComponent buildHeader() {
        JPanel p = new JPanel(new BorderLayout());
        JLabel title = new JLabel("Helpr");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 20f));

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        toggle.addActionListener(e -> {
            boolean next = !engine.isEnabled();
            engine.setEnabled(next);
            toggle.setText(next ? "Disable Monitoring" : "Enable Monitoring");
            state.setText(next ? "Monitoring" : "Disabled");
        });
        JButton report = new JButton("Generate HTML Report");
        report.addActionListener(e -> generateReport());
        JButton clear = new JButton("Clear Evidence");
        clear.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(this,
                    "Clear all captured Proxy traffic and test evidence from this Helpr session?",
                    "Clear Helpr Evidence", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.YES_OPTION) {
                engine.clearEvidence();
                refreshCounts();
            }
        });
        right.add(state);
        right.add(toggle);
        right.add(report);
        right.add(clear);
        p.add(title, BorderLayout.WEST);
        p.add(right, BorderLayout.EAST);
        return p;
    }

    private JComponent dashboard() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        JPanel metrics = new JPanel(new GridLayout(1, 3, 8, 8));
        metrics.add(metric("Captured Proxy exchanges", trafficCount));
        metrics.add(metric("Test executions", testCount));
        metrics.add(metric("True", trueCount));
        metrics.add(metric("False", falseCount));
        metrics.add(metric("Undetermined", undeterminedCount));
        activity.setEditable(false);
        activity.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        p.add(metrics, BorderLayout.NORTH);
        p.add(new JScrollPane(activity), BorderLayout.CENTER);
        return p;
    }

    private JPanel metric(String title, JLabel value) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        value.setFont(value.getFont().deriveFont(Font.BOLD, 24f));
        p.add(value, BorderLayout.CENTER);
        return p;
    }

    private JComponent testCases() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new EmptyBorder(12, 12, 12, 12));

        for (SecurityTest test : registry.all()) {
            JCheckBox check = new JCheckBox(test.name() + "  [" + test.category() + "]", test.isEnabled());
            check.addActionListener(e -> test.setEnabled(check.isSelected()));
            check.setAlignmentX(Component.LEFT_ALIGNMENT);
            check.setMaximumSize(new Dimension(Integer.MAX_VALUE, check.getPreferredSize().height));
            p.add(check);
            p.add(Box.createVerticalStrut(8));

            if (test instanceof HttpMethodsTest methods) {
                JPanel methodPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                methodPanel.setBorder(BorderFactory.createTitledBorder("HTTP methods to probe"));
                for (String method : List.of("OPTIONS", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT")) {
                    JCheckBox methodBox = new JCheckBox(method, methods.methods().contains(method));
                    methodBox.addActionListener(e -> methods.setMethodEnabled(method, methodBox.isSelected()));
                    if (HttpMethodsTest.isStateChanging(method)) {
                        methodBox.setToolTipText("Opt-in probe. May repeat the captured request body and cause state changes. Use only where safe and authorized.");
                    }
                    methodBox.setMaximumSize(methodBox.getPreferredSize());
                    methodPanel.add(methodBox);
                }
                methodPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                methodPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, methodPanel.getPreferredSize().height));
                p.add(methodPanel);
                p.add(Box.createVerticalStrut(14));
            }
        }
        return new JScrollPane(p);
    }

    private JComponent configuration() {
        JTabbedPane sections = new JTabbedPane();
        sections.addTab("Endpoint Exclusions", exclusions());
        sections.addTab("Ignored Extensions", ignoredExtensions());
        sections.addTab("Headers", sharedHeaderConfiguration());
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(sections, BorderLayout.CENTER);
        return wrapper;
    }

    private JComponent requestResponseViewer() {
        DefaultListModel<com.helpr.model.TrafficRecord> model = new DefaultListModel<>();
        JList<com.helpr.model.TrafficRecord> exchanges = new JList<>(model);
        exchanges.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        exchanges.setCellRenderer((list, item, index, selected, focus) -> {
            String label = item.method() + "  " + item.endpoint() + "  [" + item.timestamp() + "]";
            JLabel row = new JLabel(label);
            row.setOpaque(true);
            row.setBorder(new EmptyBorder(5, 7, 5, 7));
            if (selected) {
                row.setBackground(list.getSelectionBackground());
                row.setForeground(list.getSelectionForeground());
            } else {
                row.setBackground(list.getBackground());
                row.setForeground(list.getForeground());
            }
            return row;
        });

        JTextArea request = new JTextArea();
        JTextArea response = new JTextArea();
        request.setEditable(false);
        response.setEditable(false);
        request.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        response.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JTabbedPane evidence = new JTabbedPane();
        evidence.addTab("Request", new JScrollPane(request));
        evidence.addTab("Response", new JScrollPane(response));

        exchanges.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                com.helpr.model.TrafficRecord selected = exchanges.getSelectedValue();
                request.setText(selected == null ? "" : selected.request());
                response.setText(selected == null ? "" : selected.response());
                request.setCaretPosition(0);
                response.setCaretPosition(0);
            }
        });

        JButton refresh = new JButton("Refresh captured exchanges");
        refresh.addActionListener(e -> {
            int previous = exchanges.getSelectedIndex();
            model.clear();
            for (com.helpr.model.TrafficRecord record : engine.traffic()) model.addElement(record);
            if (!model.isEmpty()) exchanges.setSelectedIndex(Math.min(previous < 0 ? 0 : previous, model.size() - 1));
        });
        JPanel left = new JPanel(new BorderLayout(4, 4));
        left.add(new JLabel("Captured Proxy exchanges"), BorderLayout.NORTH);
        left.add(new JScrollPane(exchanges), BorderLayout.CENTER);
        left.add(refresh, BorderLayout.SOUTH);
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, evidence);
        split.setResizeWeight(0.34);
        JPanel panel = new JPanel(new BorderLayout(6, 6));
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));
        panel.add(new JLabel("Inspect original Proxy requests and responses captured by Helpr. This view is not included in the HTML report."), BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        refresh.doClick();
        return panel;
    }

    private JComponent sharedHeaderConfiguration() {
        JPanel wrapper = new JPanel(new GridLayout(1, 2, 10, 0));
        wrapper.setBorder(BorderFactory.createTitledBorder("Shared Header Inputs (used by applicable selected test cases)"));
        JPanel includePanel = new JPanel(new BorderLayout(4, 4));
        includePanel.setBorder(BorderFactory.createTitledBorder("Include Headers"));
        JTextArea include = new JTextArea(String.join("\n", config.includeHeaders()), 7, 30);
        include.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        includePanel.add(new JScrollPane(include), BorderLayout.CENTER);
        includePanel.add(new JLabel("One variant per line: Name: value. Each line sends a separate request."), BorderLayout.SOUTH);
        JPanel excludePanel = new JPanel(new BorderLayout(4, 4));
        excludePanel.setBorder(BorderFactory.createTitledBorder("Exclude Headers"));
        JTextArea exclude = new JTextArea(String.join("\n", config.authHeaders()), 7, 30);
        exclude.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        excludePanel.add(new JScrollPane(exclude), BorderLayout.CENTER);
        excludePanel.add(new JLabel("One header name per line. Used by Missing Authentication and applicable tests."), BorderLayout.SOUTH);
        wrapper.add(includePanel);
        wrapper.add(excludePanel);
        JButton save = new JButton("Save Shared Header Inputs");
        save.addActionListener(e -> {
            config.includeHeaders().clear();
            include.getText().lines().map(String::trim).filter(v -> !v.isEmpty()).forEach(config.includeHeaders()::add);
            config.authHeaders().clear();
            exclude.getText().lines().map(String::trim).filter(v -> !v.isEmpty()).forEach(config.authHeaders()::add);
            config.save();
            JOptionPane.showMessageDialog(this, "Shared header inputs saved. Applicable selected test cases will use these values when they execute.");
        });
        JPanel container = new JPanel(new BorderLayout(6, 6));
        container.add(wrapper, BorderLayout.CENTER);
        container.add(save, BorderLayout.SOUTH);
        return container;
    }

    private JComponent exclusions() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(new EmptyBorder(12, 12, 12, 12));
        p.add(new JLabel("One endpoint exclusion per line. Examples: /api/auth/* or /api/health. Burp Target Scope is checked separately."), BorderLayout.NORTH);
        JTextArea rules = new JTextArea(String.join("\n", config.excludedEndpoints()), 12, 60);
        rules.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        p.add(new JScrollPane(rules), BorderLayout.CENTER);
        JButton save = new JButton("Save Endpoint Exclusions");
        save.addActionListener(e -> {
            config.excludedEndpoints().clear();
            rules.getText().lines().map(String::trim).filter(s -> !s.isEmpty()).forEach(config.excludedEndpoints()::add);
            config.save();
            JOptionPane.showMessageDialog(this, "Endpoint exclusions saved. Matching requests will be skipped by all Helpr test modules.");
        });
        p.add(save, BorderLayout.SOUTH);
        return p;
    }

    private JComponent ignoredExtensions() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBorder(new EmptyBorder(12, 12, 12, 12));
        p.add(new JLabel("One file extension per line. Matching requests pass through Burp normally but are skipped by all Helpr test modules."), BorderLayout.NORTH);
        JTextArea extensions = new JTextArea(String.join("\n", config.ignoredExtensions()), 12, 60);
        extensions.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        p.add(new JScrollPane(extensions), BorderLayout.CENTER);
        JButton save = new JButton("Save Ignored Extensions");
        save.addActionListener(e -> {
            config.ignoredExtensions().clear();
            extensions.getText().lines().map(String::trim).filter(s -> !s.isEmpty()).forEach(config.ignoredExtensions()::add);
            config.save();
            JOptionPane.showMessageDialog(this, "Ignored extensions saved. Matching requests will be skipped by all Helpr test modules.");
        });
        p.add(save, BorderLayout.SOUTH);
        return p;
    }

    private void generateReport() {
        JCheckBox includeDuplicates = new JCheckBox(
                "Generate all results (include repeated test executions)", false);
        JLabel explanation = new JLabel("By default, the report includes one result per endpoint and test check. Enable this to include every execution and its evidence.");
        explanation.setFont(explanation.getFont().deriveFont(11f));
        JPanel options = new JPanel(new BorderLayout(6, 6));
        options.add(includeDuplicates, BorderLayout.NORTH);
        options.add(explanation, BorderLayout.CENTER);

        int option = JOptionPane.showConfirmDialog(this, options, "Helpr HTML Report Options",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (option != JOptionPane.OK_OPTION) return;

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Helpr HTML report");
        chooser.setSelectedFile(new java.io.File("helpr-report.html"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        try {
            new HtmlReportGenerator().write(Path.of(chooser.getSelectedFile().toURI()),
                    engine.traffic(), engine.results(), includeDuplicates.isSelected());
            JOptionPane.showMessageDialog(this, "HTML report generated successfully.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Report generation failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void onStatus(String message) {
        SwingUtilities.invokeLater(() -> {
            activity.append("[" + java.time.LocalTime.now().withNano(0) + "] " + message + "\n");
            if (activity.getLineCount() > 1000) {
                try { activity.replaceRange("", 0, activity.getLineEndOffset(100)); }
                catch (Exception ignored) { }
            }
            refreshCounts();
        });
    }

    private void refreshCounts() {
        trafficCount.setText(String.valueOf(engine.traffic().size()));
        testCount.setText(String.valueOf(engine.results().size()));
        trueCount.setText(String.valueOf(engine.results().stream().filter(r -> r.status() == TestStatus.TRUE).count()));
        falseCount.setText(String.valueOf(engine.results().stream().filter(r -> r.status() == TestStatus.FALSE).count()));
        undeterminedCount.setText(String.valueOf(engine.results().stream().filter(r -> r.status() == TestStatus.UNDETERMINED).count()));
    }
}
