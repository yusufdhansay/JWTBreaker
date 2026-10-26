package com.jwtbreaker;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;

/**
 * JWTBreaker - Burp Suite extension for inspecting and attacking JSON Web Tokens.
 *
 * Phase 1: basic skeleton. Registers the extension, logs a load message and
 * adds a "JWTBreaker" suite tab with a placeholder label.
 */
public class JwtBreakerExtension implements BurpExtension, ExtensionUnloadingHandler {

    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("JWTBreaker");
        api.extension().registerUnloadingHandler(this);

        JPanel panel = new JPanel(new BorderLayout());
        JLabel label = new JLabel("JWTBreaker Loaded", SwingConstants.CENTER);
        panel.add(label, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("JWTBreaker", panel);

        api.logging().logToOutput("JWTBreaker Loaded");
    }

    @Override
    public void extensionUnloaded() {
        if (api != null) {
            api.logging().logToOutput("JWTBreaker unloaded");
        }
    }
}
