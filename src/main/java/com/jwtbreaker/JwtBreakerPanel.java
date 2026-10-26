package com.jwtbreaker;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

import burp.api.montoya.MontoyaApi;

/**
 * Main UI for the JWTBreaker tab.
 *
 * Top: a table of detected JWTs. Bottom: the decoded header and payload of the
 * selected token.
 */
public class JwtBreakerPanel extends JPanel {

    private final MontoyaApi api;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JTextArea decodedArea;
    private final List<JwtEntry> entries = new ArrayList<>();

    public JwtBreakerPanel(MontoyaApi api) {
        super(new BorderLayout());
        this.api = api;

        String[] columns = {"Host", "Method", "Path", "Source", "Token"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        table = new JTable(tableModel);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelected();
            }
        });

        decodedArea = new JTextArea();
        decodedArea.setEditable(false);
        decodedArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        decodedArea.setText("Select a request above to decode its JWT.");

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Detected JWTs"));

        JScrollPane decodedScroll = new JScrollPane(decodedArea);
        decodedScroll.setBorder(BorderFactory.createTitledBorder("Decoded JWT"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, decodedScroll);
        split.setResizeWeight(0.4);
        split.setDividerLocation(260);

        add(split, BorderLayout.CENTER);
    }

    /** Adds a detected JWT entry. Safe to call from any thread. */
    public void addEntry(JwtEntry entry) {
        SwingUtilities.invokeLater(() -> {
            // Skip exact duplicates (same token on same path).
            for (JwtEntry e : entries) {
                if (e.token().equals(entry.token()) && e.path().equals(entry.path())) {
                    return;
                }
            }
            entries.add(entry);
            String shortToken = entry.token().length() > 40
                    ? entry.token().substring(0, 40) + "..."
                    : entry.token();
            tableModel.addRow(new Object[]{
                    entry.host(), entry.method(), entry.path(), entry.source(), shortToken});

            // Auto-select the first row so something shows immediately.
            if (entries.size() == 1) {
                table.setRowSelectionInterval(0, 0);
            }
        });
    }

    private void showSelected() {
        JwtEntry entry = getSelectedEntry();
        if (entry == null) {
            return;
        }
        try {
            JwtUtils.DecodedJwt decoded = JwtUtils.decodeJwt(entry.token());
            StringBuilder sb = new StringBuilder();
            sb.append("=== RAW TOKEN ===\n").append(entry.token()).append("\n\n");
            sb.append("=== HEADER ===\n").append(decoded.headerPretty).append("\n\n");
            sb.append("=== PAYLOAD ===\n").append(decoded.payloadPretty).append("\n\n");
            sb.append("=== SIGNATURE (Base64Url) ===\n")
              .append(decoded.signature.isEmpty() ? "(empty)" : decoded.signature);
            decodedArea.setText(sb.toString());
            decodedArea.setCaretPosition(0);
        } catch (Exception ex) {
            decodedArea.setText("Failed to decode token: " + ex.getMessage());
        }
    }

    /** Returns the currently selected entry, or null. */
    public JwtEntry getSelectedEntry() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= entries.size()) {
            return null;
        }
        return entries.get(row);
    }
}
