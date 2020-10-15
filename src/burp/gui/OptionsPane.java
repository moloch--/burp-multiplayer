/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.gui;

import burp.IBurpExtenderCallbacks;
import burp.Multiplayer;
import burp.MultiplayerLogger;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.List;
import javax.swing.JOptionPane;
import com.fasterxml.jackson.databind.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 *
 * @author moloch
 */
public class OptionsPane extends javax.swing.JPanel {

    private final Multiplayer multiplayer;
    private final IBurpExtenderCallbacks callbacks;
    private final MultiplayerLogger logger;
    
    /**
     * Creates new form Options
     * @param multiplayer
     * @param logger
     */
    public OptionsPane(Multiplayer multiplayer, MultiplayerLogger logger) {
        logger.debug("Initializing options panel");
        this.multiplayer = multiplayer;
        this.callbacks = logger.callbacks;
        this.logger = logger;
        initComponents();
        initLoadSettings();
    }
    
    private void initLoadSettings() {
        String theImplication = loadExtensionSetting("sendToImpliesInProgress");
        if (theImplication != null) {
            if ("1".equals(theImplication)) {
                multiplayer.setSendToImpliesInProgress(true);
                sendToInProgressCheckBox.setSelected(true);
            } else {
                multiplayer.setSendToImpliesInProgress(false);
                sendToInProgressCheckBox.setSelected(false);
            }
        }
        
        String ignoreScanner = loadExtensionSetting("ignoreScanner");
        if (ignoreScanner != null) {
            if ("1".equals(ignoreScanner)) {
                multiplayer.setIgnoreScanner(true);
                ignoreScannerCheckBox.setSelected(true);
            } else {
                multiplayer.setIgnoreScanner(false);
                ignoreScannerCheckBox.setSelected(false);
            }
        }
        
        loadIgnoredFileExtensionList();
        loadIgnoredStatusCodesList();
        
        String level = logger.getLevel();
        logger.debug("Init log level '%s'", level);
        logLevelComboBox.setSelectedItem(level);
    }

    private void saveExtensionSetting(String name, String value) {
        String key = String.format("multiplayer.%s.%s", this.getClass().getName(), name);
        callbacks.saveExtensionSetting(key, value);
    }
    
    private String loadExtensionSetting(String name) {
        String key = String.format("multiplayer.%s.%s", this.getClass().getName(), name);
        return callbacks.loadExtensionSetting(key);
    }
    
    private void saveIgnoredFileExtensionList() {
        List<String> ignoredFileExts = multiplayer.getIgnoredFileExtensionsList();
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String json = objectMapper.writeValueAsString(ignoredFileExts);
            saveExtensionSetting("ignoredFileExtensions", json);
        } catch (JsonProcessingException err) {
            logger.error(err);
        }
    }
    
    private void loadIgnoredFileExtensionList() {
        String json = loadExtensionSetting("ignoredFileExtensions");
        if (json != null && !json.isBlank() && !json.isEmpty()) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                List<String> ignoredFileExts = objectMapper.readValue(json, List.class);
                multiplayer.clearIgnoredExtensions();
                ignoredFileExts.forEach(ext -> multiplayer.addIgnoredExtension(ext));
            } catch (JsonProcessingException err) {
                logger.error(err);
                saveExtensionSetting("ignoredFileExtensions", null);
            }
        }
    }

    private void saveIgnoredStatusCodesList() {
        List<String> ignoredStatusCodes = multiplayer.getIgnoredStatusCodesList();
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String json = objectMapper.writeValueAsString(ignoredStatusCodes);
            saveExtensionSetting("ignoredStatusCodes", json);
        } catch (JsonProcessingException err) {
            logger.error(err);
        }
    }
    
    private void loadIgnoredStatusCodesList() {
        String json = loadExtensionSetting("ignoredStatusCodes");
        if (json != null && !json.isBlank() && !json.isEmpty()) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                List<String> ignoredFileExts = objectMapper.readValue(json, List.class);
                multiplayer.clearIgnoredStatusCodes();
                ignoredFileExts.forEach(code -> multiplayer.addIgnoredStatusCodes(code));
            } catch (JsonProcessingException err) {
                logger.error(err);
                saveExtensionSetting("ignoredStatusCodes", null);
            }
        }
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        ignoreFileExtensionLabel = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        ignoredFileExtensionJList = new javax.swing.JList<>();
        jScrollPane2 = new javax.swing.JScrollPane();
        ignoredStatusCodesJList = new javax.swing.JList<>();
        ignoreStatusCodesLabel = new javax.swing.JLabel();
        addIgnoreFileExtensionButton = new javax.swing.JButton();
        removeIgnoreFileExtensionButton = new javax.swing.JButton();
        addIgnoreStatusCodeButton = new javax.swing.JButton();
        removeIgnoreStatusCodeButton = new javax.swing.JButton();
        otherOptionsLabel = new javax.swing.JLabel();
        ignoreScannerCheckBox = new javax.swing.JCheckBox();
        disconnectButton = new javax.swing.JButton();
        sendToInProgressCheckBox = new javax.swing.JCheckBox();
        logLevelComboBox = new javax.swing.JComboBox<>();
        loggingLabel = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        addIgnoreURLPatternButton = new javax.swing.JButton();
        removeIgnoreURLPatternButton = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        ignoreURLPatternJList = new javax.swing.JList<>();
        jLabel1 = new javax.swing.JLabel();
        overwriteDuplicatesCheckBox = new javax.swing.JCheckBox();
        includeQueryParametersCheckBox = new javax.swing.JCheckBox();

        ignoreFileExtensionLabel.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        ignoreFileExtensionLabel.setText("Ignore File Extensions");

        ignoredFileExtensionJList.setModel(multiplayer.getIgnoreExtensions()
        );
        jScrollPane1.setViewportView(ignoredFileExtensionJList);

        ignoredStatusCodesJList.setModel(multiplayer.getIgnoredStatusCodes()
        );
        jScrollPane2.setViewportView(ignoredStatusCodesJList);

        ignoreStatusCodesLabel.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        ignoreStatusCodesLabel.setText("Ignore Status Codes");

        addIgnoreFileExtensionButton.setText("Add");
        addIgnoreFileExtensionButton.setToolTipText("");
        addIgnoreFileExtensionButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addIgnoreFileExtensionButtonActionPerformed(evt);
            }
        });

        removeIgnoreFileExtensionButton.setText("Remove");
        removeIgnoreFileExtensionButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeIgnoreFileExtensionButtonActionPerformed(evt);
            }
        });

        addIgnoreStatusCodeButton.setText("Add");
        addIgnoreStatusCodeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addIgnoreStatusCodeButtonActionPerformed(evt);
            }
        });

        removeIgnoreStatusCodeButton.setText("Remove");
        removeIgnoreStatusCodeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeIgnoreStatusCodeButtonActionPerformed(evt);
            }
        });

        otherOptionsLabel.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        otherOptionsLabel.setText("Other Options");

        ignoreScannerCheckBox.setSelected(true);
        ignoreScannerCheckBox.setText("Ignore Scanner Requests");
        ignoreScannerCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreScannerCheckBoxActionPerformed(evt);
            }
        });

        disconnectButton.setText("Disconnect");
        disconnectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disconnectButtonActionPerformed(evt);
            }
        });

        sendToInProgressCheckBox.setSelected(true);
        sendToInProgressCheckBox.setText("Send To Implies In Progress");
        sendToInProgressCheckBox.setToolTipText("");
        sendToInProgressCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendToInProgressCheckBoxActionPerformed(evt);
            }
        });

        logLevelComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] {
            logger.DEBUG, logger.INFO, logger.WARN, logger.ERROR
        }));
        logLevelComboBox.setSelectedItem(logger.INFO);
        logLevelComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logLevelComboBoxActionPerformed(evt);
            }
        });

        loggingLabel.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        loggingLabel.setText("Log Level");

        jSeparator1.setOrientation(javax.swing.SwingConstants.VERTICAL);

        addIgnoreURLPatternButton.setText("Add");
        addIgnoreURLPatternButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addIgnoreURLPatternButtonActionPerformed(evt);
            }
        });

        removeIgnoreURLPatternButton.setText("Remove");
        removeIgnoreURLPatternButton.setToolTipText("");
        removeIgnoreURLPatternButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeIgnoreURLPatternButtonActionPerformed(evt);
            }
        });

        ignoreURLPatternJList.setModel(multiplayer.getIgnoredURLPatterns());
        ignoreURLPatternJList.setToolTipText("");
        jScrollPane3.setViewportView(ignoreURLPatternJList);

        jLabel1.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        jLabel1.setText("Ignore URL Patterns");

        overwriteDuplicatesCheckBox.setText("Always Overwrite Duplicates");

        includeQueryParametersCheckBox.setText("Include Query Parameters in Unqiueness");
        includeQueryParametersCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                includeQueryParametersCheckBoxActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(removeIgnoreFileExtensionButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(addIgnoreFileExtensionButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(ignoreFileExtensionLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)))
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(ignoreScannerCheckBox)
                            .addComponent(otherOptionsLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 211, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(sendToInProgressCheckBox)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addComponent(logLevelComboBox, javax.swing.GroupLayout.Alignment.LEADING, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(loggingLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addComponent(overwriteDuplicatesCheckBox)
                            .addComponent(includeQueryParametersCheckBox)))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(removeIgnoreStatusCodeButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(addIgnoreStatusCodeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(ignoreStatusCodesLabel)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 148, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(32, 32, 32)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(removeIgnoreURLPatternButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(addIgnoreURLPatternButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 228, Short.MAX_VALUE)
                .addComponent(disconnectButton)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(ignoreFileExtensionLabel)
                            .addComponent(disconnectButton)
                            .addComponent(jLabel1))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(addIgnoreFileExtensionButton)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(removeIgnoreFileExtensionButton)))
                                .addGap(18, 18, 18)
                                .addComponent(ignoreStatusCodesLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(addIgnoreStatusCodeButton)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(removeIgnoreStatusCodeButton))
                                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(addIgnoreURLPatternButton)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(removeIgnoreURLPatternButton))
                            .addComponent(jScrollPane3)))
                    .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 322, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(otherOptionsLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(ignoreScannerCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(sendToInProgressCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(overwriteDuplicatesCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(includeQueryParametersCheckBox)
                .addGap(11, 11, 11)
                .addComponent(loggingLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(logLevelComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(119, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void addIgnoreFileExtensionButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addIgnoreFileExtensionButtonActionPerformed
        String fileExt = JOptionPane.showInputDialog("Add file extension:");
        multiplayer.addIgnoredExtension(fileExt);
        saveIgnoredFileExtensionList();
    }//GEN-LAST:event_addIgnoreFileExtensionButtonActionPerformed

    private void addIgnoreStatusCodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addIgnoreStatusCodeButtonActionPerformed
        String status = JOptionPane.showInputDialog("Add status code:");
        multiplayer.addIgnoredStatusCodes(status);
        saveIgnoredStatusCodesList();
    }//GEN-LAST:event_addIgnoreStatusCodeButtonActionPerformed

    private void removeIgnoreFileExtensionButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeIgnoreFileExtensionButtonActionPerformed
        List<String> selectedValues = ignoredFileExtensionJList.getSelectedValuesList();
        selectedValues.forEach(ext -> {
            multiplayer.removeIgnoredExtension(ext);
        });
        saveIgnoredFileExtensionList();
    }//GEN-LAST:event_removeIgnoreFileExtensionButtonActionPerformed

    private void removeIgnoreStatusCodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeIgnoreStatusCodeButtonActionPerformed
        List<String> selectedValues = ignoredStatusCodesJList.getSelectedValuesList();
        selectedValues.forEach(code -> {
            multiplayer.removeIgnoredStatusCodes(code);
        });
        saveIgnoredStatusCodesList();
    }//GEN-LAST:event_removeIgnoreStatusCodeButtonActionPerformed

    private void ignoreScannerCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreScannerCheckBoxActionPerformed
        multiplayer.setIgnoreScanner(ignoreScannerCheckBox.isSelected());
        String ignoreScanner = ignoreScannerCheckBox.isSelected() ? "1" : "0";
        saveExtensionSetting("ignoreScanner", ignoreScanner);
    }//GEN-LAST:event_ignoreScannerCheckBoxActionPerformed

    private void disconnectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disconnectButtonActionPerformed
        multiplayer.disconnect();
    }//GEN-LAST:event_disconnectButtonActionPerformed

    private void sendToInProgressCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendToInProgressCheckBoxActionPerformed
        multiplayer.setSendToImpliesInProgress(sendToInProgressCheckBox.isSelected());
        String theImplication = sendToInProgressCheckBox.isSelected() ? "1" : "0";
        saveExtensionSetting("sendToImpliesInProgress", theImplication);
    }//GEN-LAST:event_sendToInProgressCheckBoxActionPerformed

    private void logLevelComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logLevelComboBoxActionPerformed
        String level = (String) logLevelComboBox.getSelectedItem();
        logger.setLevel(level);
        callbacks.saveExtensionSetting("multiplayer.logLevel", level);
    }//GEN-LAST:event_logLevelComboBoxActionPerformed

    private void addIgnoreURLPatternButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addIgnoreURLPatternButtonActionPerformed
        String rawPattern = JOptionPane.showInputDialog("Add URL pattern:");
        try {
            Pattern pattern = Pattern.compile(rawPattern, Pattern.CASE_INSENSITIVE);
            multiplayer.addIgnoredURLPattern(pattern);
        } catch (PatternSyntaxException err) {
            logger.error(err);
            JOptionPane.showMessageDialog(this, 
                err.getMessage(),
                "Pattern Syntax Error",
                JOptionPane.ERROR_MESSAGE);
        }

    }//GEN-LAST:event_addIgnoreURLPatternButtonActionPerformed

    private void removeIgnoreURLPatternButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removeIgnoreURLPatternButtonActionPerformed
        List<Pattern> selectedValues = ignoreURLPatternJList.getSelectedValuesList();
        selectedValues.forEach(pattern -> {
            multiplayer.removeIgnoredURLPattern(pattern);
        });
    }//GEN-LAST:event_removeIgnoreURLPatternButtonActionPerformed

    private void includeQueryParametersCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_includeQueryParametersCheckBoxActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_includeQueryParametersCheckBoxActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addIgnoreFileExtensionButton;
    private javax.swing.JButton addIgnoreStatusCodeButton;
    private javax.swing.JButton addIgnoreURLPatternButton;
    private javax.swing.JButton disconnectButton;
    private javax.swing.JLabel ignoreFileExtensionLabel;
    private javax.swing.JCheckBox ignoreScannerCheckBox;
    private javax.swing.JLabel ignoreStatusCodesLabel;
    private javax.swing.JList<Pattern> ignoreURLPatternJList;
    private javax.swing.JList<String> ignoredFileExtensionJList;
    private javax.swing.JList<String> ignoredStatusCodesJList;
    private javax.swing.JCheckBox includeQueryParametersCheckBox;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JComboBox<String> logLevelComboBox;
    private javax.swing.JLabel loggingLabel;
    private javax.swing.JLabel otherOptionsLabel;
    private javax.swing.JCheckBox overwriteDuplicatesCheckBox;
    private javax.swing.JButton removeIgnoreFileExtensionButton;
    private javax.swing.JButton removeIgnoreStatusCodeButton;
    private javax.swing.JButton removeIgnoreURLPatternButton;
    private javax.swing.JCheckBox sendToInProgressCheckBox;
    // End of variables declaration//GEN-END:variables
}
