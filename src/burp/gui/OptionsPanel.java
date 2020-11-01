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
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 *
 * @author moloch
 */
public class OptionsPanel extends javax.swing.JPanel {

    private final Multiplayer multiplayer;
    private final IBurpExtenderCallbacks callbacks;
    private final MultiplayerLogger logger;
    
    private static final String TRUE = "1"; // String booleans
    private static final String FALSE = "0";
    
    private static final Integer KiB = 1024;
    private static final Integer MiB = 1048576;
    
    /**
     * Creates new form Options
     * @param multiplayer
     * @param logger
     */
    public OptionsPanel(Multiplayer multiplayer, MultiplayerLogger logger) {
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
            if (TRUE.equals(theImplication)) {
                multiplayer.setSendToImpliesInProgress(true);
                sendToInProgressCheckBox.setSelected(true);
            } else {
                multiplayer.setSendToImpliesInProgress(false);
                sendToInProgressCheckBox.setSelected(false);
            }
        }
        
        String overwriteDuplicates = loadExtensionSetting("overwriteDuplicates");
        if (overwriteDuplicates != null) {
            if (TRUE.equals(overwriteDuplicates)) {
                multiplayer.setOverwriteDuplicates(true);
                overwriteDuplicatesCheckBox.setSelected(true);
            } else {
                multiplayer.setOverwriteDuplicates(false);
                overwriteDuplicatesCheckBox.setSelected(false);
            }
        }
        
        String uniqueQueryParameters = loadExtensionSetting("uniqueQueryParameters");
        if (uniqueQueryParameters != null) {
            if (TRUE.equals(uniqueQueryParameters)) {
                multiplayer.setUniqueQueryParameters(true);
                uniqueQueryParametersCheckBox.setSelected(true);
            } else {
                multiplayer.setUniqueQueryParameters(false);
                uniqueQueryParametersCheckBox.setSelected(false);
            }
        }
        
        loadIgnoredFileExtensionList();
        loadIgnoredStatusCodesList();
        loadIgnoredURLPatternsList();
        loadIgnoredToolsList();
        
        String level = logger.getLevel();
        logger.debug("Init log level '%s'", level);
        logLevelComboBox.setSelectedItem(level);
    }

    private void saveExtensionSetting(String name, String value) {
        String key = String.format("multiplayer.%s.%s", this.getClass().getName(), name);
        logger.debug("Save setting %s -> %s", key, value);
        callbacks.saveExtensionSetting(key, value);
    }
    
    private String loadExtensionSetting(String name) {
        String key = String.format("multiplayer.%s.%s", this.getClass().getName(), name);
        String value = callbacks.loadExtensionSetting(key);
        logger.debug("Load setting %s <- %s", key, value);
        return value;
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
    
    private void saveIgnoredURLPatternsList() {
        List<String> ignoredPatterns = multiplayer.getIgnoredURLPatternsList();
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String json = objectMapper.writeValueAsString(ignoredPatterns);
            saveExtensionSetting("ignoredURLPatterns", json);
        } catch (JsonProcessingException err) {
            logger.error(err);
        }
    }
    
    private void loadIgnoredURLPatternsList() {
        String json = loadExtensionSetting("ignoredURLPatterns");
        if (json != null && !json.isBlank() && !json.isEmpty()) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                List<String> ignoredURLPatterns = objectMapper.readValue(json, List.class);
                multiplayer.clearIgnoredURLPatterns();
                ignoredURLPatterns.forEach(rawPattern -> {
                    Pattern pattern = Pattern.compile(rawPattern, Pattern.CASE_INSENSITIVE);
                    multiplayer.addIgnoredURLPattern(pattern);
                });
            } catch (JsonProcessingException err) {
                logger.error(err);
            }
        }
    }
    
    private void saveIgnoredToolsList() {
        List<Integer> ignoredTools = multiplayer.getIgnoredToolsList();
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            String json = objectMapper.writeValueAsString(ignoredTools);
            saveExtensionSetting("ignoredTools", json);
        } catch (JsonProcessingException err) {
            logger.error(err);
        }
    }
    
    private void loadIgnoredToolsList() {
        String json = loadExtensionSetting("ignoredTools");
        if (json != null && !json.isBlank() && !json.isEmpty()) {
            ObjectMapper objectMapper = new ObjectMapper();
            try {
                List<Integer> ignoredTools = objectMapper.readValue(json, List.class);
                
                multiplayer.clearIgnoredTools();
                ignoreScannerCheckBox.setSelected(false);
                ignoreSpiderCheckBox.setSelected(false);
                ignoreIntruderCheckBox.setSelected(false);
                ignoreRepeaterCheckBox.setSelected(false);
                ignoreDecoderCheckBox.setSelected(false);
                ignoreComparerCheckBox.setSelected(false);
                ignoreExtenderCheckBox.setSelected(false);
                ignoreSequencerCheckBox.setSelected(false);
                
                ignoredTools.forEach(toolFlag -> {
                    multiplayer.addIgnoredTool(toolFlag);
                    switch(toolFlag) {
                        case IBurpExtenderCallbacks.TOOL_SCANNER:
                            ignoreScannerCheckBox.setSelected(true);
                            break;
                        case IBurpExtenderCallbacks.TOOL_SPIDER:
                            ignoreSpiderCheckBox.setSelected(true);
                            break;
                        case IBurpExtenderCallbacks.TOOL_INTRUDER:
                            ignoreIntruderCheckBox.setSelected(true);
                            break;
                        case IBurpExtenderCallbacks.TOOL_REPEATER:
                            ignoreRepeaterCheckBox.setSelected(true);
                            break;
                        case IBurpExtenderCallbacks.TOOL_EXTENDER:
                            ignoreExtenderCheckBox.setSelected(true);
                            break;
                        case IBurpExtenderCallbacks.TOOL_SEQUENCER:
                            ignoreSequencerCheckBox.setSelected(true);
                            break;
                        case IBurpExtenderCallbacks.TOOL_DECODER:
                            ignoreDecoderCheckBox.setSelected(true);
                        case IBurpExtenderCallbacks.TOOL_COMPARER:
                            ignoreComparerCheckBox.setSelected(true);
                    }
                });
                saveIgnoredToolsList();
            } catch (JsonProcessingException err) {
                logger.error(err);
            }
        }
    }
    
    // https://stackoverflow.com/questions/3758606/how-can-i-convert-byte-size-into-a-human-readable-format-in-java
    private String humanReadableByteCount(long bytes) {
        long absB = bytes == Long.MIN_VALUE ? Long.MAX_VALUE : Math.abs(bytes);
        if (absB < 1024) {
            return bytes + " B";
        }
        long value = absB;
        CharacterIterator ci = new StringCharacterIterator("KMGTPE");
        for (int i = 40; i >= 0 && absB > 0xfffccccccccccccL >> i; i -= 10) {
            value >>= 10;
            ci.next();
        }
        value *= Long.signum(bytes);
        return String.format("%.1f %ciB", value / 1024.0, ci.current());
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
        uniqueQueryParametersCheckBox = new javax.swing.JCheckBox();
        jLabel2 = new javax.swing.JLabel();
        ignoreSpiderCheckBox = new javax.swing.JCheckBox();
        ignoreIntruderCheckBox = new javax.swing.JCheckBox();
        ignoreRepeaterCheckBox = new javax.swing.JCheckBox();
        ignoreSequencerCheckBox = new javax.swing.JCheckBox();
        ignoreDecoderCheckBox = new javax.swing.JCheckBox();
        ignoreComparerCheckBox = new javax.swing.JCheckBox();
        ignoreExtenderCheckBox = new javax.swing.JCheckBox();
        jSeparator2 = new javax.swing.JSeparator();
        jLabel3 = new javax.swing.JLabel();
        maxRequestLabel = new javax.swing.JLabel();
        maxRequestSpinner = new javax.swing.JSpinner();
        maxResponseLabel = new javax.swing.JLabel();
        maxResponseSpinner = new javax.swing.JSpinner();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        jButton5 = new javax.swing.JButton();
        jButton6 = new javax.swing.JButton();
        jButton7 = new javax.swing.JButton();
        jButton8 = new javax.swing.JButton();

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
        ignoreScannerCheckBox.setText("Scanner");
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

        overwriteDuplicatesCheckBox.setText("Overwrite Duplicates");
        overwriteDuplicatesCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                overwriteDuplicatesCheckBoxActionPerformed(evt);
            }
        });

        uniqueQueryParametersCheckBox.setText("Include Query Parameters in Uniqueness");
        uniqueQueryParametersCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                uniqueQueryParametersCheckBoxActionPerformed(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        jLabel2.setText("Ignore Tools");

        ignoreSpiderCheckBox.setText("Spider");
        ignoreSpiderCheckBox.setToolTipText("");
        ignoreSpiderCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreSpiderCheckBoxActionPerformed(evt);
            }
        });

        ignoreIntruderCheckBox.setSelected(true);
        ignoreIntruderCheckBox.setText("Intruder");
        ignoreIntruderCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreIntruderCheckBoxActionPerformed(evt);
            }
        });

        ignoreRepeaterCheckBox.setSelected(true);
        ignoreRepeaterCheckBox.setText("Repeater");
        ignoreRepeaterCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreRepeaterCheckBoxActionPerformed(evt);
            }
        });

        ignoreSequencerCheckBox.setSelected(true);
        ignoreSequencerCheckBox.setText("Sequencer");
        ignoreSequencerCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreSequencerCheckBoxActionPerformed(evt);
            }
        });

        ignoreDecoderCheckBox.setSelected(true);
        ignoreDecoderCheckBox.setText("Decoder");
        ignoreDecoderCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreDecoderCheckBoxActionPerformed(evt);
            }
        });

        ignoreComparerCheckBox.setSelected(true);
        ignoreComparerCheckBox.setText("Comparer");
        ignoreComparerCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreComparerCheckBoxActionPerformed(evt);
            }
        });

        ignoreExtenderCheckBox.setSelected(true);
        ignoreExtenderCheckBox.setText("Extender");
        ignoreExtenderCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ignoreExtenderCheckBoxActionPerformed(evt);
            }
        });

        jSeparator2.setOrientation(javax.swing.SwingConstants.VERTICAL);

        jLabel3.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        jLabel3.setText("Limit Request/Response Size");

        maxRequestLabel.setText("Max Request Size");

        maxRequestSpinner.setModel(multiplayer.getMaxRequestSizeModel());

        maxResponseLabel.setText("Max Response Size");

        maxResponseSpinner.setModel(multiplayer.getMaxResponseSizeModel());

        jButton1.setText("+1KiB");

        jButton2.setText("+1MiB");

        jButton3.setText("-1Kb");
        jButton3.setActionCommand("-1KiB");

        jButton4.setText("-1MiB");

        jButton5.setText("+1KiB");

        jButton6.setText("+1MiB");

        jButton7.setText("-1KiB");

        jButton8.setText("-1MiB");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(removeIgnoreStatusCodeButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(addIgnoreStatusCodeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(ignoreStatusCodesLabel)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 148, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(32, 32, 32)
                        .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(removeIgnoreURLPatternButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(addIgnoreURLPatternButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addComponent(uniqueQueryParametersCheckBox)
                    .addComponent(sendToInProgressCheckBox)
                    .addComponent(overwriteDuplicatesCheckBox)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(removeIgnoreFileExtensionButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(addIgnoreFileExtensionButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(ignoreFileExtensionLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)))
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                            .addComponent(otherOptionsLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 211, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGap(65, 65, 65)))
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(loggingLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 88, Short.MAX_VALUE)
                        .addComponent(logLevelComboBox, javax.swing.GroupLayout.Alignment.LEADING, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel1))
                        .addGap(32, 32, 32)
                        .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(disconnectButton))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(maxRequestLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(maxRequestSpinner)
                                    .addComponent(maxResponseLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(maxResponseSpinner))
                                .addGap(6, 6, 6)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jButton6)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton5)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton7)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton8))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jButton2)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton3)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButton4)))
                                .addGap(0, 278, Short.MAX_VALUE))))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(ignoreRepeaterCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(ignoreScannerCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(ignoreIntruderCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(ignoreSpiderCheckBox, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(ignoreSequencerCheckBox)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                        .addComponent(ignoreDecoderCheckBox, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(ignoreComparerCheckBox, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(ignoreExtenderCheckBox, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))))
                        .addGap(0, 0, Short.MAX_VALUE)))
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
                            .addComponent(jLabel1)
                            .addComponent(jLabel3))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
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
                                .addComponent(jScrollPane3))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(maxRequestLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(maxRequestSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jButton2)
                                    .addComponent(jButton3)
                                    .addComponent(jButton4)
                                    .addComponent(jButton1))
                                .addGap(24, 24, 24)
                                .addComponent(maxResponseLabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(maxResponseSpinner, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(jButton6)
                                    .addComponent(jButton7)
                                    .addComponent(jButton8)
                                    .addComponent(jButton5)))))
                    .addComponent(jSeparator1)
                    .addComponent(jSeparator2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 12, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(ignoreSpiderCheckBox)
                            .addComponent(ignoreDecoderCheckBox))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(ignoreScannerCheckBox, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(ignoreComparerCheckBox))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(ignoreIntruderCheckBox)
                            .addComponent(ignoreExtenderCheckBox))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(ignoreRepeaterCheckBox)
                            .addComponent(ignoreSequencerCheckBox)))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(otherOptionsLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(sendToInProgressCheckBox)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(overwriteDuplicatesCheckBox)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(uniqueQueryParametersCheckBox)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(loggingLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(logLevelComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(315, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void addIgnoreFileExtensionButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addIgnoreFileExtensionButtonActionPerformed
        String fileExt = JOptionPane.showInputDialog(null, "Add file extension:", "File Extension", JOptionPane.QUESTION_MESSAGE);
        multiplayer.addIgnoredExtension(fileExt);
        saveIgnoredFileExtensionList();
    }//GEN-LAST:event_addIgnoreFileExtensionButtonActionPerformed

    private void addIgnoreStatusCodeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addIgnoreStatusCodeButtonActionPerformed
        String status = JOptionPane.showInputDialog(null, "Add status code:", "Status Code", JOptionPane.QUESTION_MESSAGE);
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
        if (ignoreScannerCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_SCANNER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_SCANNER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreScannerCheckBoxActionPerformed

    private void disconnectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disconnectButtonActionPerformed
        multiplayer.disconnect();
    }//GEN-LAST:event_disconnectButtonActionPerformed

    private void sendToInProgressCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendToInProgressCheckBoxActionPerformed
        multiplayer.setSendToImpliesInProgress(sendToInProgressCheckBox.isSelected());
        String theImplication = sendToInProgressCheckBox.isSelected() ? TRUE : FALSE;
        saveExtensionSetting("sendToImpliesInProgress", theImplication);
    }//GEN-LAST:event_sendToInProgressCheckBoxActionPerformed

    private void logLevelComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logLevelComboBoxActionPerformed
        String level = (String) logLevelComboBox.getSelectedItem();
        logger.setLevel(level);
        callbacks.saveExtensionSetting("multiplayer.logLevel", level);
    }//GEN-LAST:event_logLevelComboBoxActionPerformed

    private void addIgnoreURLPatternButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addIgnoreURLPatternButtonActionPerformed
        String rawPattern = JOptionPane.showInputDialog(null, "Add URL pattern:", "URL Pattern", JOptionPane.QUESTION_MESSAGE);
        try {
            Pattern pattern = Pattern.compile(rawPattern, Pattern.CASE_INSENSITIVE);
            multiplayer.addIgnoredURLPattern(pattern);
            saveIgnoredURLPatternsList();
        } catch (PatternSyntaxException err) {
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
        saveIgnoredURLPatternsList();
    }//GEN-LAST:event_removeIgnoreURLPatternButtonActionPerformed

    private void uniqueQueryParametersCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_uniqueQueryParametersCheckBoxActionPerformed
        multiplayer.setUniqueQueryParameters(uniqueQueryParametersCheckBox.isSelected());
        String uniqueQueryParameters = uniqueQueryParametersCheckBox.isSelected() ? TRUE : FALSE;
        saveExtensionSetting("uniqueQueryParameters", uniqueQueryParameters);
    }//GEN-LAST:event_uniqueQueryParametersCheckBoxActionPerformed

    private void overwriteDuplicatesCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_overwriteDuplicatesCheckBoxActionPerformed
        multiplayer.setOverwriteDuplicates(overwriteDuplicatesCheckBox.isSelected());
        String overwrite = overwriteDuplicatesCheckBox.isSelected() ? TRUE : FALSE;
        saveExtensionSetting("overwriteDuplicates", overwrite);
    }//GEN-LAST:event_overwriteDuplicatesCheckBoxActionPerformed

    private void ignoreSpiderCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreSpiderCheckBoxActionPerformed
        if (ignoreSpiderCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_SPIDER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_SPIDER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreSpiderCheckBoxActionPerformed

    private void ignoreIntruderCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreIntruderCheckBoxActionPerformed
        if (ignoreIntruderCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_INTRUDER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_INTRUDER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreIntruderCheckBoxActionPerformed

    private void ignoreRepeaterCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreRepeaterCheckBoxActionPerformed
        if (ignoreRepeaterCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_REPEATER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_REPEATER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreRepeaterCheckBoxActionPerformed

    private void ignoreDecoderCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreDecoderCheckBoxActionPerformed
        if (ignoreDecoderCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_DECODER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_DECODER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreDecoderCheckBoxActionPerformed

    private void ignoreComparerCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreComparerCheckBoxActionPerformed
        if (ignoreComparerCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_COMPARER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_COMPARER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreComparerCheckBoxActionPerformed

    private void ignoreExtenderCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreExtenderCheckBoxActionPerformed
        if (ignoreExtenderCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_EXTENDER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_EXTENDER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreExtenderCheckBoxActionPerformed

    private void ignoreSequencerCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ignoreSequencerCheckBoxActionPerformed
        if (ignoreSequencerCheckBox.isSelected()) {
            multiplayer.addIgnoredTool(IBurpExtenderCallbacks.TOOL_SEQUENCER);   
        } else {
            multiplayer.removeIgnoredTool(IBurpExtenderCallbacks.TOOL_SEQUENCER);
        }
        saveIgnoredToolsList();
    }//GEN-LAST:event_ignoreSequencerCheckBoxActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addIgnoreFileExtensionButton;
    private javax.swing.JButton addIgnoreStatusCodeButton;
    private javax.swing.JButton addIgnoreURLPatternButton;
    private javax.swing.JButton disconnectButton;
    private javax.swing.JCheckBox ignoreComparerCheckBox;
    private javax.swing.JCheckBox ignoreDecoderCheckBox;
    private javax.swing.JCheckBox ignoreExtenderCheckBox;
    private javax.swing.JLabel ignoreFileExtensionLabel;
    private javax.swing.JCheckBox ignoreIntruderCheckBox;
    private javax.swing.JCheckBox ignoreRepeaterCheckBox;
    private javax.swing.JCheckBox ignoreScannerCheckBox;
    private javax.swing.JCheckBox ignoreSequencerCheckBox;
    private javax.swing.JCheckBox ignoreSpiderCheckBox;
    private javax.swing.JLabel ignoreStatusCodesLabel;
    private javax.swing.JList<Pattern> ignoreURLPatternJList;
    private javax.swing.JList<String> ignoredFileExtensionJList;
    private javax.swing.JList<String> ignoredStatusCodesJList;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JButton jButton5;
    private javax.swing.JButton jButton6;
    private javax.swing.JButton jButton7;
    private javax.swing.JButton jButton8;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JComboBox<String> logLevelComboBox;
    private javax.swing.JLabel loggingLabel;
    private javax.swing.JLabel maxRequestLabel;
    private javax.swing.JSpinner maxRequestSpinner;
    private javax.swing.JLabel maxResponseLabel;
    private javax.swing.JSpinner maxResponseSpinner;
    private javax.swing.JLabel otherOptionsLabel;
    private javax.swing.JCheckBox overwriteDuplicatesCheckBox;
    private javax.swing.JButton removeIgnoreFileExtensionButton;
    private javax.swing.JButton removeIgnoreStatusCodeButton;
    private javax.swing.JButton removeIgnoreURLPatternButton;
    private javax.swing.JCheckBox sendToInProgressCheckBox;
    private javax.swing.JCheckBox uniqueQueryParametersCheckBox;
    // End of variables declaration//GEN-END:variables
}
