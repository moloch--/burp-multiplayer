/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.gui;

import burp.IBurpExtenderCallbacks;
import burp.Multiplayer;
import burp.MultiplayerLogger;
import burp.version.MultiplayerSemanticVersion;
import burp.version.MultiplayerVersion;
import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import javax.swing.JOptionPane;

/**
 *
 * @author moloch
 */
public final class ConnectionPanel extends javax.swing.JPanel {

    private final Multiplayer multiplayer;
    private final List<Runnable> onConnectCallbacks = new ArrayList<>();
    private final IBurpExtenderCallbacks callbacks;
    private final MultiplayerLogger logger;
    
    private static final String helpURI = "https://github.com/moloch--/burp-multiplayer/wiki/RethinkDB-Setup";
    private static final String githubURI = "https://github.com/moloch--/burp-multiplayer";
    
    /**
     * Creates new form ConnectionPanel
     * @param multiplayer
     * @param logger
     */
    public ConnectionPanel(Multiplayer multiplayer, MultiplayerLogger logger) {
        this.callbacks = logger.callbacks;
        this.logger = logger;
        this.multiplayer = multiplayer;
        initComponents();
        initLoadSettings();
        initVersion();
    }
    
    private void initVersion() {
        String version = String.format("v%s - %s - %s", 
                MultiplayerVersion.VERSION,
                MultiplayerVersion.BUILD_DATE,
                MultiplayerVersion.GIT_SHA);
        
        if (MultiplayerVersion.DIRTY == 1) {
            version = String.format("%s - DIRTY", version);
        }
        logger.info(version);
        versionLabel.setText(version);
    }
    
    public void initLoadSettings() {
        String hostname = loadExtensionSetting("hostname");
        if (hostname != null) {
            hostnameTextField.setText(hostname);
        }
        String port = loadExtensionSetting("port");
        if (port != null) {
            try {
                Integer.parseInt(port);
                portNumberTextField.setText(port);
            } catch (NumberFormatException e) {}
        }
    }
    
    public void onConnection(Runnable callback) {
        onConnectCallbacks.add(callback);
    }
    
    private void triggerOnConnection() {
        onConnectCallbacks.forEach(callback -> {
            callback.run();
        });
    }
    
    private void saveExtensionSetting(String name, String value) {
        String key = String.format("multiplayer.%s.%s", this.getClass().getName(), name);
        callbacks.saveExtensionSetting(key, value);
    }
    
    private String loadExtensionSetting(String name) {
        String key = String.format("multiplayer.%s.%s", this.getClass().getName(), name);
        return callbacks.loadExtensionSetting(key);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        hoastnameLabel = new javax.swing.JLabel();
        hostnameTextField = new javax.swing.JTextField();
        portNumberLabel = new javax.swing.JLabel();
        portNumberTextField = new javax.swing.JTextField();
        titleLabel = new javax.swing.JLabel();
        connectButton = new javax.swing.JButton();
        saveSettingsCheckBox = new javax.swing.JCheckBox();
        setupHelpButton = new javax.swing.JButton();
        githubButton = new javax.swing.JButton();
        versionLabel = new javax.swing.JLabel();

        hoastnameLabel.setText("Hostname");

        hostnameTextField.setColumns(10);
        hostnameTextField.setText("localhost");
        hostnameTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                hostnameTextFieldActionPerformed(evt);
            }
        });

        portNumberLabel.setText("Port Number");

        portNumberTextField.setColumns(10);
        portNumberTextField.setText("28015");

        titleLabel.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        titleLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        titleLabel.setText("RethinkDB Connection");

        connectButton.setText("Connect");
        connectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectButtonActionPerformed(evt);
            }
        });

        saveSettingsCheckBox.setSelected(true);
        saveSettingsCheckBox.setText("Save Connection Settings");
        saveSettingsCheckBox.setToolTipText("");
        saveSettingsCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveSettingsCheckBoxActionPerformed(evt);
            }
        });

        setupHelpButton.setText("Setup Help");
        setupHelpButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                setupHelpButtonActionPerformed(evt);
            }
        });

        githubButton.setLabel("GitHub");
        githubButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                githubButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(setupHelpButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(githubButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(0, 394, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(saveSettingsCheckBox)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(titleLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 223, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(connectButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                            .addComponent(portNumberLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(hoastnameLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(10, 10, 10)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(hostnameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(portNumberTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))))))
                        .addGap(0, 394, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(versionLabel)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(9, 9, 9)
                .addComponent(setupHelpButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(githubButton)
                .addGap(122, 122, 122)
                .addComponent(titleLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 16, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(hostnameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(hoastnameLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(portNumberLabel)
                    .addComponent(portNumberTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(saveSettingsCheckBox)
                .addGap(11, 11, 11)
                .addComponent(connectButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 317, Short.MAX_VALUE)
                .addComponent(versionLabel)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void hostnameTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hostnameTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_hostnameTextFieldActionPerformed

    private void connectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectButtonActionPerformed

        connectButton.setEnabled(false);
        
        String hostname = hostnameTextField.getText();
        Integer port = Integer.parseInt(portNumberTextField.getText());

        try {
            Boolean connected = multiplayer.connect(hostname, port);
            if (connected) {
                
                if (saveSettingsCheckBox.isSelected()) {
                    saveExtensionSetting("hostname", hostname);
                    saveExtensionSetting("port", String.format("%d", port));
                }
                
                this.triggerOnConnection();
            }
        } catch (Exception err) {
            logger.error(err);
            JOptionPane.showMessageDialog(this,
                String.format("Failed to connect.\n%s", err),
                "Conncection Error",
                JOptionPane.ERROR_MESSAGE);
            connectButton.setEnabled(true);
        }
    }//GEN-LAST:event_connectButtonActionPerformed

    private void saveSettingsCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveSettingsCheckBoxActionPerformed

    }//GEN-LAST:event_saveSettingsCheckBoxActionPerformed

    private void setupHelpButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_setupHelpButtonActionPerformed
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            try {
                Desktop.getDesktop().browse(new URI(helpURI));
            } catch (IOException | URISyntaxException err) {
                logger.error(err);
            }
        }
    }//GEN-LAST:event_setupHelpButtonActionPerformed

    private void githubButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_githubButtonActionPerformed
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            try {
                Desktop.getDesktop().browse(new URI(githubURI));
            } catch (IOException | URISyntaxException err) {
                logger.error(err);
            }
        }
    }//GEN-LAST:event_githubButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton connectButton;
    private javax.swing.JButton githubButton;
    private javax.swing.JLabel hoastnameLabel;
    private javax.swing.JTextField hostnameTextField;
    private javax.swing.JLabel portNumberLabel;
    private javax.swing.JTextField portNumberTextField;
    private javax.swing.JCheckBox saveSettingsCheckBox;
    private javax.swing.JButton setupHelpButton;
    private javax.swing.JLabel titleLabel;
    private javax.swing.JLabel versionLabel;
    // End of variables declaration//GEN-END:variables
}
