/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.gui;

import burp.IBurpExtenderCallbacks;
import burp.Multiplayer;
import burp.MultiplayerLogger;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;

/**
 *
 * @author moloch
 */
public class SelectProjectPanel extends javax.swing.JPanel {

    private final Multiplayer multiplayer;
    private List<Runnable> onProjectSelectionCallbacks = new ArrayList<>();
    private final IBurpExtenderCallbacks callbacks;
    private final MultiplayerLogger logger;
    private final DefaultListModel<String> projectListModel = new DefaultListModel<>();
    private static final String RethinkDBInternal = "rethinkdb"; 
    
    /**
     * Creates new form SelectProjectPanel
     * @param multiplayer
     * @param logger
     */
    public SelectProjectPanel(Multiplayer multiplayer, MultiplayerLogger logger) {
        this.multiplayer = multiplayer;
        this.logger = logger;
        this.callbacks = logger.callbacks;
        initComponents();
    }
    
    public void initProjectList() {
        logger.debug("Fetching project list ...");
        projectListModel.clear();
        List<String> projects = multiplayer.getProjects();
        projects.forEach(project -> {
            logger.debug("Project: %s", project);
            if (RethinkDBInternal.equals(project)) {
                return;
            }
            projectListModel.addElement(project);
        });
        projectsJList.setModel(projectListModel);
    }
    
    public void onProjectSelection(Runnable callback) {
        onProjectSelectionCallbacks.add(callback);
    }
    
    private void triggerOnProjectSelection() {
        onProjectSelectionCallbacks.forEach(callback -> {
            callback.run();
        });
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        projectsJList = new javax.swing.JList<>();
        createProjectButton = new javax.swing.JButton();
        selectProjectButton = new javax.swing.JButton();
        deleteProjectButton = new javax.swing.JButton();

        projectsJList.setModel(projectListModel);
        jScrollPane1.setViewportView(projectsJList);

        createProjectButton.setText("Create Project");
        createProjectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                createProjectButtonActionPerformed(evt);
            }
        });

        selectProjectButton.setText("Select Project");
        selectProjectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                selectProjectButtonActionPerformed(evt);
            }
        });

        deleteProjectButton.setLabel("Delete Project");
        deleteProjectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteProjectButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(400, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addComponent(selectProjectButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(createProjectButton, javax.swing.GroupLayout.DEFAULT_SIZE, 208, Short.MAX_VALUE)
                    .addComponent(deleteProjectButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(400, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(63, 63, 63)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 239, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(selectProjectButton, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(createProjectButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(deleteProjectButton)
                .addContainerGap(297, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void selectProjectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_selectProjectButtonActionPerformed
        String project = projectsJList.getSelectedValue();
        if (project != null && !project.isBlank() && !project.isEmpty()) {
            multiplayer.setProject(project);
            triggerOnProjectSelection();
        }
    }//GEN-LAST:event_selectProjectButtonActionPerformed

    private void createProjectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_createProjectButtonActionPerformed
        String projectName = JOptionPane.showInputDialog(null, "New project name:", "Create Project", JOptionPane.QUESTION_MESSAGE);
        if (projectName != null && !projectName.isBlank() && !projectName.isEmpty()) {
            multiplayer.setProject(projectName);
            triggerOnProjectSelection();   
        }
    }//GEN-LAST:event_createProjectButtonActionPerformed

    private void deleteProjectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteProjectButtonActionPerformed
        String project = projectsJList.getSelectedValue();
        if (project != null && !project.isBlank() && !project.isEmpty()) {
            String message = String.format("Delete project '%s'?", project);
            int confirmation = JOptionPane.showConfirmDialog(null, message, "Delete Project", JOptionPane.OK_CANCEL_OPTION, JOptionPane.ERROR_MESSAGE);
            logger.debug("Confirmation: %d", confirmation);
            if (confirmation == 0) {
                multiplayer.deleteProject(project);
                projectsJList.clearSelection();
                initProjectList();
            }
        }
    }//GEN-LAST:event_deleteProjectButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton createProjectButton;
    private javax.swing.JButton deleteProjectButton;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JList<String> projectsJList;
    private javax.swing.JButton selectProjectButton;
    // End of variables declaration//GEN-END:variables
}
