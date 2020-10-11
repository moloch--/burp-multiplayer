/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.gui;

import burp.HTTPMessageEditor;
import burp.IBurpExtenderCallbacks;
import burp.Multiplayer;
import burp.MultiplayerRequestResponse;
import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.RowFilter;
import javax.swing.RowFilter.Entry;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;


/**
 *
 * @author moloch
 */
public class InScopePane extends javax.swing.JPanel implements TableModelListener {

    private Multiplayer multiplayer;
    private IBurpExtenderCallbacks callbacks;
    private ListSelectionListener rowSelectionListener;
    private TableRowSorter<TableModel> sorter;
    
    /**
     * Creates new form InScopePane
     */
    public InScopePane(Multiplayer multiplayer, IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.multiplayer = multiplayer;
        initComponents();
        
        // Hide ID column
        inScopeTable.getColumnModel().getColumn(0).setMinWidth(0);
        inScopeTable.getColumnModel().getColumn(0).setMaxWidth(0);

        // Highlight column
        int highlightColumnIndex = multiplayer.history.columns.indexOf(multiplayer.history.Highlight);
        TableColumn highlightColumn = inScopeTable.getColumnModel().getColumn(highlightColumnIndex);
        JComboBox highlightComboBox = new JComboBox();
        for (String colorName : multiplayer.history.highlights) {
            highlightComboBox.addItem(colorName);
        }
        highlightColumn.setCellEditor(new DefaultCellEditor(highlightComboBox));

        // Assessment column
        int assessmentColumnIndex = multiplayer.history.columns.indexOf(multiplayer.history.Assessment);
        TableColumn assessmentColumn = inScopeTable.getColumnModel().getColumn(assessmentColumnIndex);
        JComboBox assessmentStateComboBox = new JComboBox();
        for (String state : multiplayer.history.assessmentStates) {
            assessmentStateComboBox.addItem(state);
        }
        assessmentColumn.setCellEditor(new DefaultCellEditor(assessmentStateComboBox));
        
        // Table listener
        this.multiplayer.history.addTableModelListener(inScopeTable);
        this.multiplayer.history.addTableModelListener(this);
        
        // Row Selection Listener
        rowSelectionListener = new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent event) {
                if (!event.getValueIsAdjusting()) {
                    String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                    displayMessageEditorFor(reqRespId);
                }
            }
        };
        inScopeTable.getSelectionModel().addListSelectionListener(rowSelectionListener);
        applyRowFilter();
        updateStateProgress();
        refresh();
    }
    
    private void applyRowFilter() {

        sorter.setRowFilter(new RowFilter<TableModel, Integer>() {
            
            public boolean include(Entry<? extends TableModel, ? extends Integer> entry) {
                Integer rowNumber = entry.getIdentifier();
                TableModel model = entry.getModel();
                int assessmentColumnIndex = multiplayer.history.columns.indexOf(multiplayer.history.Assessment);
                String state = (String) model.getValueAt(rowNumber, assessmentColumnIndex);
                return getEnabledFilters().contains(state);
            }
            
        });
    }
        
    private List<String> getEnabledFilters() {
        List<String> enabledFilters = new ArrayList();
        if (newStateCheckBox.isSelected()) {
            enabledFilters.add(multiplayer.history.New);
        }
        if (inProgressStateCheckBox.isSelected()) {
            enabledFilters.add(multiplayer.history.InProgress);
        }
        if (doneStateCheckBox.isSelected()) {
            enabledFilters.add(multiplayer.history.Done);
        }
        if (blockedStateCheckBox.isSelected()) {
            enabledFilters.add(multiplayer.history.Blocked);
        }
        return enabledFilters;
    }
    
    public void refresh() {
        this.repaint();
        this.revalidate();
    }
    
    public void displayMessageEditorFor(String reqRespId) {
        // callbacks.printOutput(String.format("Selected: %s", reqRespId));
        MultiplayerRequestResponse reqResp = multiplayer.history.getById(reqRespId);
        
        // Save active tab
        int selectedTabIndex = bottomTabbedPane.getSelectedIndex();
        if (selectedTabIndex == -1) {
            selectedTabIndex = 0;
        }
        
        bottomTabbedPane.removeAll();
        
        HTTPMessageEditor editor = new HTTPMessageEditor(reqResp, callbacks);
        bottomTabbedPane.addTab("Request", editor.getRequestEditor().getComponent());
        bottomTabbedPane.addTab("Response", editor.getResponseEditor().getComponent());
        bottomTabbedPane.setSelectedIndex(selectedTabIndex);
    }
    
    public void tableChanged(TableModelEvent event) {
        callbacks.printOutput("Table changed (InScopePanel)");
        updateStateProgress();
    }
    
    public void updateStateProgress() {
        int progress = multiplayer.history.getProgress();
        callbacks.printOutput(String.format("Progress %d", progress));
        stateProgressBar.setValue(progress);
        refresh();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        parentSplitPane = new javax.swing.JSplitPane();
        inScopeTablePane = new javax.swing.JScrollPane();
        inScopeTable = new javax.swing.JTable(this.multiplayer.history) {
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component component = super.prepareRenderer(renderer, row, column);
                JComponent jComponent = (JComponent) component;
                String id = (String) this.getValueAt(row, 0);
                Color backgroundColor = multiplayer.history.getColorForId(id);
                // callbacks.printOutput(String.format("Row = %d, Column = %d (%s) -> %s", row, column, id, backgroundColor));
                if(!component.getBackground().equals(getSelectionBackground())) {
                    component.setBackground(backgroundColor);
                }
                return component;
            }
        };
        bottomTabbedPane = new javax.swing.JTabbedPane();
        jButton1 = new javax.swing.JButton();
        newStateCheckBox = new javax.swing.JCheckBox();
        filtersLabel = new javax.swing.JLabel();
        inProgressStateCheckBox = new javax.swing.JCheckBox();
        doneStateCheckBox = new javax.swing.JCheckBox();
        blockedStateCheckBox = new javax.swing.JCheckBox();
        jLabel1 = new javax.swing.JLabel();
        stateProgressBar = new javax.swing.JProgressBar();

        parentSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        inScopeTable.setColumnSelectionAllowed(true);
        inScopeTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        inScopeTable.setRowSelectionAllowed(true);
        inScopeTable.setColumnSelectionAllowed(false);
        sorter = new TableRowSorter<TableModel>(inScopeTable.getModel());
        inScopeTable.setRowSorter(sorter);
        inScopeTablePane.setViewportView(inScopeTable);
        inScopeTable.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

        parentSplitPane.setTopComponent(inScopeTablePane);
        parentSplitPane.setRightComponent(bottomTabbedPane);

        jButton1.setText("jButton1");

        newStateCheckBox.setSelected(true);
        newStateCheckBox.setText("New");
        newStateCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                newStateCheckBoxActionPerformed(evt);
            }
        });

        filtersLabel.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        filtersLabel.setText("Filters:");

        inProgressStateCheckBox.setSelected(true);
        inProgressStateCheckBox.setText("In Progress");
        inProgressStateCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                inProgressStateCheckBoxActionPerformed(evt);
            }
        });

        doneStateCheckBox.setText("Done");
        doneStateCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                doneStateCheckBoxActionPerformed(evt);
            }
        });

        blockedStateCheckBox.setSelected(true);
        blockedStateCheckBox.setText("Blocked");
        blockedStateCheckBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                blockedStateCheckBoxActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font(".SF NS Text", 1, 13)); // NOI18N
        jLabel1.setText("Progress:");

        stateProgressBar.setStringPainted(true);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(parentSplitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 962, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(34, 34, 34)
                .addComponent(filtersLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(newStateCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(inProgressStateCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(doneStateCheckBox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(blockedStateCheckBox)
                .addGap(18, 18, 18)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(stateProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jButton1)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(newStateCheckBox)
                    .addComponent(filtersLabel)
                    .addComponent(inProgressStateCheckBox)
                    .addComponent(doneStateCheckBox)
                    .addComponent(blockedStateCheckBox)
                    .addComponent(jLabel1)
                    .addComponent(stateProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(parentSplitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 682, Short.MAX_VALUE)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void newStateCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_newStateCheckBoxActionPerformed
        applyRowFilter();
        refresh();
    }//GEN-LAST:event_newStateCheckBoxActionPerformed

    private void inProgressStateCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_inProgressStateCheckBoxActionPerformed
        applyRowFilter();
        refresh();
    }//GEN-LAST:event_inProgressStateCheckBoxActionPerformed

    private void doneStateCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_doneStateCheckBoxActionPerformed
        applyRowFilter();
        refresh();
    }//GEN-LAST:event_doneStateCheckBoxActionPerformed

    private void blockedStateCheckBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_blockedStateCheckBoxActionPerformed
        applyRowFilter();
        refresh();
    }//GEN-LAST:event_blockedStateCheckBoxActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox blockedStateCheckBox;
    private javax.swing.JTabbedPane bottomTabbedPane;
    private javax.swing.JCheckBox doneStateCheckBox;
    private javax.swing.JLabel filtersLabel;
    private javax.swing.JCheckBox inProgressStateCheckBox;
    private javax.swing.JTable inScopeTable;
    private javax.swing.JScrollPane inScopeTablePane;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JCheckBox newStateCheckBox;
    private javax.swing.JSplitPane parentSplitPane;
    private javax.swing.JProgressBar stateProgressBar;
    // End of variables declaration//GEN-END:variables


}
