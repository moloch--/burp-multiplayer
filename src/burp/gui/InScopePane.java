/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.gui;

import burp.HTTPHistory;
import burp.HTTPMessageEditor;
import burp.IBurpExtenderCallbacks;
import burp.Multiplayer;
import burp.MultiplayerExporter;
import burp.MultiplayerLogger;
import burp.MultiplayerRequestResponse;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
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
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;


/**
 *
 * @author moloch
 */
public final class InScopePane extends javax.swing.JPanel implements TableModelListener {

    private final Multiplayer multiplayer;
    private final IBurpExtenderCallbacks callbacks;
    private final ListSelectionListener rowSelectionListener;
    private TableRowSorter<TableModel> sorter;
    private final MultiplayerLogger logger;
    
    /**
     * Creates new form InScopePane
     * @param multiplayer
     * @param logger
     */
    public InScopePane(Multiplayer multiplayer, MultiplayerLogger logger) {
        this.callbacks = logger.callbacks;
        this.logger = logger;
        this.multiplayer = multiplayer;
        logger.debug("Initializing in-scope panel");
        initComponents();
        
        // Hide ID column
        inScopeTable.getColumnModel().getColumn(0).setMinWidth(0);
        inScopeTable.getColumnModel().getColumn(0).setMaxWidth(0);
        
        setMinColumnWidths();

        // Highlight column
        int highlightColumnIndex = HTTPHistory.columns.indexOf(HTTPHistory.Highlight);
        TableColumn highlightColumn = inScopeTable.getColumnModel().getColumn(highlightColumnIndex);
        JComboBox highlightComboBox = new JComboBox();
        for (String colorName : HTTPHistory.highlights) {
            highlightComboBox.addItem(colorName);
        }
        highlightColumn.setCellEditor(new DefaultCellEditor(highlightComboBox));

        // Assessment column
        int assessmentColumnIndex = HTTPHistory.columns.indexOf(HTTPHistory.Assessment);
        TableColumn assessmentColumn = inScopeTable.getColumnModel().getColumn(assessmentColumnIndex);
        JComboBox assessmentStateComboBox = new JComboBox();
        for (String state : HTTPHistory.assessmentStates) {
            assessmentStateComboBox.addItem(state);
        }
        assessmentColumn.setCellEditor(new DefaultCellEditor(assessmentStateComboBox));
        
        // Table listener
        this.multiplayer.history.addTableModelListener(inScopeTable);
        this.multiplayer.history.addTableModelListener(this);
        
        // Row Selection Listener
        rowSelectionListener = (ListSelectionEvent event) -> {
            if (!event.getValueIsAdjusting()) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                displayMessageEditorFor(reqRespId);
                updateAvailibleFilters(reqRespId);
            }
        };
        inScopeTable.getSelectionModel().addListSelectionListener(rowSelectionListener);

        applyRowFilter();
        updateStateProgress();
        initContextMenu();
        refresh();
        
        logger.debug("in-scope panel initialized!");
    }

    private void setMinColumnWidths() {
        // Assessment
        int assessmentIndex = HTTPHistory.columns.indexOf(HTTPHistory.Assessment);
        inScopeTable.getColumnModel().getColumn(assessmentIndex).setMinWidth(100);
        
        // Method
        int methodIndex = HTTPHistory.columns.indexOf(HTTPHistory.Method);
        inScopeTable.getColumnModel().getColumn(methodIndex).setMinWidth(75);
        inScopeTable.getColumnModel().getColumn(methodIndex).setPreferredWidth(75);

        // Protocol
        int protocolIndex = HTTPHistory.columns.indexOf(HTTPHistory.Protocol);
        inScopeTable.getColumnModel().getColumn(protocolIndex).setMinWidth(75);
        
        // Host
        int hostIndex = HTTPHistory.columns.indexOf(HTTPHistory.Host);
        inScopeTable.getColumnModel().getColumn(hostIndex).setMinWidth(75);
        
        // Path
        int pathIndex = HTTPHistory.columns.indexOf(HTTPHistory.Path);
        inScopeTable.getColumnModel().getColumn(pathIndex).setMinWidth(75);
        
        // Port
        int portIndex = HTTPHistory.columns.indexOf(HTTPHistory.Port);
        inScopeTable.getColumnModel().getColumn(portIndex).setMinWidth(50);
        inScopeTable.getColumnModel().getColumn(portIndex).setPreferredWidth(50);

        // Status Code
        int statusCodeIndex = HTTPHistory.columns.indexOf(HTTPHistory.StatusCode);
        inScopeTable.getColumnModel().getColumn(statusCodeIndex).setMinWidth(100);
        
        // Comment
        int commentIndex = HTTPHistory.columns.indexOf(HTTPHistory.Comment);
        inScopeTable.getColumnModel().getColumn(commentIndex).setMinWidth(100);
        
        // Highlight
        int highlightIndex = HTTPHistory.columns.indexOf(HTTPHistory.Highlight);
        inScopeTable.getColumnModel().getColumn(highlightIndex).setMinWidth(100);
        
        // Date / Time
        int dateTimeIndex = HTTPHistory.columns.indexOf(HTTPHistory.DateTime);
        inScopeTable.getColumnModel().getColumn(dateTimeIndex).setMinWidth(100);
    }
    
    private void applyRowFilter() {
        if (multiplayer.history.size() < 1) {
            return;
        }
        sorter.setRowFilter(new RowFilter<TableModel, Integer>() {
            
            @Override
            public boolean include(Entry<? extends TableModel, ? extends Integer> entry) {
                Integer rowNumber = entry.getIdentifier();
                TableModel model = entry.getModel();
                int assessmentColumnIndex = HTTPHistory.columns.indexOf(HTTPHistory.Assessment);
                String state = (String) model.getValueAt(rowNumber, assessmentColumnIndex);
                return getEnabledFilters().contains(state);
            }

        });
    }
        
    private List<String> getEnabledFilters() {
        List<String> enabledFilters = new ArrayList();
        if (newStateCheckBox.isSelected()) {
            enabledFilters.add(HTTPHistory.New);
        }
        if (inProgressStateCheckBox.isSelected()) {
            enabledFilters.add(HTTPHistory.InProgress);
        }
        if (doneStateCheckBox.isSelected()) {
            enabledFilters.add(HTTPHistory.Done);
        }
        if (blockedStateCheckBox.isSelected()) {
            enabledFilters.add(HTTPHistory.Blocked);
        }
        return enabledFilters;
    }
    
    public void refresh() {
        this.repaint();
        this.revalidate();
    }
    
    public void displayMessageEditorFor(String reqRespId) {
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

    public void updateAvailibleFilters(String reqRespId) {
        String state = multiplayer.history.getById(reqRespId).getAssessment();
        newStateCheckBox.setEnabled(!state.equals(HTTPHistory.New));
        doneStateCheckBox.setEnabled(!state.equals(HTTPHistory.Done));
        inProgressStateCheckBox.setEnabled(!state.equals(HTTPHistory.InProgress));
        blockedStateCheckBox.setEnabled(!state.equals(HTTPHistory.Blocked));
    }
    
    @Override
    public void tableChanged(TableModelEvent event) {
        updateStateProgress();
    }
    
    public void updateStateProgress() {
        int progress = multiplayer.history.getProgress();
        stateProgressBar.setValue(progress);
        refresh();
    }
    
    public void initContextMenu() {
        logger.debug("initContextMenu");
        
        final JPopupMenu contextMenu = new JPopupMenu();
        
        contextMenu.add(initSendToMenu());

        // Active Scan
        JMenuItem activeScanItem = new JMenuItem("Active Scan");
        activeScanItem.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                MultiplayerRequestResponse reqResp = multiplayer.history.getById(reqRespId);
                Boolean useHttps = "https".equals(reqResp.getProtocol().toLowerCase());
                callbacks.doActiveScan(reqResp.getHost(), reqResp.getPort(), useHttps, reqResp.getRequest());  
            }
            
        });
        contextMenu.add(activeScanItem);
        
        // Delete
        JMenuItem deleteItem = new JMenuItem("Delete");
        deleteItem.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                multiplayer.reqRespRemove(reqRespId);
            }
            
        });
        contextMenu.add(deleteItem);

        inScopeTable.addMouseListener(new MouseAdapter() {
            
            @Override
            public void mouseReleased(MouseEvent event) {
                int r = inScopeTable.rowAtPoint(event.getPoint());
                if (r >= 0 && r < inScopeTable.getRowCount()) {
                    inScopeTable.setRowSelectionInterval(r, r);
                } else {
                    inScopeTable.clearSelection();
                }

                int rowIndex = inScopeTable.getSelectedRow();
                if (rowIndex < 0) {
                    return;
                }
                if (event.isPopupTrigger() && event.getComponent() instanceof JTable) {
                    contextMenu.show(event.getComponent(), event.getX(), event.getY());
                }
            }
            
        });
        inScopeTable.setComponentPopupMenu(contextMenu);

    }
    
    public JMenu initSendToMenu() {
        logger.debug("initSendToMenu");
        JMenu sendToMenu = new JMenu("Send To");
        

        // Repeater
        JMenuItem sendToRepeaterItem = new JMenuItem("Repeater");
        sendToRepeaterItem.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                MultiplayerRequestResponse reqResp = multiplayer.history.getById(reqRespId);
                Boolean useHttps = "https".equals(reqResp.getProtocol().toLowerCase());
                if (multiplayer.getSendToImpliesInProgress()) {
                    impliedInProgress(inScopeTable.getSelectedRow());
                }
                callbacks.sendToRepeater(reqResp.getHost(), reqResp.getPort(), useHttps, reqResp.getRequest(), "From Multiplayer");
            }
            
        });
        sendToMenu.add(sendToRepeaterItem);

        // Intruder
        JMenuItem sendToIntruderItem = new JMenuItem("Intruder");
        sendToIntruderItem.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                MultiplayerRequestResponse reqResp = multiplayer.history.getById(reqRespId);
                Boolean useHttps = "https".equals(reqResp.getProtocol().toLowerCase());
                if (multiplayer.getSendToImpliesInProgress()) {
                    impliedInProgress(inScopeTable.getSelectedRow());
                }
                callbacks.sendToIntruder(reqResp.getHost(), reqResp.getPort(), useHttps, reqResp.getRequest());
            }
            
        });
        sendToMenu.add(sendToIntruderItem);

        // Comparer (Request)
        JMenuItem sendToComparerReqItem = new JMenuItem("Comparer (Request)");
        sendToComparerReqItem.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                MultiplayerRequestResponse reqResp = multiplayer.history.getById(reqRespId);
                if (multiplayer.getSendToImpliesInProgress()) {
                    impliedInProgress(inScopeTable.getSelectedRow());
                }
                callbacks.sendToComparer(reqResp.getRequest());
            }
            
        });
        sendToMenu.add(sendToComparerReqItem);        
        
        // Comparer (Response)
        JMenuItem sendToComparerRespItem = new JMenuItem("Comparer (Response)");
        sendToComparerRespItem.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                MultiplayerRequestResponse reqResp = multiplayer.history.getById(reqRespId);
                if (multiplayer.getSendToImpliesInProgress()) {
                    impliedInProgress(inScopeTable.getSelectedRow());
                }
                callbacks.sendToComparer(reqResp.getResponse());
            }
            
        });
        sendToMenu.add(sendToComparerRespItem);
        
        // Spider
        JMenuItem sendToSpiderItem = new JMenuItem("Spider");
        sendToSpiderItem.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                String reqRespId = (String) inScopeTable.getValueAt(inScopeTable.getSelectedRow(), 0);
                MultiplayerRequestResponse reqResp = multiplayer.history.getById(reqRespId);
                if (multiplayer.getSendToImpliesInProgress()) {
                    impliedInProgress(inScopeTable.getSelectedRow());
                }
                callbacks.sendToSpider(reqResp.getURL(callbacks.getHelpers()));
            }
            
        });
        sendToMenu.add(sendToSpiderItem);
        
        
        return sendToMenu;
    }
    
    private void impliedInProgress(int row) {
        int columnIndex = HTTPHistory.columns.indexOf(HTTPHistory.Assessment);
        inScopeTable.setValueAt(HTTPHistory.InProgress, row, columnIndex);
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

                // Handle row colors
                String id = (String) this.getValueAt(row, 0);
                Color backgroundColor = multiplayer.history.getColorForId(id);
                if(!component.getBackground().equals(getSelectionBackground())) {
                    component.setBackground(backgroundColor);
                }

                // Handle column width
                int rendererWidth = component.getPreferredSize().width;
                TableColumn tableColumn = getColumnModel().getColumn(column);
                tableColumn.setPreferredWidth(Math.max(rendererWidth + getIntercellSpacing().width, tableColumn.getPreferredWidth()));

                return component;
            }
        };
        bottomTabbedPane = new javax.swing.JTabbedPane();
        exportSpreadsheetButton = new javax.swing.JButton();
        newStateCheckBox = new javax.swing.JCheckBox();
        filtersLabel = new javax.swing.JLabel();
        inProgressStateCheckBox = new javax.swing.JCheckBox();
        doneStateCheckBox = new javax.swing.JCheckBox();
        blockedStateCheckBox = new javax.swing.JCheckBox();
        jLabel1 = new javax.swing.JLabel();
        stateProgressBar = new javax.swing.JProgressBar();

        parentSplitPane.setOrientation(javax.swing.JSplitPane.VERTICAL_SPLIT);

        inScopeTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        inScopeTable.setColumnSelectionAllowed(false);
        inScopeTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        inScopeTable.setRowSelectionAllowed(true);
        sorter = new TableRowSorter<TableModel>(inScopeTable.getModel());
        inScopeTable.setRowSorter(sorter);
        inScopeTablePane.setViewportView(inScopeTable);
        inScopeTable.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

        parentSplitPane.setTopComponent(inScopeTablePane);
        parentSplitPane.setRightComponent(bottomTabbedPane);

        exportSpreadsheetButton.setText("Export Spreadsheet");
        exportSpreadsheetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportSpreadsheetButtonActionPerformed(evt);
            }
        });

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
        jLabel1.setText("Coverage:");

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
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(stateProgressBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(exportSpreadsheetButton)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(exportSpreadsheetButton)
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

    private void exportSpreadsheetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exportSpreadsheetButtonActionPerformed
        MultiplayerExporter exporter = new MultiplayerExporter(multiplayer, logger);
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save spreadsheet to ...");
        int userSelection = fileChooser.showSaveDialog(parentFrame);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            String filePath = fileToSave.getAbsolutePath();
            if (!filePath.endsWith(".xlsx")) {
                filePath = String.format("%s.xlsx", filePath);
            }
            exporter.exportXLSX(filePath);
        }
    }//GEN-LAST:event_exportSpreadsheetButtonActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox blockedStateCheckBox;
    private javax.swing.JTabbedPane bottomTabbedPane;
    private javax.swing.JCheckBox doneStateCheckBox;
    private javax.swing.JButton exportSpreadsheetButton;
    private javax.swing.JLabel filtersLabel;
    private javax.swing.JCheckBox inProgressStateCheckBox;
    private javax.swing.JTable inScopeTable;
    private javax.swing.JScrollPane inScopeTablePane;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JCheckBox newStateCheckBox;
    private javax.swing.JSplitPane parentSplitPane;
    private javax.swing.JProgressBar stateProgressBar;
    // End of variables declaration//GEN-END:variables


}
