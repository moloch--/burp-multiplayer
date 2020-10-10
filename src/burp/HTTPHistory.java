/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ExecutorService;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;


/**
 *
 * @author moloch
 */
public class HTTPHistory extends AbstractTableModel {
    
    private IBurpExtenderCallbacks callbacks;
    private final List<TableModelListener> tableListenerCallbacks = new ArrayList();
    private final ExecutorService executor;
    
    public static final String Method = "Method";
    public static final String Protocol = "Protocol";
    public static final String Host = "Host";
    public static final String Path = "Path";
    public static final String Port = "Port";
    public static final String StatusCode = "Status Code";
    public static final String[] columns = {
        Method, Protocol, Host, Path, Port, StatusCode
    };
    private final ConcurrentSkipListSet<MultiplayerRequestResponse> history;
    
    public HTTPHistory(ExecutorService executor, IBurpExtenderCallbacks callbacks) {
        history = new ConcurrentSkipListSet();
        this.executor = executor;
        this.callbacks = callbacks;
    }
    
    public void add(MultiplayerRequestResponse reqResp) {
        history.add(reqResp);
        TableModelEvent event = new TableModelEvent(this);
        tableListenerCallbacks.forEach(listener -> {
            callbacks.printOutput("Table Changed!");
            executor.submit(() -> listener.tableChanged(event));
        });
    }
    
    @Override
    public int getRowCount() {
        return history.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return columns[columnIndex];
    }
    
    @Override
    public void addTableModelListener(TableModelListener callback) {
        tableListenerCallbacks.add(callback);
    }
     
    @Override
    public void removeTableModelListener(TableModelListener callback) {
        tableListenerCallbacks.remove(callback);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        callbacks.printOutput(String.format("getValueAt->%d,%d", rowIndex, columnIndex));
        MultiplayerRequestResponse reqResp = history.toArray(new MultiplayerRequestResponse[history.size()])[rowIndex];
        callbacks.printOutput(String.format("Got: %s (want: %s)", reqResp, columns[columnIndex]));
        switch(columns[columnIndex]) {
            case Method:
                return reqResp.getMethod();
            case Protocol:
                return reqResp.getProtocol();
            case Host:
                return reqResp.getHost();
            case Path:
                return reqResp.getPath();
            case Port:
                return reqResp.getPort();
            case StatusCode:
                return reqResp.getStatus();
        }
        return null;
    }
    
    @Override
    public Class getColumnClass(int columnIndex) {
        return getValueAt(0, columnIndex).getClass();
    }
    
    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

}
