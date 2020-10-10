/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
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
    
    public static final String ID = "ID";
    public static final String Method = "Method";
    public static final String Protocol = "Protocol";
    public static final String Host = "Host";
    public static final String Path = "Path";
    public static final String Port = "Port";
    public static final String StatusCode = "Status Code";
    public static final String[] columns = {
        ID, Method, Protocol, Host, Path, Port, StatusCode
    };
    private final ConcurrentSkipListSet<MultiplayerRequestResponse> history;
    
    public HTTPHistory(ExecutorService executor, IBurpExtenderCallbacks callbacks) {
        history = new ConcurrentSkipListSet();
        this.executor = executor;
        this.callbacks = callbacks;
    }
    
    public void add(MultiplayerRequestResponse reqResp) {
        history.add(reqResp);
        TableModelEvent event = new TableModelEvent(this); // TODO: Don't refresh the entire table
        tableListenerCallbacks.forEach(listener -> {
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
    
    public MultiplayerRequestResponse getById(String reqRespId) {
        // Linear search, yea yea it's terrible    
        Iterator<MultiplayerRequestResponse> iter = history.iterator();
        while (iter.hasNext()) {
            MultiplayerRequestResponse reqResp = iter.next();
            if (reqResp.getId().equals(reqRespId)) {
                return reqResp;
            }
        }
        return null;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Iterator<MultiplayerRequestResponse> iter = history.iterator();
        for (int index = 0; index < rowIndex; ++index) {
            iter.next();
        }
        MultiplayerRequestResponse reqResp = iter.next();

        switch(columns[columnIndex]) {
            case ID:
                return reqResp.getId();
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
