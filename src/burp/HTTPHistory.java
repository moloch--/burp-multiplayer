/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

/**
 *
 * @author moloch
 */
public class HTTPHistory implements TableModel {
    
    public static final String[] columns = {
        "Protocol", "Domain", "Path", "Status", "Time"
    }; 
    
    private final List<TableModelListener> tableListenerCallbacks = new ArrayList();
    private final ExecutorService executor;
    private final LinkedHashMap<String, MultiplayerRequestResponse> history;
    
    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();
    
    private IBurpExtenderCallbacks callbacks;

    public HTTPHistory(ExecutorService executor, IBurpExtenderCallbacks callbacks) {
        history = new LinkedHashMap();
        this.executor = executor;
        this.callbacks = callbacks;
    }
    
    public void put(String id, MultiplayerRequestResponse reqResp) {
        writeLock.lock();
        try {

            history.put(id, reqResp);

            // int rowNumber = getRowNumberOfId(id);

            TableModelEvent event = new TableModelEvent(this);

//            tableListenerCallbacks.forEach(listener -> {
//                callbacks.printOutput("5");
//                executor.submit(() -> listener.tableChanged(event));
//            });

        } finally {
            writeLock.unlock();
        }
    }
    
    public MultiplayerRequestResponse get(String id) {
        readLock.lock();
        try {
            MultiplayerRequestResponse reqResp = history.get(id);
            return reqResp;
        } finally {
            readLock.unlock();
        }
    }
    
    private int getRowNumberOfId(String id) {
        readLock.lock();
        try {
            String[] keys = (String[]) history.keySet().toArray();
            for (int index = 0; index < keys.length; ++index) {
                if (id.equals(keys[index])) {
                    return index;
                }
            }
            return -1;
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public int getRowCount() {
        readLock.lock();
        try {
            int size = history.size();
            return size;
        } finally {
            readLock.unlock();
        }
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
    public Class<?> getColumnClass(int columnIndex) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        readLock.lock();
        try {
            String rowKey = (String) history.keySet().toArray()[columnIndex];
            MultiplayerRequestResponse reqResp = history.get(rowKey);
            String columnName = columns[columnIndex];
            return reqResp.getProperty(columnName);
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void addTableModelListener(TableModelListener callback) {
        tableListenerCallbacks.add(callback);
    }

    @Override
    public void removeTableModelListener(TableModelListener callback) {
        tableListenerCallbacks.remove(callback);
    }

}
