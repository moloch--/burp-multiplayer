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
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

/**
 *
 * @author moloch
 */
public class HTTPHistory implements TableModel {
    
    private final List<ChangeCallback> changeCallbacks = new ArrayList();
    private final List<TableModelListener> tableListenerCallbacks = new ArrayList();
    private final ExecutorService executor;
    private final LinkedHashMap<String, MultiplayerRequestResponse> history;
    
    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();

    public HTTPHistory(ExecutorService executor) {
        this.history = new LinkedHashMap();
        this.executor = executor;
    }
    
    public void put(String id, MultiplayerRequestResponse reqResp) {
        writeLock.lock();
        try {
            MultiplayerRequestResponse value = history.put(id, reqResp);
            changeCallbacks.forEach(callback -> {
                executor.submit(() -> callback.onChange(value.getId()));
            });
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
    
    public void registerOnChangeCallback(ChangeCallback callback) {
        changeCallbacks.add(callback);
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
        return 1;
    }

    @Override
    public String getColumnName(int columnIndex) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
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
