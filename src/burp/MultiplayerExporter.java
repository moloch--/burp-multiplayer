/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import static burp.HTTPHistory.Comment;
import static burp.HTTPHistory.DateTime;
import static burp.HTTPHistory.Host;
import static burp.HTTPHistory.Method;
import static burp.HTTPHistory.Path;
import static burp.HTTPHistory.Port;
import static burp.HTTPHistory.Protocol;
import static burp.HTTPHistory.StatusCode;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;


/**
 *
 * @author moloch
 */
public class MultiplayerExporter {
    
    private final MultiplayerLogger logger;
    private final Multiplayer multiplayer;
    public static final List<String> defaultExportedColumns = new ArrayList<String>(Arrays.asList(
        Method, Protocol, Host, Path, Port, StatusCode, Comment, DateTime
    ));
    
    public MultiplayerExporter(Multiplayer multiplayer, MultiplayerLogger logger) {
        this.multiplayer = multiplayer;
        this.logger = logger;
    }
    
    public Boolean exportXLSX(String filePath) {
        return this.exportXLSX(filePath, defaultExportedColumns);
    }
    
    public Boolean exportXLSX(String filePath, List<String> exportColumns) {
        
        Workbook workbook = new XSSFWorkbook();
        
        Sheet allSheet = workbook.createSheet("All");
        Integer allRowCursor = 1;
        
        HashMap<String, Sheet> sheetMap = new HashMap();
        HashMap<String, Integer> rowCursors = new HashMap();
        List<String> hostColumns = new ArrayList<>(exportColumns);
        if (hostColumns.contains(Host)) {
            hostColumns.remove(Host);
        }
        
        HashMap<String, MultiplayerRequestResponse> snapshot = multiplayer.history.snapshot();
        
        
        writeHeaders(allSheet, exportColumns);
        for (String key : snapshot.keySet()) {
            MultiplayerRequestResponse reqResp = snapshot.get(key);
            Row allRow = allSheet.createRow(allRowCursor++);
            writeRow(allRow, exportColumns, reqResp);
            
            if (!sheetMap.containsKey(reqResp.getHost())) {
                Sheet sheet = workbook.createSheet(reqResp.getHost());
                writeHeaders(sheet, hostColumns);
                sheetMap.put(reqResp.getHost(), sheet);
                rowCursors.put(reqResp.getHost(), 1);
            }
            
            Sheet sheet = sheetMap.get(reqResp.getHost());
            int rowCursor = rowCursors.get(reqResp.getHost());
            Row row = sheet.createRow(rowCursor);
            rowCursors.put(reqResp.getHost(), ++rowCursor);
            writeRow(row, hostColumns, reqResp);
        }

        // Write to disk
        try (OutputStream fileOut = new FileOutputStream(filePath)) {
            workbook.write(fileOut);
            return true;
        } catch (FileNotFoundException err) {
            logger.error(err);
        } catch (IOException err) {
            logger.error(err);
        }
        return false;
    }
    
    private void writeRow(Row row, List<String> exportedColumns, MultiplayerRequestResponse reqResp) {
        exportedColumns.forEach(columnName -> {
            Cell cell = row.createCell(exportedColumns.indexOf(columnName));
            Object value = reqResp.getProperty(columnName);
            if (value == null) {
                return;
            }
            logger.debug("Export: %s", value.getClass().getSimpleName());
            switch (value.getClass().getSimpleName()) {
                case "String":
                    cell.setCellValue((String) value);
                    break;
                case "Integer":
                    cell.setCellValue((Integer) value);
                    break;
            }
        });
    }
    
    private void writeHeaders(Sheet sheet, List<String> columnNames) {
        Row row = sheet.createRow(0);
        for (int index = 0; index < columnNames.size(); ++index) {
            row.createCell(index).setCellValue(columnNames.get(index));
        }
    }
}
