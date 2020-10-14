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
    
    private final Multiplayer multiplayer;
    private final IBurpExtenderCallbacks callbacks;
    public static final List<String> defaultExportedColumns = new ArrayList<String>(Arrays.asList(
        Method, Protocol, Host, Path, Port, StatusCode, Comment, DateTime
    ));
    
    public MultiplayerExporter(Multiplayer multiplayer, IBurpExtenderCallbacks callbacks) {
        this.multiplayer = multiplayer;
        this.callbacks = callbacks;
    }
    
    public Boolean ExportXLSX(String filepath) {
        
        Workbook workbook = new XSSFWorkbook();
        Sheet allSheet = workbook.createSheet("All");
        Integer allRowCursor = 0;
//        HashMap<String, Sheet> sheetMap = new HashMap();
//        HashMap<String, Integer> rowCursors = new HashMap();
        HashMap<String, MultiplayerRequestResponse> snapshot = multiplayer.history.snapshot();
        
        for (String key : snapshot.keySet()) {
            MultiplayerRequestResponse reqResp = snapshot.get(key);
            Row allRow = allSheet.createRow(allRowCursor++);
            writeRow(allRow, defaultExportedColumns, reqResp);   
        }

        // Write to disk
        try (OutputStream fileOut = new FileOutputStream(filepath)) {
            workbook.write(fileOut);
            return true;
        } catch (FileNotFoundException err) {
            callbacks.printError(err.toString());
        } catch (IOException err) {
            callbacks.printError(err.toString());
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
            callbacks.printOutput(String.format("Export: %s", value.getClass().getSimpleName()));
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
}
