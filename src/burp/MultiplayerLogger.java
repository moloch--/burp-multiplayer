/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author moloch
 */
public class MultiplayerLogger {
    
    public static final String DEBUG = "Debug";
    public static final String INFO = "Info";
    public static final String WARN = "Warn";
    public static final String ERROR = "Error";
    public static final List<String> levels = new ArrayList<String>(Arrays.asList(
        DEBUG, INFO, WARN, ERROR
    ));
    public final IBurpExtenderCallbacks callbacks;
    private String currentLevel = INFO;

    public MultiplayerLogger(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    public void setLevel(String level) {
        if (levels.contains(level)) {
            currentLevel = level;
        }
    }
    
    private int currentLevelIndex() {
        return levels.indexOf(currentLevel);
    }
    
    public void debug(String format, Object ... args) {
        if (currentLevelIndex() <= levels.indexOf(DEBUG)) {
            callbacks.printOutput(String.format(format, args));
        }
    }
    
    public void info(String format, Object ... args) {
        if (currentLevelIndex() <= levels.indexOf(INFO)) {
            callbacks.printOutput(String.format(format, args));
        }
    }
    
    public void warn(String format, Object ... args) {
        if (currentLevelIndex() <= levels.indexOf(WARN) ) {
            callbacks.printOutput(String.format(format, args));
        }
    }

    public void error(String format, Object ... args) {
        callbacks.printError(String.format(format, args));
    }
    
    public void error(Exception err) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        err.printStackTrace(pw);
        callbacks.printError(sw.toString());
    }
    
}
