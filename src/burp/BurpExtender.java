package burp;

import java.awt.Component;

import javax.swing.*;

public class BurpExtender implements IBurpExtender, ITab {

    private static final String name = "Coverage";
    private static IBurpExtenderCallbacks callbacks;
    private static JTabbedPane mainTabbedPane;
    
    private static Coverage coverage;
    private static Boolean isConnected = false;
    private static ConnectionPanel connectionPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        this.logInfo("Coverage plugin loading ...");
        BurpExtender.callbacks.setExtensionName(BurpExtender.name);
        BurpExtender.coverage = new Coverage(callbacks);
        
        // Build Root GUI Components
        BurpExtender.connectionPanel = new ConnectionPanel(BurpExtender.coverage); 
        BurpExtender.mainTabbedPane = new JTabbedPane();
        
        // Register us as the main ITab
        BurpExtender.callbacks.addSuiteTab(BurpExtender.this);

        // HTTP Listener
        BurpExtender.coverage = new Coverage(BurpExtender.callbacks);
        BurpExtender.callbacks.registerHttpListener(coverage);

    }

    @Override
    public String getTabCaption() {
        return BurpExtender.name;
    }

    @Override
    public Component getUiComponent() {
        if (BurpExtender.isConnected) {
            this.logInfo("Connected to database, loading main GUI");
            return mainTabbedPane;
        } else {
            this.logInfo("Not connected to database, loading connection panel");
            return connectionPanel;
        }
    }

    // Loggers
    public void logInfo(String msg) {
        BurpExtender.callbacks.printOutput(String.format("[*] %s", msg));
    }
    
    public void logWarn(String msg) {
        BurpExtender.callbacks.printOutput(String.format("[!] %s", msg));
    }
    
    public void logError(String msg) {
        BurpExtender.callbacks.printError(String.format("[ERROR] %s", msg));
    }

}