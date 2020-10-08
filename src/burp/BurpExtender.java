package burp;

import java.awt.Component;

import javax.swing.JPanel;


public class BurpExtender implements IBurpExtender, ITab {

    private static final String name = "Coverage";
    private static IBurpExtenderCallbacks callbacks;
    private static JPanel rootPanel;
    
    private static Coverage coverage;
    

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        this.logInfo("Coverage plugin loading ...");
        BurpExtender.callbacks.setExtensionName(BurpExtender.name);
        BurpExtender.coverage = new Coverage(callbacks);
        
        // Root Panel
        BurpExtender.rootPanel = new CoverageRootPanel();
        
        // ConnectionPanel
        ConnectionPanel connectionPanel = new ConnectionPanel(BurpExtender.coverage);
        BurpExtender.rootPanel.add(connectionPanel);  
        connectionPanel.onConnection(() -> {
            this.logInfo("Connection callback!");
            BurpExtender.rootPanel.remove(connectionPanel);
        });
        
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
        return rootPanel;
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