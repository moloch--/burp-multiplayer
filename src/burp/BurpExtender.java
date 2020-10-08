package burp;

import burp.gui.CoverageRootPanel;
import burp.gui.ConnectionPanel;
import burp.gui.MainPanel;
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
            BurpExtender.rootPanel.remove(connectionPanel);
            
            MainPanel mainPanel = new MainPanel(BurpExtender.coverage);
            BurpExtender.rootPanel.add(mainPanel);
            
            // HTTP Listener
            BurpExtender.coverage = new Coverage(BurpExtender.callbacks);
            BurpExtender.callbacks.registerHttpListener(coverage);
            
            BurpExtender.rootPanel.repaint();
            BurpExtender.rootPanel.revalidate();
        });
        
        // Register us as the main ITab
        BurpExtender.callbacks.addSuiteTab(BurpExtender.this);
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