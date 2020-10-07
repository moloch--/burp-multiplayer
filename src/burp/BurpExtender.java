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
        BurpExtender.callbacks.printOutput("[*] Coverage plugin loading ...");
        BurpExtender.callbacks.setExtensionName(BurpExtender.name);
        BurpExtender.mainTabbedPane = new JTabbedPane();

        // Build Tab Panels
        BurpExtender.connectionPanel = new ConnectionPanel(); 
        mainTabbedPane.addTab("Connection", BurpExtender.connectionPanel);


        // Register Root Tab
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
        return mainTabbedPane;
    }


}