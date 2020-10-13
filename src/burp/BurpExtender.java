package burp;

import burp.gui.MultiplayerRootPanel;
import burp.gui.ConnectionPanel;
import burp.gui.MainPanel;
import java.awt.Component;
import javax.swing.JPanel;

/**
 *
 * @author moloch
 */
public class BurpExtender implements IBurpExtender, ITab {

    private static final String name = "Multiplayer";
    private static IBurpExtenderCallbacks callbacks;
    private static JPanel rootPanel;
    private static MainPanel mainPanel;

    private static Multiplayer multiplayer;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        this.logInfo("Multiplayer plugin loading ...");
        BurpExtender.callbacks.setExtensionName(BurpExtender.name);
        
        main();

        // Register us as the main ITab
        BurpExtender.callbacks.addSuiteTab(BurpExtender.this);
    }
    
    public void main() {
        try {

            BurpExtender.multiplayer = new Multiplayer(this, callbacks);
            
            // Root Panel
            if (BurpExtender.rootPanel == null) {
                BurpExtender.rootPanel = new MultiplayerRootPanel();    
            }
            
            // ConnectionPanel
            ConnectionPanel connectionPanel = new ConnectionPanel(multiplayer, callbacks);
            BurpExtender.rootPanel.add(connectionPanel);
            
            connectionPanel.onConnection(() -> {
                BurpExtender.rootPanel.remove(connectionPanel);

                BurpExtender.mainPanel = new MainPanel(multiplayer, callbacks);
                BurpExtender.rootPanel.add(mainPanel);

                // HTTP Listener
                BurpExtender.callbacks.registerHttpListener(multiplayer);

                BurpExtender.rootPanel.repaint();
                BurpExtender.rootPanel.revalidate();
            });
            
            BurpExtender.rootPanel.repaint();
            BurpExtender.rootPanel.revalidate();
        } catch (Exception err) {
            callbacks.printError(String.format("%s", err));
        }
        
    }
    
    public void disconnect() {
        try {
            BurpExtender.rootPanel.remove(mainPanel);
            BurpExtender.callbacks.removeHttpListener(multiplayer);
            main();
        } catch (Exception err) {
            callbacks.printError(String.format("%s", err));
        }
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
