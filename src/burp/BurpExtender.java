package burp;

import burp.gui.MultiplayerRootPanel;
import burp.gui.ConnectionPanel;
import burp.gui.LoadingPanel;
import burp.gui.MainPanel;
import java.awt.Component;
import javax.swing.JPanel;

/**
 *
 * @author moloch
 */
public class BurpExtender implements IBurpExtender, ITab {

    private static IBurpExtenderCallbacks callbacks;
    private static JPanel rootPanel;
    
    private static final String name = "Multiplayer";
    private static MainPanel mainPanel;

    private static Multiplayer multiplayer;
    private static MultiplayerLogger logger;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.logger = new MultiplayerLogger(callbacks);
        String logLevel = callbacks.loadExtensionSetting("multiplayer.logLevel");
        if (logLevel != null) {
            BurpExtender.logger.info("Log Level -> %s", logLevel);
            BurpExtender.logger.setLevel(logLevel);
        }
        logger.info("Multiplayer plugin loading ...");
        BurpExtender.callbacks.setExtensionName(BurpExtender.name);
        
        try {
            main();
        } catch (Exception err) {
            logger.error(err);
        }

        // Register us as the main ITab
        BurpExtender.callbacks.addSuiteTab(BurpExtender.this);
    }
    
    public void main() {
        try {

            BurpExtender.multiplayer = new Multiplayer(this, logger);
            
            // Root Panel
            // If we diconnect/re-connect rootPanel will already exist
            if (BurpExtender.rootPanel == null) {
                BurpExtender.rootPanel = new MultiplayerRootPanel();    
            }
            
            // ConnectionPanel
            ConnectionPanel connectionPanel = new ConnectionPanel(multiplayer, logger);
            LoadingPanel loadingPanel = new LoadingPanel(multiplayer, logger);
            BurpExtender.rootPanel.add(connectionPanel);

            connectionPanel.onConnection(() -> {
                logger.debug("onConnection()");
                BurpExtender.rootPanel.remove(connectionPanel);
                
                BurpExtender.rootPanel.add(loadingPanel);             
                BurpExtender.rootPanel.repaint();
                BurpExtender.rootPanel.revalidate();
                loadingPanel.initialize();
                loadingPanel.registerOnCompleteCallback(() -> {
                    BurpExtender.rootPanel.remove(loadingPanel);
                    BurpExtender.mainPanel = new MainPanel(multiplayer, logger);
                    BurpExtender.rootPanel.add(mainPanel);

                    // HTTP Listener
                    BurpExtender.callbacks.registerHttpListener(multiplayer);
                    BurpExtender.rootPanel.repaint();
                    BurpExtender.rootPanel.revalidate();    
                });
                
            });
            
            BurpExtender.rootPanel.repaint();
            BurpExtender.rootPanel.revalidate();
        } catch (Exception err) {
            BurpExtender.logger.error("%s", err);
        }
        
    }
    
    public void disconnect() {
        try {
            BurpExtender.rootPanel.remove(mainPanel);
            BurpExtender.callbacks.removeHttpListener(multiplayer);
            main();
        } catch (Exception err) {
            BurpExtender.logger.error("%s", err);
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

}
