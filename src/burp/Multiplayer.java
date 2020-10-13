package burp;

import com.rethinkdb.RethinkDB;
import com.rethinkdb.gen.ast.Table;
import com.rethinkdb.gen.exc.ReqlDriverError;
import com.rethinkdb.model.MapObject;
import com.rethinkdb.net.Connection;
import com.rethinkdb.net.Result;

import java.net.URL;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.swing.DefaultListModel;

/**
 *
 * @author moloch
 */
public class Multiplayer implements IHttpListener, OnEditCallback {

    private static final RethinkDB r = RethinkDB.r;
    private static final String HTTPTable = "http";
    private Connection dbConn = null;
    private String dbName;  // Database Name aka 'Project Name'
    
    private IBurpExtenderCallbacks callbacks;
    private BurpExtender extension;
    private IExtensionHelpers helpers;
    private ExecutorService executor = Executors.newFixedThreadPool(4);

    private Boolean respectScope = true;
    private Boolean ignoreScanner = true;
    
    private DefaultListModel<String> ignoredExtensions = new DefaultListModel<>();
    private List<String> defaultIgnoredExtensions = new ArrayList<String>(Arrays.asList(
        "js", "woff", "woff2", "jpg", "jpeg", "png", "gif", "css", "txt"
    ));
    
    private DefaultListModel<String> ignoredStatusCodes = new DefaultListModel<>();
    private final List<String> defaultIgnoredStatusCodes = new ArrayList<String>(Arrays.asList(
        "404"
    ));

    public HTTPHistory history;

    // Constructor
    public Multiplayer(BurpExtender extension, IBurpExtenderCallbacks callbacks) {
        this.history = new HTTPHistory(executor, callbacks);
        this.extension = extension;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        defaultIgnoredExtensions.forEach(ext -> {
            ignoredExtensions.addElement(ext);
        });
        defaultIgnoredStatusCodes.forEach(code -> {
            ignoredStatusCodes.addElement(code);
        });
    }
    
    // Database = Project Name
    public Boolean Connect(String hostname, Integer port, String database) {
        this.logInfo(String.format("Connecting to '%s:%d/%s' ...", hostname, port, database));
        try {
            this.dbConn = r.connection().hostname(hostname).port(port).connect();
        } catch (ReqlDriverError err) {
            this.logWarn(String.format("Failed to connect to database: %s", err));
        }
        if (dbConn.isOpen()) {
            logInfo(String.format("Successfully connected: %s", dbConn));
            dbName = database;
            
            Result<Object> result = r.dbList().run(dbConn);
            ArrayList<String> dbList = (ArrayList<String>) result.single();
            if (!dbList.contains(dbName)) {
                createDatabase();
            }

            initalizeHistory();
            history.registerOnEditCallback(this);
            
            executor.submit(() -> {
                Result<ChangefeedMessage> changes = http().changes().run(dbConn, ChangefeedMessage.class);
                for (ChangefeedMessage msg : changes) {
                    if (msg.getNewVal() != null) {
                        history.add(msg.getNewVal());
                    } else if (msg.getNewVal() == null && msg.getOldVal() != null) {
                        history.remove(msg.getOldVal().getId());
                    }
                }
            });
            callbacks.printOutput("Connected!");
            return true;
        } else {
            return false;
        }
    }

    private void createDatabase() {
        logInfo(String.format("Database '%s' does not exist, initializing ...", dbName));
        
        // Create Database
        r.dbCreate(dbName).run(dbConn);
        
        // Create Table
        r.db(dbName).tableCreate(HTTPTable).run(dbConn);
        
        // Create Indexes
        r.db(dbName).table(HTTPTable).indexCreate("protocol").run(dbConn);
        r.db(dbName).table(HTTPTable).indexCreate("host").run(dbConn);
        r.db(dbName).table(HTTPTable).indexCreate("port").run(dbConn);
        r.db(dbName).table(HTTPTable).indexCreate("path").run(dbConn);
        r.db(dbName).table(HTTPTable).indexCreate("method").run(dbConn);
        r.db(dbName).table(HTTPTable).indexCreate("status").run(dbConn);
        r.db(dbName).table(HTTPTable).indexCreate("highlight").run(dbConn);
    }
    
    private void initalizeHistory() {
        logInfo("Initializing history ...");
        Result<MultiplayerRequestResponse> result = http().run(dbConn, MultiplayerRequestResponse.class);
        while (result.hasNext()) {
            MultiplayerRequestResponse entry = result.next();
            history.add(entry);
        }
        logInfo("History initialized");
    }
    
    public Boolean IsConnected() {
        return dbConn != null ? dbConn.isOpen() : false;
    }
    
    public void disconnect() {
        dbConn.close();
        extension.disconnect();
    }
    
    public void setRespectScope(Boolean respectScope) {
        this.respectScope = respectScope;
    }
    
    // Ignored File Extensions
    public DefaultListModel<String> getIgnoreExtensions() {
        return ignoredExtensions;
    }
    
    public Boolean isIgnoredExtension(String fileExtension) {
        return ignoredExtensions.contains(fileExtension.toLowerCase());
    }
    
    public void addIgnoredExtension(String fileExtension) {
        ignoredExtensions.addElement(fileExtension.toLowerCase());
    }
    
    public void removeIgnoredExtension(String fileExtension) {
        int index = ignoredExtensions.indexOf(fileExtension);
        ignoredExtensions.remove(index);
    }
    
    // Ignored Status Codes
    public DefaultListModel<String> getIgnoredStatusCodes() {        
        return ignoredStatusCodes;
    }
    
    public Boolean isIgnoredStatusCode(short statusCode) {
        return ignoredStatusCodes.contains(String.format("%d", statusCode));
    }
    
    public void addIgnoredStatusCodes(String statusCode) {
        try {
            Integer code = Integer.parseInt(statusCode);
            if (code < 0 || 999 < code) {
                return;
            }
            ignoredStatusCodes.addElement(statusCode);
        } catch(NumberFormatException e) {
            return;
        }
    }
    
    public void removeIgnoredStatusCodes(String statusCode) {
        int index = ignoredStatusCodes.indexOf(statusCode);
        ignoredStatusCodes.remove(index);
    }

    // Burp HTTP Callback
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse burpReqResp) { 
        if (!messageIsRequest) {
            IRequestInfo reqInfo = helpers.analyzeRequest(burpReqResp);
            IResponseInfo respInfo = helpers.analyzeResponse(burpReqResp.getResponse());
            URL url = reqInfo.getUrl();
            
            // Ignore tools? TODO: Make configurable
            if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) {
                callbacks.printOutput(String.format("Ignore: tools (%d)", toolFlag));
                return;
            }
            
            // Is in-scope?
            if (respectScope && !callbacks.isInScope(url)) {
                callbacks.printOutput("Ignore: scope");
                return;
            }
            
            // Is ignored response status?
            if (isIgnoredStatusCode(respInfo.getStatusCode())) {
                callbacks.printOutput(String.format("Ignore: status code (%d)", respInfo.getStatusCode()));
                return;
            }
            
            // Is ignored file extension?
            if (isIgnoredExtension(getFileExtension(url))) {
                callbacks.printOutput(String.format("Ignore: file ext (%s)", getFileExtension(url)));
                return;
            }

            http().insert(reqRespToRethink(burpReqResp)).run(dbConn);
        }
    }
    
    public void reqRespRemove(String reqRespId) {
        http().get(reqRespId).delete().run(dbConn);
    }
    
    public Boolean reqRespExists(IHttpRequestResponse reqResp) {
        return http().get(getReqRespID(reqResp)).run(dbConn) != null;
    }

    private MapObject reqRespToRethink(IHttpRequestResponse reqResp) {
        IRequestInfo reqInfo = helpers.analyzeRequest(reqResp);
        IResponseInfo respInfo = helpers.analyzeResponse(reqResp.getResponse());
        URL url = reqInfo.getUrl();
        return r.hashMap("id", getReqRespID(reqResp))
            .with("protocol", url.getProtocol())
            .with("host", url.getHost())
            .with("port",  url.getPort())
            .with("path", url.getPath())
            .with("method", reqInfo.getMethod())
            .with("status", respInfo.getStatusCode())
            .with("comment", "")
            .with("highlight", "")
            .with("assessment", "")
            .with("time", Instant.now().getEpochSecond())
            .with("request", r.binary(reqResp.getRequest()))
            .with("response", r.binary(reqResp.getResponse()));
    }
    
    // Creates an ID for a req/resp object (METHOD>PROTOCOL>AUTHORITY>PATH)
    private String getReqRespID(IHttpRequestResponse reqResp) {
        IRequestInfo reqInfo = helpers.analyzeRequest(reqResp);
        URL url = reqInfo.getUrl();
        String urlParts = String.format("%s>%s>%s", url.getProtocol(), url.getAuthority(), url.getPath());
        return String.format("%s>%s", reqInfo.getMethod(), urlParts);
    }
    
    // Database Helpers
    private Table http() {
        return r.db(dbName).table(HTTPTable);
    }

    @Override
    public void onEdit(String id, String field, Object value) {
        http().get(id).update(r.hashMap(field.toLowerCase(), value)).run(dbConn);
    }
    
    private String getFileExtension(URL url) {
        String path = url.getPath();
        int index = path.lastIndexOf(".") + 1;
        if (index < path.length()) {
            return path.substring(index);
        }
        return "";
    }
    
    // Loggers
    public void logInfo(String msg) {
        this.callbacks.printOutput(String.format("[*] %s", msg));
    }
    
    public void logWarn(String msg) {
        this.callbacks.printOutput(String.format("[!] %s", msg));
    }
    
    public void logError(String msg) {
        this.callbacks.printError(String.format("[ERROR] %s", msg));
    }

}
