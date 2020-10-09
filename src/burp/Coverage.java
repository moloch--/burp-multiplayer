package burp;

import com.rethinkdb.RethinkDB;
import com.rethinkdb.gen.ast.Table;
import com.rethinkdb.gen.exc.ReqlDriverError;
import com.rethinkdb.model.MapObject;
import com.rethinkdb.net.Connection;
import com.rethinkdb.net.Cursor;

import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 *
 * @author moloch
 */
public class Coverage implements IHttpListener {

    private static final RethinkDB r = RethinkDB.r;
    private static final String HTTPTable = "http";
    private Connection dbConn = null;
    private String dbName;  // Database Name aka 'Project Name'
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ExecutorService executor = Executors.newFixedThreadPool(4);
    private ConcurrentHashMap<String, CoverageRequestResponse> work;
    private List<Runnable> changeCallbacks = new ArrayList<Runnable>();
    
    private Boolean respectScope = true;
    private Set<String> ignoredExtensions = new HashSet<String>();
    private Set<Integer> ignoredStatusCodes = new HashSet<Integer>();

    // Constructor
    public Coverage(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
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
            List<String> dbList = r.dbList().run(dbConn);
            if (!dbList.contains(dbName)) {
                createDatabase();
            }

            executor.submit(() -> {
                Cursor<HashMap> changeCursor = http().changes().run(dbConn);
                for (HashMap change : changeCursor) {
                    HashMap entry = (HashMap) change.get("new_val");
                    String id = (String) entry.get("id");
                    CoverageRequestResponse reqResp = new CoverageRequestResponse(callbacks);
                    reqResp.setRequest(helpers.base64Decode((String) entry.get("request")));
                    reqResp.setResponse(helpers.base64Decode((String) entry.get("response")));
                    work.put(id, reqResp);
                    for (Runnable callback : changeCallbacks) {
                        executor.submit(callback);
                    }
                }
            });
            
            return true;
        } else {
            return false;
        }
    }
    
    public void registerChangeCallback(Runnable callback) {
        changeCallbacks.add(callback);
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
    }
    
    public Boolean IsConnected() {
        return dbConn != null ? dbConn.isOpen() : false;
    }
    
    public void setRespectScope(Boolean respectScope) {
        this.respectScope = respectScope;
    }
    
    // Ignored File Extensions
    public String[] getIgnoreExtensions() {
        return (String[]) ignoredExtensions.toArray();
    }
    
    public Boolean isIgnoredExtension(String fileExtension) {
        return ignoredExtensions.contains(fileExtension.toLowerCase());
    }
    
    public void addIgnoredExtension(String fileExtension) {
        ignoredExtensions.add(fileExtension.toLowerCase());
    }
    
    public void removeIgnoredExtension(String fileExtension) {
        ignoredExtensions.remove(fileExtension.toLowerCase());
    }
    
    // Ignored Status Codes
    public Integer[] getIgnoredStatusCodes() {
        return (Integer[]) ignoredStatusCodes.toArray();
    }
    
    public Boolean isIgnoredStatusCodes(Integer statusCode) {
        return ignoredStatusCodes.contains(statusCode);
    }
    
    public void addIgnoredStatusCodes(Integer statusCode) {
        ignoredStatusCodes.add(statusCode);
    }
    
    public void removeIgnoredStatusCodes(Integer statusCode) {
        ignoredStatusCodes.remove(statusCode);
    }

    // Burp HTTP Callback
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse reqResp) { 
        if (!messageIsRequest) {
            IRequestInfo reqInfo = helpers.analyzeRequest(reqResp);
            URL url = reqInfo.getUrl();
            if (!respectScope || callbacks.isInScope(url)) {
                http().insert(r.array(
                    requestResponseToJSON(reqResp)
                )).run(dbConn);
            }
        }
    }

    private MapObject requestResponseToJSON(IHttpRequestResponse reqResp) {
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
            .with("request", helpers.base64Encode(reqResp.getRequest()))
            .with("response", helpers.base64Encode(reqResp.getResponse()));
    }
    
    // Creates an ID for a req/resp object (METHOD.PROTOCOL.AUTHORITY.PATH)
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
