package burp;

import com.rethinkdb.RethinkDB;
import com.rethinkdb.gen.ast.Table;
import com.rethinkdb.gen.exc.ReqlDriverError;
import com.rethinkdb.model.MapObject;
import com.rethinkdb.net.Connection;
import com.rethinkdb.net.Result;

import java.net.URL;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.DefaultListModel;

/**
 *
 * @author moloch
 */
public class Multiplayer implements IHttpListener, OnEditCallback {

    private static final RethinkDB r = RethinkDB.r;
    private static final String HTTPTable = "http";
    private Connection dbConn = null;
    private String dbHostname;
    private Integer dbPort;
    private String dbName;  // Database Name aka 'Project Name'
    
    private Integer dbCount;
    private Integer dbLoaded;
    private final List<OnLoadEventCallback> onLoadEventCallbacks = new ArrayList<>();
    
    private final IBurpExtenderCallbacks callbacks;
    private final BurpExtender extension;
    private final IExtensionHelpers helpers;
    private final ExecutorService executor = Executors.newFixedThreadPool(6);

    private Boolean sendToImpliesInProgress = true;
    private Boolean overwriteDuplicates = false;
    private Boolean uniqueQueryParameters = false;
    
    private final DefaultListModel<Pattern> ignoredURLPatterns = new DefaultListModel<>();
    
    private DefaultListModel<Integer> ignoredTools = new DefaultListModel<>();
    private final List<Integer> defaultIgnoredTools = new ArrayList<>(Arrays.asList(
        IBurpExtenderCallbacks.TOOL_SCANNER, IBurpExtenderCallbacks.TOOL_SPIDER,
        IBurpExtenderCallbacks.TOOL_INTRUDER, IBurpExtenderCallbacks.TOOL_REPEATER,
        IBurpExtenderCallbacks.TOOL_DECODER, IBurpExtenderCallbacks.TOOL_COMPARER,
        IBurpExtenderCallbacks.TOOL_EXTENDER, IBurpExtenderCallbacks.TOOL_SEQUENCER
    ));
    
    private DefaultListModel<String> ignoredExtensions = new DefaultListModel<>();
    private final List<String> defaultIgnoredExtensions = new ArrayList<>(Arrays.asList(
        "js", "woff", "woff2", "jpg", "jpeg", "png", "gif", "css", "txt"
    ));
    
    private DefaultListModel<String> ignoredStatusCodes = new DefaultListModel<>();
    private final List<String> defaultIgnoredStatusCodes = new ArrayList<>(Arrays.asList(
        "404"
    ));

    public HTTPHistory history;
    private final MultiplayerLogger logger;

    // Constructor
    public Multiplayer(BurpExtender extension, MultiplayerLogger logger) {
        this.history = new HTTPHistory(executor, logger);
        this.extension = extension;
        this.callbacks = logger.callbacks;
        this.logger = logger;
        this.helpers = callbacks.getHelpers();
        
        defaultIgnoredExtensions.forEach(ext -> {
            ignoredExtensions.addElement(ext);
        });
        defaultIgnoredStatusCodes.forEach(code -> {
            ignoredStatusCodes.addElement(code);
        });
        defaultIgnoredTools.forEach(toolFlag -> {
           ignoredTools.addElement(toolFlag); 
        });
    }
    
    // Database = Project Name
    public Boolean connect(String hostname, Integer port) {
        logger.info("Connecting to '%s:%d' ...", hostname, port);
        dbHostname = hostname;
        dbPort = port;
        try {
            dbConn = this.dbConnect();
        } catch (ReqlDriverError err) {
            logger.warn("Failed to connect to database: %s", err);
            throw err;
        }
        if (dbConn.isOpen()) {
            logger.debug("Successfully connected: %s", dbConn);
            return true;
        } else {
            return false;
        }
    }
    
    // This is a workaround because sometimes the RethinkDB cursor
    // hangs while loading the history. So executing it in another thread
    // at least prevents the entire app from locking up.
    public void initializeHistory() {
        executor.submit(() -> { initalizeHistory(); });
        logger.debug("History non-blocking initialize...");
    }
    
    public void startChangefeed() {
        logger.debug("Starting changefeed ...");
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
    }
    
    public List<String> getProjects() {
        if (isConnected()) {
            Result<Object> result = r.dbList().run(dbConn);
            return (ArrayList<String>) result.single();
        }
        return new ArrayList<>();
    }
    
    public void setProject(String projectName) {
        dbName = projectName;
        logger.debug("Database/project name: %s", projectName);
        Result<Object> result = r.dbList().run(dbConn);
        ArrayList<String> dbList = (ArrayList<String>) result.single();
        if (!dbList.contains(dbName)) {
            createDatabase();
        }
    }
    
    public void deleteProject(String projectName) {
        r.dbDrop(projectName).run(dbConn);
    }

    private void createDatabase() {
        logger.info("Database '%s' does not exist, initializing ...", dbName);
        
        // Create Database
        r.dbCreate(dbName).run(dbConn);
        
        // Create Table
        r.db(dbName).tableCreate(HTTPTable).run(dbConn);
        
        // Create Indexes
//        r.db(dbName).table(HTTPTable).indexCreate("protocol").run(dbConn);
//        r.db(dbName).table(HTTPTable).indexCreate("host").run(dbConn);
//        r.db(dbName).table(HTTPTable).indexCreate("port").run(dbConn);
//        r.db(dbName).table(HTTPTable).indexCreate("path").run(dbConn);
//        r.db(dbName).table(HTTPTable).indexCreate("method").run(dbConn);
//        r.db(dbName).table(HTTPTable).indexCreate("status").run(dbConn);
//        r.db(dbName).table(HTTPTable).indexCreate("highlight").run(dbConn);
    }
    
    private void initalizeHistory() {
        logger.debug("Initializing history ...");
        
        try {
            Result<Integer> countCursor = http().count().run(dbConnect(), Integer.class);
            dbCount = countCursor.single();
            logger.debug("Expect %d  results ...", dbCount);
            dbLoaded = 0;
            
            if (dbCount < 1) {
                triggerOnLoadEvent();
                return;
            }
            
            while (dbLoaded < dbCount) {
                Result<MultiplayerRequestResponse> result = http().skip(dbLoaded).limit(1).run(dbConn, MultiplayerRequestResponse.class);    
                MultiplayerRequestResponse entry = result.single();
                logger.debug("Got entry %d of %d: %s", dbLoaded, dbCount, entry);
                history.add(entry);
                dbLoaded++;
                triggerOnLoadEvent();
            }
            logger.debug("Results done.");
            
        } catch(Exception err) {
            logger.error(err);
        }
        
        logger.debug("History initialized");
    }

    public Boolean isConnected() {
        return dbConn != null ? dbConn.isOpen() : false;
    }
    
    public void disconnect() {
        dbConn.close();
        extension.disconnect();
    }
    
    public void setSendToImpliesInProgress(Boolean theImplication) {
        sendToImpliesInProgress = theImplication;
    }
    
    public Boolean getSendToImpliesInProgress() {
        return sendToImpliesInProgress;
    }
    
    // Ignore Tools
    public void addIgnoredTool(Integer toolFlag) {
        if (!ignoredTools.contains(toolFlag)) {
            ignoredTools.addElement(toolFlag);
        }
    }
    
    public void removeIgnoredTool(Integer toolFlag) {
        ignoredTools.removeElement(toolFlag);
    }
    
    public Boolean isIgnoredTool(Integer toolFlag) {
        return ignoredTools.contains(toolFlag);
    }
    
    public void clearIgnoredTools() {
        ignoredTools.removeAllElements();
    }

    public List<Integer> getIgnoredToolsList() {        
        List<Integer> ignoredToolsList = new ArrayList();
        Iterator<Integer> iter = ignoredTools.elements().asIterator();
        while (iter.hasNext()) {
            ignoredToolsList.add(iter.next());
        }
        return ignoredToolsList;
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
    
    public void clearIgnoredExtensions() {
        ignoredExtensions.removeAllElements();
    }

    private String getFileExtension(URL url) {
        String path = url.getPath();
        int index = path.lastIndexOf(".") + 1;
        if (index < path.length()) {
            return path.substring(index);
        }
        return "";
    }
    
    public List<String> getIgnoredFileExtensionsList() {
        List<String> ignoredExtsList = new ArrayList();
        Iterator<String> iter = ignoredExtensions.elements().asIterator();
        while (iter.hasNext()) {
            ignoredExtsList.add(iter.next());
        }
        return ignoredExtsList;
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
        } catch (NumberFormatException e) { }
    }
    
    public void removeIgnoredStatusCodes(String statusCode) {
        int index = ignoredStatusCodes.indexOf(statusCode);
        ignoredStatusCodes.remove(index);
    }
    
    public void clearIgnoredStatusCodes() {
        ignoredStatusCodes.removeAllElements();
    }

    public List<String> getIgnoredStatusCodesList() {
        List<String> ignoredStatusCodesList = new ArrayList();
        Iterator<String> iter = ignoredStatusCodes.elements().asIterator();
        while (iter.hasNext()) {
            ignoredStatusCodesList.add(iter.next());
        }
        return ignoredStatusCodesList;
    }
    
    // Ignore Patterns
    public void addIgnoredURLPattern(Pattern pattern) {
        ignoredURLPatterns.addElement(pattern);
    }
    
    public void removeIgnoredURLPattern(Pattern pattern) {
        ignoredURLPatterns.removeElement(pattern);
    }

    public DefaultListModel<Pattern> getIgnoredURLPatterns() {        
        return ignoredURLPatterns;
    }
    
    public List<String> getIgnoredURLPatternsList() {
        List<String> ignoredPatternsList = new ArrayList();
        Iterator<Pattern> iter = ignoredURLPatterns.elements().asIterator();
        while (iter.hasNext()) {
            ignoredPatternsList.add(iter.next().toString());
        }
        return ignoredPatternsList;
    }
    
    public void clearIgnoredURLPatterns() {
        ignoredURLPatterns.removeAllElements();
    }
    
    // Duplicates
    public void setOverwriteDuplicates(Boolean overwriteDuplicates) {
        this.overwriteDuplicates = overwriteDuplicates;
    }
    
    public Boolean getOverwriteDuplicates() {
        return overwriteDuplicates;
    }
    
    // Query parameters as unique
    public void setUniqueQueryParameters(Boolean uniqueQueryParameters) {
        this.uniqueQueryParameters = uniqueQueryParameters;
    }
    
    public Boolean getUniqueQueryParameters() {
        return uniqueQueryParameters;
    }

    // ---------------------
    //  Burp HTTP Callback
    // ---------------------
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse burpReqResp) { 
        if (!messageIsRequest) {
            IRequestInfo reqInfo = helpers.analyzeRequest(burpReqResp);
            IResponseInfo respInfo = helpers.analyzeResponse(burpReqResp.getResponse());
            URL url = reqInfo.getUrl();
            
            // Ignore scanner?
            if (isIgnoredTool(toolFlag)) {
                logger.debug("Ignore: tools (%d) '%s'", toolFlag, url);
                return;
            }
            
            // Is in-scope?
            if (!callbacks.isInScope(url)) {
                logger.debug("Ignore: out of scope '%s'", url);
                return;
            }
            
            // Is ignored response status?
            if (isIgnoredStatusCode(respInfo.getStatusCode())) {
                logger.debug("Ignore: status code (%d) '%s'", respInfo.getStatusCode(), url);
                return;
            }
            
            // Is ignored file extension?
            if (isIgnoredExtension(getFileExtension(url))) {
                logger.debug("Ignore: file ext (%s) '%s'", getFileExtension(url), url);
                return;
            }
            
            // Is ignored URL pattern?
            if (0 < ignoredURLPatterns.size()) {
                for (int index = 0; index < ignoredURLPatterns.size(); ++index) {
                    Pattern pattern = ignoredURLPatterns.getElementAt(index);
                    Matcher matcher = pattern.matcher(url.toString());
                    if (matcher.find()) {
                        logger.debug("Ignore: url pattern %s '%s'", pattern, url);
                        return;
                    }
                }
            }
            
            if (!isDuplicate(burpReqResp) || overwriteDuplicates) {
                http().insert(reqRespToRethink(burpReqResp)).run(dbConn);
            } else {
                logger.debug("Ignore: duplicate request '%s'", url);
            }

        }
    }
    
    public void reqRespRemove(String reqRespId) {
        http().get(reqRespId).delete().runNoReply(dbConn);
    }
    
    public Boolean isDuplicate(IHttpRequestResponse reqResp) {
        Result<Object> result = http().get(getReqRespID(reqResp)).run(dbConn);
        return result.first() != null;
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
    // optionally include query as unique
    private String getReqRespID(IHttpRequestResponse reqResp) {
        IRequestInfo reqInfo = helpers.analyzeRequest(reqResp);
        URL url = reqInfo.getUrl();
        String urlParts = String.format("%s>%s>%s", url.getProtocol(), url.getAuthority(), url.getPath());
        if (uniqueQueryParameters) {
            urlParts = String.format("%s>%s", urlParts, url.getQuery());
        }
        String rawID = String.format("%s>%s", reqInfo.getMethod(), urlParts);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(rawID.getBytes());
            StringBuilder builder = new StringBuilder();
            for (byte data : md.digest()) {
                builder.append(String.format("%02x", data));
            }
            return builder.toString();
        } catch (Exception err) {
            logger.error(err);
        }
        return "";
    }
    
    // Database Helpers
    private Table http() {
        return r.db(dbName).table(HTTPTable);
    }
    
    private Connection dbConnect() {
        return r.connection().hostname(dbHostname).port(dbPort).connect();
    }
    
    public void registerOnLoadEventCallback(OnLoadEventCallback callback) {
        onLoadEventCallbacks.add(callback);
    }
    
    public void unregisterOnLoadEventCallback(OnLoadEventCallback callback) {
        onLoadEventCallbacks.remove(callback);
    }
    
    private void triggerOnLoadEvent() {
        onLoadEventCallbacks.forEach(callback -> {
            executor.submit(() -> { callback.onLoad(dbLoaded, dbCount); });
        });
    }

    @Override
    public void onEdit(String id, String field, Object value) {
        http().get(id).update(r.hashMap(field.toLowerCase(), value)).run(dbConn);
    }
   
}
