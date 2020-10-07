package burp;

import com.rethinkdb.RethinkDB;
import com.rethinkdb.gen.exc.ReqlDriverError;
// import com.rethinkdb.gen.exc.ReqlError;
// import com.rethinkdb.gen.exc.ReqlQueryLogicError;
// import com.rethinkdb.model.MapObject;
import com.rethinkdb.net.Connection;


public class Coverage implements IHttpListener {

    private static final RethinkDB r = RethinkDB.r;
    private IBurpExtenderCallbacks callbacks;
    private Connection dbConn = null;

    public Coverage(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    // Database = Project Name
    public Boolean Connect(String hostname, Integer port, String database) {
        this.logInfo(String.format("Connecting to '%s:%d/%s' ...", hostname, port, database));
        try {
            dbConn = r.connection().hostname(hostname).port(port).connect();
        } catch (ReqlDriverError err) {
            this.logWarn(String.format("Failed to connect to database: %s", err));
        }
        if (dbConn.isOpen()) {
            this.logInfo("Successfully connected to database");
            String[] databases = r.dbList().run(dbConn);
            this.logInfo(String.format("Databases: %s", databases));
            return true;
        } else {
            return false;
        }
    }
    
    public Boolean IsConnected() {
        return dbConn != null ? dbConn.isOpen() : false;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
        this.logInfo(String.format("[http] toolFlag: %i messageIsRequest: %s messageInfo: %s", 
            toolFlag, messageIsRequest, messageInfo));

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
