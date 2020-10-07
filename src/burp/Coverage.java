package burp;

import com.rethinkdb.RethinkDB;
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
    
    public Boolean Connect(String hostname, Integer port, String database) {
        Connection dbConn = r.connection().hostname(hostname).port(port).connect();
        if (dbConn.isOpen()) {
            String[] databases = r.dbList().run(dbConn);
            this.callbacks.printOutput(String.format("Databases: %s", databases));
            return true;
        }
        return false;
    }
    
    public Boolean IsConnected() {
        return dbConn != null ? dbConn.isOpen() : false;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
        callbacks.printOutput(String.format("[http] toolFlag: %i messageIsRequest: %s messageInfo: %s", 
            toolFlag, messageIsRequest, messageInfo));

    }
    
}
