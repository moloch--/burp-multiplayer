package burp;

import com.rethinkdb.RethinkDB;
// import com.rethinkdb.gen.exc.ReqlError;
// import com.rethinkdb.gen.exc.ReqlQueryLogicError;
// import com.rethinkdb.model.MapObject;
// import com.rethinkdb.net.Connection;


public class Coverage implements IHttpListener {

    private static final RethinkDB r = RethinkDB.r;
    private IBurpExtenderCallbacks callbacks;

    public Coverage(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        
        callbacks.printOutput(String.format("[http] toolFlag: %i messageIsRequest: %s messageInfo: %s", 
            toolFlag, messageIsRequest, messageInfo));

    }
    
}
