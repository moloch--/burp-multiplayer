/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

/**
 *
 * @author moloch
 */
public class HTTPMessageEditor implements IMessageEditorController {

    private MultiplayerRequestResponse reqResp;
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    
    public HTTPMessageEditor(MultiplayerRequestResponse reqResp, IBurpExtenderCallbacks callbacks) {
        this.reqResp = reqResp;
        
        // Request Editor
        requestEditor = callbacks.createMessageEditor(this, false);
        requestEditor.setMessage(reqResp.getRequest(), true);
        
        // Response Editor
        responseEditor = callbacks.createMessageEditor(this, false);
        responseEditor.setMessage(reqResp.getResponse(), false);
    }
    
    public IMessageEditor getRequestEditor() {
        return requestEditor;
    }
    
    public IMessageEditor getResponseEditor() {
        return responseEditor;
    }
    
    @Override
    public IHttpService getHttpService() {
        return reqResp.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return reqResp.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return reqResp.getResponse();
    }
    
}
