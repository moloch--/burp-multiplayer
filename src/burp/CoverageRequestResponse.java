/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.net.URL;

/**
 *
 * @author moloch
 */
public class CoverageRequestResponse implements IHttpRequestResponse {
    
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private IHttpService httpService;
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    public CoverageRequestResponse(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public IRequestInfo getRequestInfo() {
        return helpers.analyzeRequest(this);
    }
    
    public IResponseInfo getResponseInfo() {
        return helpers.analyzeResponse(this.getResponse());
    }
    
    public URL getURL() {
        return this.getRequestInfo().getUrl();
    }
    
    // Interface Methods
    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] request) {
        this.request = request;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] response) {
        this.response = response;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String highlight) {
        this.highlight = highlight;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
    }
    
}
