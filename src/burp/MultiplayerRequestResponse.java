/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import static burp.HTTPHistory.Assessment;
import static burp.HTTPHistory.Comment;
import static burp.HTTPHistory.DateTime;
import static burp.HTTPHistory.Highlight;
import static burp.HTTPHistory.Host;
import static burp.HTTPHistory.ID;
import static burp.HTTPHistory.Method;
import static burp.HTTPHistory.New;
import static burp.HTTPHistory.None;
import static burp.HTTPHistory.Path;
import static burp.HTTPHistory.Port;
import static burp.HTTPHistory.Protocol;
import static burp.HTTPHistory.StatusCode;
import java.net.URL;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;


/**
 *
 * @author moloch
 */
public class MultiplayerRequestResponse implements IHttpRequestResponse, Comparable<MultiplayerRequestResponse>  {
    
    private String id;
    
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;
    private String method;
    private String path;
    private String assessment;
    private int status;
    private long time;

    private MultiplayerHttpService httpService = new MultiplayerHttpService();

    public IRequestInfo getRequestInfo(IExtensionHelpers helpers) {
        IRequestInfo info = helpers.analyzeRequest(this);
        return info;
    }
    
    public IResponseInfo getResponseInfo(IExtensionHelpers helpers) {
        return helpers.analyzeResponse(this.getResponse());
    }
    
    public URL getURL(IExtensionHelpers helpers) {
        return getRequestInfo(helpers).getUrl();
    }
    
    /* Getters & Setters */
    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }
    
    public void setMethod(String method) {
        this.method = method;
    }
    
    public String getMethod() {
        return method;
    }
    
    public void setPath(String path) {
        this.path = path;
    }
    
    public String getPath() {
        return path;
    }
    
    public void setStatus(int status) {
        this.status = status;
    }
    
    public int getStatus() {
        return status;
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
    
    public void setAssessment(String assessment) {
        this.assessment = assessment;
    }
    
    public String getAssessment() {
        return assessment;
    }
    
    public void setTime(long time) {
        this.time = time;
    }
    
    public Long getTime() {
        return time;
    }
    
    public String getDateTime() {
        Instant instant = Instant.ofEpochSecond(time);
        DateTimeFormatter formatter = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT)
                                                       .withZone(ZoneId.systemDefault());
        return formatter.format(instant);
    }
    
    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.httpService = new MultiplayerHttpService();
        this.httpService.setHost(httpService.getHost());
        this.httpService.setPort(httpService.getPort());
        this.httpService.setProtocol(httpService.getProtocol());
    }
    
    public void setHost(String host) {
        httpService.setHost(host);
    }
    
    public String getHost() {
        return httpService.getHost();
    }
    
    public void setPort(int port) {
        httpService.setPort(port);
    }

    public Integer getPort() {
        return httpService.getPort();
    }

    public void setProtocol(String protocol) {
        httpService.setProtocol(protocol);
    }

    public String getProtocol() {
        return httpService.getProtocol();
    }

    @Override
    public int compareTo(MultiplayerRequestResponse other) {
        if (other.id.equals(this.id)) {
            return 0;
        }
        return other.hashCode() - this.hashCode();
    }
    
    public boolean equals(MultiplayerRequestResponse other) {
        return other.id.equals(this.id);
    }
    
    @Override
    public String toString() {
        return String.format("<id: %s, method: %s, protocol: %s, host: %s, port: %d, path: %s, comment: %s>", 
                id, method, getProtocol(), getHost(), getPort(), getPath(), comment);
    }
    
    
    public Object getProperty(String propertyName) {
        switch(propertyName) {
            case ID:
                return this.getId();
            case Method:
                return this.getMethod();
            case Protocol:
                return this.getProtocol();
            case Host:
                return this.getHost();
            case Path:
                return this.getPath();
            case Port:
                return this.getPort();
            case StatusCode:
                return this.getStatus();
            case Comment:
                return this.getComment();
            case Highlight:
                String highlightState = this.getHighlight();
                if (highlightState.isBlank() || highlightState.isEmpty()) {
                    return None;
                }
                return highlightState;
            case Assessment:
                String assessmentState = this.getAssessment();
                if (assessmentState.isBlank() || assessmentState.isEmpty()) {
                    return New;
                }
                return assessmentState;
            case DateTime:
                return this.getDateTime();
                
        }
        return null;
    }
}
