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
public class MultiplayerHttpService implements IHttpService {
    
    private String host;
    private int port;
    private String protocol;

    public void setHost(String host) {
        this.host = host;
    }
    
    @Override
    public String getHost() {
        return host;
    }
    
    public void setPort(int port) {
        this.port = port;
    }

    @Override
    public int getPort() {
        return port;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
    
    @Override
    public String getProtocol() {
        return protocol;
    }
    
}
