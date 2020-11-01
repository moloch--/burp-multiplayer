/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp.version;

import burp.MultiplayerLogger;
import java.util.Objects;

/**
 *
 * @author moloch
 */
public class MultiplayerSemanticVersion {
    
    private Integer major;
    private Integer minor;
    private Integer patch;
    
    public MultiplayerSemanticVersion() {}
    
    public static MultiplayerSemanticVersion mySemanticVerion() {
        String compiledVersion[] = MultiplayerVersion.VERSION.split("\\.");

        MultiplayerSemanticVersion semVer = new MultiplayerSemanticVersion();
        
        if (1 <= compiledVersion.length) {
            semVer.setMajor(Integer.parseInt(compiledVersion[0]));
        } else {
            semVer.setMajor(0);
        }
        
        if (2 <= compiledVersion.length) {
            semVer.setMinor(Integer.parseInt(compiledVersion[1]));
        } else {
            semVer.setMinor(0);
        }
        
        if (3 <= compiledVersion.length) {
            semVer.setPatch(Integer.parseInt(compiledVersion[2]));
        } else {
            semVer.setPatch(0);
        }
        
        return semVer;
    }
    
    public void setMajor(Integer major) {
        this.major = major;
    }
    
    public Integer getMajor() {
        return major;
    }
    
    public void setMinor(Integer minor) {
        this.minor = minor;
    }
    
    public Integer getMinor() {
        return minor;
    }
    
    public void setPatch(Integer patch) {
        this.patch = patch;
    }
    
    public Integer getPatch() {
        return patch;
    }

    public Boolean isCompatible(MultiplayerSemanticVersion other) {
        return Objects.equals(this.getMajor(), other.getMajor()) && other.getMinor() <= this.getMinor();
    }
    
}
