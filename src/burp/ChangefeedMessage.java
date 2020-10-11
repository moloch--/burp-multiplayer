/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author moloch
 */
public class ChangefeedMessage {
    
    private MultiplayerRequestResponse newValue;
    private MultiplayerRequestResponse oldValue;
    
    @JsonProperty("new_val")
    public void setNewVal(MultiplayerRequestResponse newValue) {
        this.newValue = newValue;
    }
    
    public MultiplayerRequestResponse getNewVal() {
        return newValue;
    }
    
    @JsonProperty("old_val")
    public void setOldVal(MultiplayerRequestResponse oldValue) {
        this.oldValue = oldValue;
    }
    
    public MultiplayerRequestResponse getOldVal() {
        return oldValue;
    }
    
}
