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
public interface OnEditCallback {
    
    public void onEdit(String id, String field, Object value);
    
}
