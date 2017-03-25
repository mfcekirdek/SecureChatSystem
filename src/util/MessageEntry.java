package util;

import java.io.Serializable;

public class MessageEntry implements Serializable{
  
  private String userName;
  private String encryptedMsg;
  
  
  public MessageEntry(String userName, String encryptedMsg) {
    this.userName = userName;
    this.encryptedMsg = encryptedMsg;
  }
    
  public String getUserName() {
    return userName;
  }
  public void setUserName(String userName) {
    this.userName = userName;
  }
  public String getEncryptedMsg() {
    return encryptedMsg;
  }
  public void setEncryptedMsg(String encryptedMsg) {
    this.encryptedMsg = encryptedMsg;
  }
  
  

}
