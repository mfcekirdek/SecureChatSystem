// ChatClient.java
//
// Modified 1/30/2000 by Alan Frindell
// Last modified 2/18/2003 by Ting Zhang
// Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
// Chat Client starter application.
package client;


// AWT/Swing

import java.awt.CardLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
// Java
import java.io.PrintWriter;
import java.math.BigInteger;
// socket
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.AccessControlException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
// Crypto
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;

import javax.swing.JFrame;
import javax.swing.JTextArea;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import server.ChatServer;
import util.DH;
import util.PublicKeyUtil;
import util.SymmetricKeyUtil;

public class ChatClient {

  public static final int SUCCESS = 0;
  public static final int CONNECTION_REFUSED = 1;
  public static final int BAD_HOST = 2;
  public static final int ERROR = 3;
  String _loginName;
  ChatServer _server;
  ChatClientThread _thread;
  ChatLoginPanel _loginPanel;
  ChatRoomPanel _chatPanel;
  PrintWriter _out = null;
  BufferedReader _in = null;
  CardLayout _layout;
  JFrame _appFrame;

  Socket _socket = null;
  SecureRandom secureRandom;
  KeyStore clientKeyStore;
  KeyStore caKeyStore;
  

  
  // KeyManagerFactory keyManagerFactory;
  // TrustManagerFactory trustManagerFactory;


  private String symmetricAESkey; // 128 bit key
  private byte [] initVector; // 16 bytes IV
  private String hmacKey = "qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50";
  
  private X509Certificate clientCert;
  private static int selectedRoomNumber = 1;
  private HashMap<String, BigInteger> dhParameters;
  private HashMap<String, BigInteger> serverDhParameters;
  private BigInteger sharedKey;
  private KeyPair kp;


  // ChatClient Constructor
  //
  // empty, as you can see.
  public ChatClient() {

    _loginName = null;
    _server = null;

    try {
      initComponents();
    } catch (Exception e) {
      System.out.println("ChatClient error: " + e.getMessage());
      e.printStackTrace();
    }

    _layout.show(_appFrame.getContentPane(), "Login");

  }

  public void run() {
    _appFrame.pack();
    _appFrame.setVisible(true);

  }

  // main
  //
  // Construct the app inside a frame, in the center of the screen
  public static void main(String[] args) {

    ChatClient app = new ChatClient();

    app.run();
  }

  // initComponents
  //
  // Component initialization
  private void initComponents() throws Exception {

    _appFrame = new JFrame("CS255 Chat");
    _layout = new CardLayout();
    _appFrame.getContentPane().setLayout(_layout);
    _loginPanel = new ChatLoginPanel(this);
    _chatPanel = new ChatRoomPanel(this);
    _appFrame.getContentPane().add(_loginPanel, "Login");
    _appFrame.getContentPane().add(_chatPanel, "ChatRoom");
    _appFrame.addWindowListener(new WindowAdapter() {

      public void windowClosing(WindowEvent e) {
        quit();
      }
    });


  }

  // quit
  //
  // Called when the application is about to quit.
  public void quit() {

    try {
      _socket.shutdownOutput();
      // _thread.join();
      _socket.close();

    } catch (Exception err) {
      System.out.println("ChatClient error: " + err.getMessage());
      err.printStackTrace();
    }

    System.exit(0);
  }

  //
  // connect
  //
  // Called from the login panel when the user clicks the "connect"
  // button. You will need to modify this method to add certificate
  // authentication.
  // There are two passwords : the keystorepassword is the password
  // to access your private key on the file system
  // The other is your authentication password on the CA.
  //
  public int connect(String loginName, char[] password, String keyStoreName,
      char[] keyStorePassword, String caHost, int caPort, String serverHost, int serverPort,
      int roomNumber) {

    System.out.println("Loginname : " + loginName + " password : " + String.valueOf(password)
        + " keyStoreName : " + keyStoreName + " keyStorePassword : "
        + String.valueOf(keyStorePassword) + " caHost : " + caHost + " caPort : " + caPort
        + " serverHost :" + serverHost + " serverPort : " + serverPort + " roomNumber : "
        + roomNumber);

    int result = ERROR;

    try {
      kp = PublicKeyUtil.getKeyPairFromKeyStore(keyStoreName, loginName, keyStorePassword, password);
      if (kp != null) {
        System.out.println(kp.getPublic().toString());
        System.out.println(kp.getPrivate().toString());
        result = SUCCESS;

        try {
          _loginName = loginName;
          selectedRoomNumber = roomNumber;

          _socket = new Socket(serverHost, serverPort);
          _out = new PrintWriter(_socket.getOutputStream(), true);

          _in = new BufferedReader(new InputStreamReader(_socket.getInputStream()));

          X509Certificate caCert = PublicKeyUtil.getCertFromFile("ca.cer");

          _out.println("Hello#" + selectedRoomNumber);

          ObjectInputStream ois = new ObjectInputStream(_socket.getInputStream());
          ObjectOutputStream oos = new ObjectOutputStream(_socket.getOutputStream());


          X509Certificate serverCert = (X509Certificate) ois.readObject();

          try {
            serverCert.verify(caCert.getPublicKey());
          } catch (Exception e) {
            _socket.close();
            System.exit(0);
          }

          clientCert = PublicKeyUtil.getCertFromFile(_loginName + "_CA_.cer");
          oos.writeObject(clientCert);

          String isVerified;
          if ((isVerified = _in.readLine()) != null) {
            System.out.println("isis " + isVerified);
            if (!Boolean.valueOf(isVerified)) {
              System.err.println("SERVER DID NOT VERIFY THE CLIENT..");
              _in.close();
              _out.close();
              ois.close();
              oos.close();
              _socket.close();
              System.exit(0);
            }
          }

          HashMap<String,String> tmp = (HashMap<String, String>) ois.readObject();
          serverDhParameters = new HashMap<String, BigInteger>();
          BigInteger decryptedServerDHPublic = new BigInteger(PublicKeyUtil.decrypt(tmp.get("public"), kp.getPrivate()));
          BigInteger decryptedServerDHGeneratorValue = new BigInteger(PublicKeyUtil.decrypt(tmp.get("generatorValue"), kp.getPrivate()));
          BigInteger decryptedServerDHPrimeValue = new BigInteger(PublicKeyUtil.decrypt(tmp.get("primeValue"), kp.getPrivate()));
          serverDhParameters.put("public",decryptedServerDHPublic);
          serverDhParameters.put("generatorValue",decryptedServerDHGeneratorValue);
          serverDhParameters.put("primeValue",decryptedServerDHPrimeValue);
          System.out.println("CLIENT : " + serverDhParameters);

          
          //TODO  encrypt edilecek..
          dhParameters = DH.getDHParameters(serverDhParameters.get("generatorValue"),serverDhParameters.get("primeValue"));
          HashMap<String,String> dhParametersToSend = new HashMap<String, String>();
          String encryptedClientDHPublic = PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("public")), serverCert.getPublicKey());
          String encryptedClientDHGeneratorValue = PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("generatorValue")), serverCert.getPublicKey());
          String encryptedClientDHPrimeValue = PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("primeValue")), serverCert.getPublicKey());
          dhParametersToSend.put("public", encryptedClientDHPublic);
          dhParametersToSend.put("generatorValue", encryptedClientDHGeneratorValue);
          dhParametersToSend.put("primeValue", encryptedClientDHPrimeValue);
          oos.writeObject(dhParametersToSend);
          
          sharedKey = DH.getSharedKey(serverDhParameters.get("public"), dhParameters.get("secret"), dhParameters.get("primeValue"));
          System.err.println(sharedKey);
          
          // aynı
          
          byte[] hashOfSharedKey = SymmetricKeyUtil.generateMD5Hash(String.valueOf(sharedKey)).getBytes();
          // System.out.println("hashOfSharedKey : " + Base64.encode(hashOfSharedKey));
          hashOfSharedKey = Arrays.copyOf(hashOfSharedKey, 16);
          // System.out.println("hashOfSharedKey 16: " + hashOfSharedKey.length);
          // aynı
          String encryptedChatRoomKey;
          byte [] zeroIV = "0000000000000000".getBytes();

          if ((encryptedChatRoomKey = _in.readLine()) != null) {
            // System.out.println("Alinan: " + encryptedChatRoomKey);
            String decryptedChatRoomKey = SymmetricKeyUtil.decrypt(hashOfSharedKey, zeroIV, encryptedChatRoomKey.getBytes());
            System.out.println("Decrypted: " + decryptedChatRoomKey);
            symmetricAESkey = decryptedChatRoomKey;
            System.out.println("Symmetric AES key: " + symmetricAESkey);
          }          
          

          _layout.show(_appFrame.getContentPane(), "ChatRoom");
          _thread = new ChatClientThread(ChatClient.this);
          _thread.start();

          return result;

        } catch (UnknownHostException e) {

          System.err.println("Don't know about the serverHost: " + serverHost);
          System.exit(1);

        } catch (IOException e) {

          System.err.println("Couldn't get I/O for " + "the connection to the serverHost: "
              + serverHost);
          System.out.println("ChatClient error: " + e.getMessage());
          e.printStackTrace();

          System.exit(1);

        } catch (AccessControlException e) {

          return BAD_HOST;

        } catch (Exception e) {

          System.out.println("ChatClient err: " + e.getMessage());
          e.printStackTrace();
        }

      } else
        result = ERROR;

    } catch (NoSuchAlgorithmException e) {
      result = ERROR;
    } catch (CertificateException e) {
      result = ERROR;
    } catch (UnrecoverableEntryException e) {
      result = ERROR;
    } catch (KeyStoreException e) {
      result = ERROR;
    } catch (IOException e) {
      System.out.println(e);
      result = ERROR;
      if (e instanceof FileNotFoundException) {
        result = ERROR;
        System.out.println("LOL");
      }
    }

    return ERROR;
  }

  // sendMessage
  //
  // Called from the ChatPanel when the user types a carrige return.
  public void sendMessage(String msg) {

    try {
      msg = _loginName + "> " + msg;
      initVector = SymmetricKeyUtil.generate16bitIV();
      
      System.out.println("SENDMSG " + initVector +" ve " + symmetricAESkey + " ve " + symmetricAESkey.length()); 
      
      
      String encryptedMsg = SymmetricKeyUtil.encrypt(symmetricAESkey.getBytes(), initVector, msg.getBytes());

      
//      System.out.println("SENDMSG: "+encryptedMsg + new String(initVector)  + hmac);
      
      String hmac = SymmetricKeyUtil.getHMACMD5(hmacKey, encryptedMsg);
      _out.println(encryptedMsg + new String(initVector)  + hmac);

    } catch (Exception e) {

      System.out.println("ChatClient err: " + e.getMessage());
      e.printStackTrace();
    }

  }

  public Socket getSocket() {

    return _socket;
  }

  public JTextArea getOutputArea() {

    return _chatPanel.getOutputArea();
  }
  
  public String getSymmetricAESkey() {
    return symmetricAESkey;
  }

  public void setSymmetricAESkey(String symmetricAESkey) {
    this.symmetricAESkey = symmetricAESkey;
  }

  public byte[] getInitVector() {
    return initVector;
  }

  public void setInitVector(byte[] initVector) {
    this.initVector = initVector;
  }

}
