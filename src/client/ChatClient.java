//  ChatClient.java
//
//  Modified 1/30/2000 by Alan Frindell
//  Last modified 2/18/2003 by Ting Zhang 
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Chat Client starter application.
package client;


//  AWT/Swing
import java.awt.CardLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
//  Java
import java.io.PrintWriter;
// socket
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.AccessControlException;
import java.security.KeyStore;
//  Crypto
import java.security.SecureRandom;

import javax.swing.JFrame;
import javax.swing.JTextArea;

import server.ChatServer;
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
//    KeyManagerFactory keyManagerFactory;
//    TrustManagerFactory trustManagerFactory;
  
    
    
    private String key = "Bar12345Bar12345"; // 128 bit key
    private String initVector = "XandomInitVector"; // 16 bytes IV
    private String hmacKey = "qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50";
    
    //  ChatClient Constructor
    //
    //  empty, as you can see.
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

    //  main
    //
    //  Construct the app inside a frame, in the center of the screen
    public static void main(String[] args) {
        
        ChatClient app = new ChatClient();

        app.run();
    }

    //  initComponents
    //
    //  Component initialization
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

    //  quit
    //
    //  Called when the application is about to quit.
    public void quit() {

        try {
            _socket.shutdownOutput();
            _thread.join();
            _socket.close();

        } catch (Exception err) {
            System.out.println("ChatClient error: " + err.getMessage());
            err.printStackTrace();
        }

        System.exit(0);
    }

    //
    //  connect
    //
    //  Called from the login panel when the user clicks the "connect"
    //  button. You will need to modify this method to add certificate
    //  authentication.  
    //  There are two passwords : the keystorepassword is the password
    //  to access your private key on the file system
    //  The other is your authentication password on the CA.
    //
    public int connect(String loginName, char[] password,
            String keyStoreName, char[] keyStorePassword,
            String caHost, int caPort,
            String serverHost, int serverPort) {

        try {

            _loginName = loginName;


            //
            //  Read the client keystore
            //         (for its private/public keys)
            //  Establish secure connection to the CA
            //  Send public key and get back certificate
            //  Use certificate to establish secure connection with server
            //

            _socket = new Socket(serverHost, serverPort);
            _out = new PrintWriter(_socket.getOutputStream(), true);

            _in = new BufferedReader(new InputStreamReader(
                    _socket.getInputStream()));

            _layout.show(_appFrame.getContentPane(), "ChatRoom");

            _thread = new ChatClientThread(this);
            _thread.start();
            return SUCCESS;

        } catch (UnknownHostException e) {

            System.err.println("Don't know about the serverHost: " + serverHost);
            System.exit(1);

        } catch (IOException e) {

            System.err.println("Couldn't get I/O for "
                    + "the connection to the serverHost: " + serverHost);
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();

            System.exit(1);

        } catch (AccessControlException e) {

            return BAD_HOST;

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

        return ERROR;

    }

    //  sendMessage
    //
    //  Called from the ChatPanel when the user types a carrige return.
    public void sendMessage(String msg) {

        try {
            
            msg = _loginName + "> " + msg;
            String encryptedMsg = SymmetricKeyUtil.encrypt(key, initVector, msg);
            String hmac = SymmetricKeyUtil.getHMACMD5(hmacKey, encryptedMsg);
            _out.println(encryptedMsg+hmac);

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
}
