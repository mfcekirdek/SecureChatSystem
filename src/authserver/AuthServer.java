//
// AuthServer.java
//
// Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
package authserver;

// AWT/Swing
import java.awt.CardLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.swing.JFrame;
import javax.swing.JTextArea;
// Java
// socket
// Crypto

import util.PublicKeyUtil;

public class AuthServer {

  // Failure codes
  public static final int SUCCESS = 0;
  public static final int KEYSTORE_FILE_NOT_FOUND = 1;
  // public static final int PERMISSIONS_FILE_NOT_FOUND = 2;
  // public static final int PERMISSIONS_FILE_TAMPERED = 3;
  public static final int ERROR = 4;
  public static final int WRONG_PASSWORD = 5;

  // The GUI
  AuthServerLoginPanel _panel;
  AuthServerActivityPanel _activityPanel;
  CardLayout _layout;
  JFrame _appFrame;
  private AuthServerThread _thread;
  // Port number to listen on
  private int _portNum;

  private static char[] KEY_STORE_PASSWORD;
  private static String keyStoreFilename;

  private static final char[] KEY_PASSWORD = "s3rv3r1k3y".toCharArray();
  private static final String ALIAS = "Server1"; // "serverKey";
  private KeyPair kp;

  // Data structures to hold the authentication
  // information read from the file
  // ............
  // ............
  public AuthServer() throws Exception {

    _panel = null;
    _activityPanel = null;
    _layout = null;
    _appFrame = null;

    try {
      initialize();
    } catch (Exception e) {
      System.out.println("AS error: " + e.getMessage());
      e.printStackTrace();
    }

    _layout.show(_appFrame.getContentPane(), "ASPanel");

  }

  // initialize
  //
  // AS initialization
  private void initialize() throws Exception {

    _appFrame = new JFrame("Authentication Server");
    _layout = new CardLayout();

    _appFrame.getContentPane().setLayout(_layout);
    _panel = new AuthServerLoginPanel(this);
    _appFrame.getContentPane().add(_panel, "ASPanel");

    _activityPanel = new AuthServerActivityPanel(this);
    _appFrame.getContentPane().add(_activityPanel, "ActivityPanel");

    _appFrame.addWindowListener(new WindowAdapter() {

      public void windowClosing(WindowEvent e) {
        quit();
      }
    });
  }

  public void run() {
    _appFrame.pack();
    _appFrame.setVisible(true);
  }

  // quit
  //
  // Called when the application is about to quit.
  public void quit() {

    try {
      System.out.println("quit called");
    } catch (Exception err) {
      System.out.println("AuthServer error: " + err.getMessage());
      err.printStackTrace();
    }

    System.exit(0);
  }

  //
  // Start up the AS server
  //
  public int startup(String _ksFileName, char[] _privateKeyPass, int _asPort) {
    _portNum = _asPort;
    KEY_STORE_PASSWORD = _privateKeyPass;
    keyStoreFilename = _ksFileName;
    int result = AuthServer.KEYSTORE_FILE_NOT_FOUND;



    //
    // Read the AS keystore (i.e. its private key)
    // Failure codes to return are defined on the top
    //


    try {
      kp =
          PublicKeyUtil.getKeyPairFromKeyStore(keyStoreFilename, AuthServer.ALIAS,
              KEY_STORE_PASSWORD, AuthServer.KEY_PASSWORD);
      if (kp != null) {
        System.out.println(kp.getPublic().toString());
        System.out.println(kp.getPrivate().toString());
        result = AuthServer.SUCCESS;

        _layout.show(_appFrame.getContentPane(), "ActivityPanel");
        _thread = new AuthServerThread(this);
        _thread.start();
      }

      else
        result = AuthServer.ERROR;

    } catch (NoSuchAlgorithmException e) {
      result = AuthServer.ERROR;
    } catch (CertificateException e) {
      result = AuthServer.ERROR;
    } catch (UnrecoverableEntryException e) {
      result = AuthServer.ERROR;
    } catch (KeyStoreException e) {
      result = AuthServer.ERROR;
    } catch (IOException e) {
      System.out.println(e);
      result = AuthServer.WRONG_PASSWORD;
      if (e instanceof FileNotFoundException) {
        result = AuthServer.KEYSTORE_FILE_NOT_FOUND;
        System.out.println("LOL");
      }
    }


    //
    // Note :
    // When you return a success DO-NOT forget to show the
    // Activity panel using the line below and start the
    // thread listening for connections
    //

    return result;
  }

  public int getPortNumber() {
    return _portNum;
  }

  public JTextArea getOutputArea() {

    return _activityPanel.getOutputArea();
  }

  public KeyPair getKeyPair() {
    return this.kp;
  }



  // main
  //
  // Construct the AS panel, read in the passwords and give the
  // control back
  public static void main(String[] args) throws Exception {

    AuthServer as = new AuthServer();
    as.run();
  }
}
