//
// CertificateAuthority.java
//
// Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
package ca;

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
import authserver.AuthServer;
import authserver.AuthServerThread;

public class CertificateAuthority {
  // Failure codes

  public static final int SUCCESS = 0;
  public static final int KEYSTORE_FILE_NOT_FOUND = 1;
  // public static final int PERMISSIONS_FILE_NOT_FOUND = 2;
  // public static final int PERMISSIONS_FILE_TAMPERED = 3;
  public static final int ERROR = 4;
  public static final int WRONG_PASSWORD = 5;
  // The GUI
  CertificateAuthorityLoginPanel _panel;
  CertificateAuthorityActivityPanel _activityPanel;
  CardLayout _layout;
  JFrame _appFrame;
  CertificateAuthorityThread _thread;
  // Port number to listen on
  private int _portNum;

  private static char[] KEY_STORE_PASSWORD;
  private static String keyStoreFilename;

  private static final String ALIAS = "CAKey";
  private static final char[] KEY_PASSWORD = "cak3ys3cr3t".toCharArray();

  // Data structures to hold the authentication
  // information read from the file
  // ............
  // ............
  public CertificateAuthority() throws Exception {

    _panel = null;
    _activityPanel = null;
    _layout = null;
    _appFrame = null;

    try {
      initialize();
    } catch (Exception e) {
      System.out.println("CA error: " + e.getMessage());
      e.printStackTrace();
    }

    _layout.show(_appFrame.getContentPane(), "CAPanel");

  }

  // initialize
  //
  // CA initialization
  private void initialize() throws Exception {

    _appFrame = new JFrame("Certificate Authority");
    _layout = new CardLayout();

    _appFrame.getContentPane().setLayout(_layout);
    _panel = new CertificateAuthorityLoginPanel(this);
    _appFrame.getContentPane().add(_panel, "CAPanel");

    _activityPanel = new CertificateAuthorityActivityPanel(this);
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
      System.out.println("CertificateAuthority error: " + err.getMessage());
      err.printStackTrace();
    }

    System.exit(0);
  }

  //
  // Start up the CA server
  //
  public int startup(String _ksFileName, char[] _privateKeyPass,
  /*
   * String _permissionsFileName, char[] _permissionsFilePass,
   */
  int _caPort) {
    _portNum = _caPort;
    KEY_STORE_PASSWORD = _privateKeyPass;
    keyStoreFilename = _ksFileName;


    int result = CertificateAuthority.ERROR;
    KeyPair kp;

    try {
      kp =
          PublicKeyUtil.getKeyPairFromKeyStore(keyStoreFilename, CertificateAuthority.ALIAS,
              KEY_STORE_PASSWORD, CertificateAuthority.KEY_PASSWORD);
      if (kp != null) {
        System.out.println(kp.getPublic().toString());
        System.out.println(kp.getPrivate().toString());
        result = AuthServer.SUCCESS;


        _layout.show(_appFrame.getContentPane(), "ActivityPanel");

        _thread = new CertificateAuthorityThread(this);
        _thread.start();
      }

      else
        result = AuthServer.ERROR;

    } catch (NoSuchAlgorithmException e) {
      result = CertificateAuthority.ERROR;
    } catch (CertificateException e) {
      result = CertificateAuthority.ERROR;
    } catch (UnrecoverableEntryException e) {
      result = CertificateAuthority.ERROR;
    } catch (KeyStoreException e) {
      result = CertificateAuthority.ERROR;
    } catch (IOException e) {
      System.out.println(e);
      result = CertificateAuthority.WRONG_PASSWORD;
      if (e instanceof FileNotFoundException) {
        result = CertificateAuthority.KEYSTORE_FILE_NOT_FOUND;
        System.out.println("LOL");
      }
    }



    //
    // Decrypt the permissions file
    // Read the CA keystore (i.e. its private key)
    // Failure codes to return are defined on the top
    //

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

  // main
  //
  // Construct the CA panel, read in the passwords and give the
  // control back
  public static void main(String[] args) throws Exception {

    CertificateAuthority ca = new CertificateAuthority();
    ca.run();
  }
}
