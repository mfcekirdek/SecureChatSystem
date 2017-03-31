// ChatClient.java
//
// Modified 1/30/2000 by Alan Frindell
// Last modified 2/18/2003 by Ting Zhang
// Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
// Chat Client starter application.
package client;

import java.awt.CardLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.AccessControlException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;

import org.apache.commons.codec.binary.Base64;

import util.DH;
import util.PublicKeyUtil;
import util.SymmetricKeyUtil;

public class ChatClient {

    // Logger
    private final static Logger logger = Logger.getLogger(ChatClient.class.getName());

    // Status codes
    public static final int SUCCESS = 0;
    public static final int CONNECTION_REFUSED = 1;
    public static final int BAD_HOST = 2;
    public static final int ERROR = 3;

    // UI variables
    private JFrame _app;
    private CardLayout _layout;
    private ChatLoginPanel _loginPanel;
    private ChatRoomPanel _chatPanel;
    private ChatClientThread _thread;

    // Client variables
    private static int selectedRoomNumber = 1;
    private Socket _socket = null;
    private String _loginName;
    private PrintWriter _out = null;
    private BufferedReader _in = null;

    // 128 Bit AES key
    private String symmetricAESkey;

    // Client certificate
    private X509Certificate clientCert;

    // Diffie-Hellman Parameters of client
    private HashMap<String, BigInteger> dhParameters;

    // Diffie-Hellman Parameters of server
    private HashMap<String, BigInteger> serverDhParameters;

    // Diffie-Hellman shared key between client and server
    private BigInteger sharedKey;
    private KeyPair kp;

    /**
     * Default constructor.
     */
    public ChatClient() {

        logger.setLevel(Level.INFO);
        _loginName = null;

        try {
            initComponents();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "ChatClient error: " + e.getMessage());
            e.printStackTrace();
        }

        _layout.show(_app.getContentPane(), "Login");

    }

    public void run() {
        _app.pack();
        _app.setVisible(true);

    }

    /**
     * Runs applications
     *
     * @param args
     */
    public static void main(String[] args) {

        ChatClient app = new ChatClient();

        app.run();
    }

    /**
     * Initializes application frame and panels.
     */
    private void initComponents() {

        _app = new JFrame("Bil448 Chat Room ");
        _layout = new CardLayout();
        _app.getContentPane().setLayout(_layout);
        _loginPanel = new ChatLoginPanel(this);
        _chatPanel = new ChatRoomPanel(this);
        _app.getContentPane().add(_loginPanel, "Login");
        _app.getContentPane().add(_chatPanel, "ChatRoom");
        _app.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        });
        logger.log(Level.INFO, "Started client GUI");

    }

    /**
     * Closes the sockets and quits.
     * This method is called when Window Close(X) button clicked.
     */
    public void quit() {

        try {
            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (Exception err) {
            logger.log(Level.SEVERE, err.getMessage());
        }
        System.exit(0);
    }

    /**
     * @param loginName        Client's login name
     * @param password         Client's password to read public & private key pair
     * @param keyStoreName
     * @param keyStorePassword
     * @param serverHost       Server's host address
     * @param serverPort       Server's port number
     * @param roomNumber       Room number to be connected
     * @return
     */
    public int connect(String loginName, char[] password, String keyStoreName,
                       char[] keyStorePassword, String serverHost, int serverPort,
                       int roomNumber) {

        int result;

        try {
            // Read client's keypair from keystore
            kp = PublicKeyUtil.getKeyPairFromKeyStore(keyStoreName, loginName, keyStorePassword, password);

            if (kp != null) {
                // If reading is success
                logger.log(Level.INFO, "Read client key pair");
                result = SUCCESS;

                try {
                    _loginName = loginName;
                    selectedRoomNumber = roomNumber;

                    _socket = new Socket(serverHost, serverPort);
                    _in = new BufferedReader(new InputStreamReader(_socket.getInputStream()));
                    _out = new PrintWriter(_socket.getOutputStream(), true);

                    // Get CA certificate from file
                    X509Certificate caCert = PublicKeyUtil.getCertFromFile("CA", "CA.cer");

                    // Send hello message to server to start the protocol
                    _out.println("Hello#" + _loginName + "#" + selectedRoomNumber);

                    ObjectInputStream ois = new ObjectInputStream(_socket.getInputStream());
                    ObjectOutputStream oos = new ObjectOutputStream(_socket.getOutputStream());

                    // Read server's certificate from stream
                    X509Certificate serverCert = (X509Certificate) ois.readObject();

                    try {
                        // try to verify server's certificate
                        serverCert.verify(caCert.getPublicKey());
                    } catch (Exception e) {
                        // If certificate is not verified, close the connection and quit.
                        _socket.close();
                        System.exit(0);
                    }

                    // Read client's own certificate from file
                    clientCert = PublicKeyUtil.getCertFromFile(_loginName, _loginName + ".cer");
                    // Send client certificate to server
                    oos.writeObject(clientCert);

                    String isVerified;
                    if ((isVerified = _in.readLine()) != null) {
                        if (!Boolean.valueOf(isVerified)) {
                            logger.log(Level.SEVERE, "Server did not verify the client certificate");
                            _in.close();
                            _out.close();
                            ois.close();
                            oos.close();
                            _socket.close();
                            logger.log(Level.SEVERE, "Closed connection. Now exiting...");
                            System.exit(0);
                        }
                    }
                    // Read encryted DH parameters of server
                    HashMap<String, String> tmp = (HashMap<String, String>) ois.readObject();
                    serverDhParameters = new HashMap<String, BigInteger>();
                    BigInteger decryptedServerDHPublic =
                            new BigInteger(PublicKeyUtil.decrypt(tmp.get("public"), kp.getPrivate()));
                    BigInteger decryptedServerDHGeneratorValue =
                            new BigInteger(PublicKeyUtil.decrypt(tmp.get("generatorValue"), kp.getPrivate()));
                    BigInteger decryptedServerDHPrimeValue =
                            new BigInteger(PublicKeyUtil.decrypt(tmp.get("primeValue"), kp.getPrivate()));
                    serverDhParameters.put("public", decryptedServerDHPublic);
                    serverDhParameters.put("generatorValue", decryptedServerDHGeneratorValue);
                    serverDhParameters.put("primeValue", decryptedServerDHPrimeValue);

                    // Generate DH parameters for client to send to server
                    dhParameters =
                            DH.getDHParameters(serverDhParameters.get("generatorValue"),
                                    serverDhParameters.get("primeValue"));
                    HashMap<String, String> dhParametersToSend = new HashMap<String, String>();

                    // Encrypt parameters with server's public key
                    String encryptedClientDHPublic =
                            PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("public")),
                                    serverCert.getPublicKey());
                    String encryptedClientDHGeneratorValue =
                            PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("generatorValue")),
                                    serverCert.getPublicKey());
                    String encryptedClientDHPrimeValue =
                            PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("primeValue")),
                                    serverCert.getPublicKey());
                    dhParametersToSend.put("public", encryptedClientDHPublic);
                    dhParametersToSend.put("generatorValue", encryptedClientDHGeneratorValue);
                    dhParametersToSend.put("primeValue", encryptedClientDHPrimeValue);

                    // send encrypted DH parameters
                    oos.writeObject(dhParametersToSend);

                    // Calculate DH shared key
                    sharedKey =
                            DH.getSharedKey(serverDhParameters.get("public"), dhParameters.get("secret"),
                                    dhParameters.get("primeValue"));

                    // Calculate hash of shared key
                    byte[] hashOfSharedKey =
                            SymmetricKeyUtil.generateMD5Hash(String.valueOf(sharedKey)).getBytes();
                    byte[] hashOfSharedKey16Bytes = Arrays.copyOf(hashOfSharedKey, 16);

                    String encryptedChatRoomKey;
                    byte[] zeroIV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

                    // Read encrypted chat room key and decrypt with DH shared key
                    if ((encryptedChatRoomKey = _in.readLine()) != null) {

                        byte[] decryptedChatRoomKey =
                                SymmetricKeyUtil.decrypt(hashOfSharedKey16Bytes, zeroIV,
                                        Base64.decodeBase64(encryptedChatRoomKey));
                        symmetricAESkey = Base64.encodeBase64String(decryptedChatRoomKey);
                        // debug log
                        logger.log(Level.CONFIG, "Symmetric AES key: " + symmetricAESkey);
                    }

                    _app.setTitle(_app.getTitle() + String.valueOf(roomNumber));
                    _layout.show(_app.getContentPane(), "ChatRoom");
                    _thread = new ChatClientThread(ChatClient.this);
                    _thread.start();

                    return result;

                } catch (EOFException e) {
                    logger.log(Level.SEVERE, "Possible duplicate login name");
                    JOptionPane.showMessageDialog(_app, "There is a connected user with the same login name in room",
                            "Multiple Login Attempt", JOptionPane.ERROR_MESSAGE);
                    System.exit(1);
                } catch (UnknownHostException e) {

                    logger.log(Level.SEVERE, "Don't know about the serverHost: " + serverHost);
                    System.exit(1);

                } catch (IOException e) {

                    logger.log(Level.SEVERE, "Couldn't get I/O for " + "the connection to the serverHost: "
                            + serverHost);
                    logger.log(Level.SEVERE, "ChatClient error: " + e.getMessage());
                    e.printStackTrace();

                    System.exit(1);

                } catch (AccessControlException e) {

                    return BAD_HOST;

                } catch (Exception e) {

                    logger.log(Level.SEVERE, "ChatClient err: " + e.getMessage());
                    e.printStackTrace();
                }

            } else {

                result = ERROR;
                logger.log(Level.SEVERE, "Cannot read client key pair");
            }

        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException | CertificateException e) {
            result = ERROR;
        } catch (IOException e) {
            result = ERROR;
            if (e instanceof FileNotFoundException) {
                result = ERROR;
                logger.log(Level.SEVERE, "Keystore file is not found.");
            }
        }

        return ERROR;
    }

    /**
     * Sends an ecrypted message to server
     *
     * @param msg Message to encrypt and send
     */
    public void sendMessage(String msg) {

        try {
            msg = _loginName + " > " + msg;

            int msgType = 1;
            // Generate a 16 bytes long initialization vector
            byte[] iv = SymmetricKeyUtil.generate16BytesIV();

            byte[] encryptedMsg =
                    SymmetricKeyUtil.encrypt(Base64.decodeBase64(symmetricAESkey), iv, msg.getBytes());
            String ivStr = Base64.encodeBase64String(iv);
            String encryptedMsgStr = Base64.encodeBase64String(encryptedMsg);

            // Calculate HMAC
            String hmac = SymmetricKeyUtil.getHMACMD5(symmetricAESkey.getBytes(), encryptedMsgStr);

            // Send encrypted message, IV and HMAC
            _out.println(msgType + "#" + encryptedMsgStr + "#" + ivStr + "#" + hmac);

            logger.log(Level.CONFIG, "Sent message");

        } catch (Exception e) {
            logger.log(Level.SEVERE, e.getMessage());
        }

    }

    /**
     * Returns socket object
     *
     * @return Socket object
     */
    public Socket getSocket() {

        return _socket;
    }

    /**
     * Returns chat area of chat panel
     *
     * @return Chat area
     */
    public JTextArea getOutputArea() {

        return _chatPanel.getOutputArea();
    }

    /**
     * Returns symmetric AES key
     *
     * @return symmetric key
     */
    public String getSymmetricAESkey() {
        return symmetricAESkey;
    }

    /**
     * Returns private key read from file
     * @return private key
     */
    public PrivateKey getPrivateKey() {
        return this.kp.getPrivate();
    }

    /**
     * Sets symmetric AES key
     * @param symmetricAESkey new key
     */
    public void setSymmetricAESKey(String symmetricAESkey) {
        this.symmetricAESkey = symmetricAESkey;
    }
}
