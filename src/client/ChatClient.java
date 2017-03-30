// ChatClient.java
//
// Modified 1/30/2000 by Alan Frindell
// Last modified 2/18/2003 by Ting Zhang
// Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
// Chat Client starter application.
package client;

import org.apache.commons.codec.binary.Base64;
import server.ChatServer;
import util.DH;
import util.PublicKeyUtil;
import util.SymmetricKeyUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ChatClient {

    private final static Logger logger = Logger.getLogger(ChatClient.class.getName());
    public static final int SUCCESS = 0;
    public static final int CONNECTION_REFUSED = 1;
    public static final int BAD_HOST = 2;
    public static final int ERROR = 3;
    private String _loginName;
    private ChatServer _server;
    private ChatClientThread _thread;
    private ChatLoginPanel _loginPanel;
    private ChatRoomPanel _chatPanel;
    private PrintWriter _out = null;
    private BufferedReader _in = null;
    private CardLayout _layout;
    private JFrame _app;

    private Socket _socket = null;

    private String symmetricAESkey; // 128 bit key
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

        logger.setLevel(Level.INFO);
        _loginName = null;
        _server = null;

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

    // quit
    //
    // Called when the application is about to quit.
    public void quit() {

        try {
            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (Exception err) {
            logger.log(Level.SEVERE, err.getMessage());
            //err.printStackTrace();
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

        int result = ERROR;

        try {
            kp =
                    PublicKeyUtil.getKeyPairFromKeyStore(keyStoreName, loginName, keyStorePassword, password);

            if (kp != null) {
                logger.log(Level.INFO, "Read client key pair");
                result = SUCCESS;

                try {
                    _loginName = loginName;
                    selectedRoomNumber = roomNumber;

                    _socket = new Socket(serverHost, serverPort);
                    _out = new PrintWriter(_socket.getOutputStream(), true);

                    _in = new BufferedReader(new InputStreamReader(_socket.getInputStream()));

                    X509Certificate caCert = PublicKeyUtil.getCertFromFile("CA", "CA.cer");

                    _out.println("Hello#" + _loginName + "#" + selectedRoomNumber);

                    ObjectInputStream ois = new ObjectInputStream(_socket.getInputStream());
                    ObjectOutputStream oos = new ObjectOutputStream(_socket.getOutputStream());


                    X509Certificate serverCert = (X509Certificate) ois.readObject();

                    try {
                        serverCert.verify(caCert.getPublicKey());
                    } catch (Exception e) {
                        _socket.close();
                        System.exit(0);
                    }

                    clientCert = PublicKeyUtil.getCertFromFile(_loginName,_loginName + ".cer");
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

                    dhParameters =
                            DH.getDHParameters(serverDhParameters.get("generatorValue"),
                                    serverDhParameters.get("primeValue"));
                    HashMap<String, String> dhParametersToSend = new HashMap<String, String>();
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
                    oos.writeObject(dhParametersToSend);

                    sharedKey =
                            DH.getSharedKey(serverDhParameters.get("public"), dhParameters.get("secret"),
                                    dhParameters.get("primeValue"));

                    byte[] hashOfSharedKey =
                            SymmetricKeyUtil.generateMD5Hash(String.valueOf(sharedKey)).getBytes();

                    byte[] hashOfSharedKey16Bytes = Arrays.copyOf(hashOfSharedKey, 16);

                    String encryptedChatRoomKey;
                    byte[] zeroIV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

                    if ((encryptedChatRoomKey = _in.readLine()) != null) {

                        byte[] decryptedChatRoomKey =
                                SymmetricKeyUtil.decrypt(hashOfSharedKey16Bytes, zeroIV,
                                        Base64.decodeBase64(encryptedChatRoomKey));
                        symmetricAESkey = Base64.encodeBase64String(decryptedChatRoomKey);
                        logger.log(Level.CONFIG, "Symmetric AES key: " + symmetricAESkey);
                    }


                    _app.setTitle(_app.getTitle() + String.valueOf(roomNumber));
                    _layout.show(_app.getContentPane(), "ChatRoom");
                    _thread = new ChatClientThread(ChatClient.this);
                    _thread.start();

                    return result;

                } catch(EOFException e) {
                    logger.log(Level.SEVERE, "Possible duplicate login name");
                    JOptionPane.showMessageDialog(_app, "There is a connected user with the same login name in room",
                            "Multiple Login Attempt", JOptionPane.ERROR_MESSAGE);
                    System.exit(1);
                }
                catch (UnknownHostException e) {

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

    // sendMessage
    //
    // Called from the ChatPanel when the user types a carrige return.
    public void sendMessage(String msg) {

        try {
            msg = _loginName + "> " + msg;

            int msgType = 1;
            byte[] iv = SymmetricKeyUtil.generate16BytesIV();

            byte[] encryptedMsg =
                    SymmetricKeyUtil.encrypt(Base64.decodeBase64(symmetricAESkey), iv, msg.getBytes());
            String ivStr = Base64.encodeBase64String(iv);
            String encryptedMsgStr = Base64.encodeBase64String(encryptedMsg);

            String hmac = SymmetricKeyUtil.getHMACMD5(symmetricAESkey.getBytes(), encryptedMsgStr);
            _out.println(msgType + "#" + encryptedMsgStr + "#" + ivStr + "#" + hmac);
            logger.log(Level.CONFIG, "Sent message");
        } catch (Exception e) {
            logger.log(Level.SEVERE, e.getMessage());
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

    public PublicKey getPublicKey() {
        return this.kp.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.kp.getPrivate();
    }

    public void setSymmetricAESKey(String symmetricAESkey) {
        this.symmetricAESkey = symmetricAESkey;
    }
}
