//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package server;

// Java General

import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
// socket
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JFrame;

import org.apache.commons.codec.binary.Base64;

import util.DH;
import util.PublicKeyUtil;
import util.SymmetricKeyUtil;

public class ChatServer {
  
    // Logger
    private final static Logger logger = Logger.getLogger(ChatServer.class.getName());
    
    // Status codes
    public static final int SUCCESS = 0;
    public static final int KEYSTORE_FILE_NOT_FOUND = 1;
    public static final int ERROR = 2;
    public static final int WRONG_PASSWORD = 3;

    // Clients;
    private HashMap<Integer, ClientRecord> _clientsRoom1;
    private HashMap<Integer, ClientRecord> _clientsRoom2;

    // Server variables
    private int _clientID = 0;
    private String _hostName = null;
    private ServerSocket _serverSocket = null;

    // Chat room keystore aliases
    private static final String ALIAS_1 = "Room1";
    private static final String ALIAS_2 = "Room2";
    
    // UI variables
    JFrame _app;
    CardLayout _layout;
    ChatServerConnectedClientsPanel _clientsPanel;
    ChatServerLoginPanel _loginPanel;
    
    // Client certificate
    private X509Certificate clientCert;
    
    // Keypairs of chat rooms
    private KeyPair[] kpArr = new KeyPair[2];
    
    // Certificates of chat rooms
    private X509Certificate[] chatRoomCertArr = new X509Certificate[2];
    
    // Symmetric 128 Bit AES keys of chat rooms
    private byte[][] symmetricAESkeys = new byte[2][16]; // 128 bit key
    
    // Initialization Vector variables of chat rooms
    private byte[][] initVector = new byte[2][16];

    // Diffie-Hellman parameters for each client
    private HashMap<Integer, HashMap<String, BigInteger>> dhParameters =
            new HashMap<Integer, HashMap<String, BigInteger>>(); // clientID,HashMap


    /**
     * Default constructor.
     */
    public ChatServer() {
        logger.setLevel(Level.INFO);

        try {

            _clientsRoom1 = new HashMap<Integer, ClientRecord>();
            _clientsRoom2 = new HashMap<Integer, ClientRecord>();
            _serverSocket = null;
            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

        } catch (UnknownHostException e) {

            _hostName = "0.0.0.0";

        }
    }
    
    /**
     * Runs applications
     *
     * @param args
     */
    public static void main(String args[]) {


        ChatServer server = new ChatServer();
        server.run();

    }

    /***
     *
     * Starts server GUI
     *
     */
    public void run() {

        _app = new JFrame("Bil448 Chat Server");
        _layout = new CardLayout();
        _loginPanel = new ChatServerLoginPanel(this);
        _clientsPanel = new ChatServerConnectedClientsPanel(this);
        _app.getContentPane().setLayout(_layout);
        _app.getContentPane().add(_loginPanel, "Login");
        _app.getContentPane().add(_clientsPanel, "Clients");
        _app.setPreferredSize(new Dimension(360, 310));
        _app.setResizable(false);
        _app.setLocationByPlatform(true);
        _app.pack();
        _app.setVisible(true);
        _app.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                super.windowClosing(e);
                try {
                    quit();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        });
        logger.log(Level.INFO, "Started server GUI");

    }

    /**
     * Closes the sockets and quits.
     * This method is called when Window Close(X) button clicked.
     */
    
    private void quit() throws IOException {
        for (ClientRecord c : _clientsRoom1.values()) {
            c.getClientSocket().shutdownInput();
            c.getClientSocket().shutdownOutput();
            c.getClientSocket().close();
        }
        for (ClientRecord c : _clientsRoom2.values()) {
            c.getClientSocket().shutdownInput();
            c.getClientSocket().shutdownOutput();
            c.getClientSocket().close();
        }
        logger.log(Level.INFO, "Server closed");
        _app.dispose();
        System.exit(0);
    }

    /**
     * Establishes connection without blocking the GUI
     * @param port
     */
    public void connect(int port) {

        new ChatServerHelperThread(this, port).start();
    }

    
    @SuppressWarnings("unchecked")
    public HashMap<Integer, ClientRecord> getClientRecordsA() {

        return _clientsRoom1;
    }

    @SuppressWarnings("unchecked")
    public HashMap<Integer, ClientRecord> getClientRecordsB() {

        return _clientsRoom2;
    }

    /**
     * 
     * @param keyStoreFile1     Keystore file of chat room #1
     * @param keyStorePwd1      Keystore password of chat room #1
     * @param keypairPwd1       Keypair password of chat room #1
     * @param keyStoreFile2     Keystore file of chat room #2
     * @param keyStorePwd2      Keystore password of chat room #2
     * @param keypairPwd2       Keypair password of chat room #2
     * @param portNumber        Server's port number
     * @return
     */
    public int[] startup(String keyStoreFile1, char[] keyStorePwd1, char[] keypairPwd1,
                         String keyStoreFile2, char[] keyStorePwd2, char[] keypairPwd2, int portNumber) {

        int[] results = new int[2];
        
        // Read chat room keypairs from keystore
        results[0] = readKeyStore(keyStoreFile1, ALIAS_1, keyStorePwd1, keypairPwd1, 1);
        results[1] = readKeyStore(keyStoreFile2, ALIAS_2, keyStorePwd2, keypairPwd2, 2);

        if (results[0] == SUCCESS && results[1] == SUCCESS) {
            // If reading is successful
            
            // read chat room certificates
            readChatRoomCertificatesFromFile();
            // generate symmetric 128 bit AES Keys for each chat room
            generateAESKeys();

        } else {
            logger.log(Level.SEVERE, "Startup error! ");
        }
        return results;
    }
    
    /**
     *  Generates symmetric 128 bit AES Keys and IV's for each chat room
     */

    private void generateAESKeys() {
        symmetricAESkeys[0] = SymmetricKeyUtil.generateSymmetricAESKey();
        symmetricAESkeys[1] = SymmetricKeyUtil.generateSymmetricAESKey();
        initVector[0] = SymmetricKeyUtil.generate16BytesIV();
        initVector[1] = SymmetricKeyUtil.generate16BytesIV();
        logger.log(Level.INFO, "Generated chat room AES keys");
    }
    
    /**
     *  Reads chat room certificates
     */
    private void readChatRoomCertificatesFromFile() {

        String selectedChatRoom = "Room" + 1;
        chatRoomCertArr[0] = PublicKeyUtil.getCertFromFile(selectedChatRoom, selectedChatRoom + ".cer");

        selectedChatRoom = "Room" + 2;
        chatRoomCertArr[1] = PublicKeyUtil.getCertFromFile(selectedChatRoom, selectedChatRoom + ".cer");

        logger.log(Level.INFO, "Read chat room certificates");
    }

    /**
     * Authenticates clients
     * @param clientRecord
     * @return 
     */
    private ClientRecord authenticate(ClientRecord clientRecord) {

        String loginName = "";
        int roomNumber = -1;
        Socket socket = clientRecord.getClientSocket();

        try {
            BufferedReader _in;
            PrintWriter _out;
            
            _in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            _out = new PrintWriter(socket.getOutputStream(), true);
            
            // Get CA certificate from file
            X509Certificate caCert = PublicKeyUtil.getCertFromFile("CA", "CA.cer");
            
            // Receive the first message of client and parse it. 
            // Hello#" + _loginName + "#" + selectedRoomNumber
            String msg;
            if ((msg = _in.readLine()) != null) {
                loginName = msg.substring(msg.indexOf("#"), msg.lastIndexOf("#"));
                roomNumber = Integer.parseInt(msg.substring(msg.lastIndexOf("#") + 1));
                clientRecord.setRoom(roomNumber);
                clientRecord.setLoginName(loginName);
            }
            
            // Check if the client is already connected
            if(isMultipleLogin(clientRecord)) {
                socket.close();
                logger.log(Level.INFO, "Connection rejected. Same login name: " + clientRecord.getLoginName());
                return  null;
            }


            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            
            // Get chat room certificate from file
            X509Certificate serverCert = this.chatRoomCertArr[roomNumber - 1];
            
            // Send chat room's certificate to client
            oos.writeObject(serverCert);
            // Receive client's certificate from client
            clientCert = (X509Certificate) ois.readObject();

            try {
              // Try to verify client's certificate
                clientCert.verify(caCert.getPublicKey());
            } catch (Exception e) {
              // If certificate is not verified, close the connection.
                socket.close();
                logger.log(Level.SEVERE, "Client certificate is not verified. Socket is closed.");
            }
            
            // Client's certificate is verified now
            _out.println("true");
            logger.log(Level.INFO, "Verified client certificate");
            
            // Generate and store DH parameters for server. 
            // <key: clientID, value: DiffieHellmanParametersOfServer> : this DH parameters will be used for this client (whose ID is _clientID)
            dhParameters.put(_clientID, DH.getDHParameters());
            HashMap<String, BigInteger> parameters = dhParameters.get(_clientID);
            
            
            // Encrypt g,p,A values with client's public key
            HashMap<String, String> dhParametersToSend = new HashMap<String, String>();
            /* TODO: clientCert null exception */
            String encryptedServerDHPublic =
                    PublicKeyUtil
                            .encrypt(String.valueOf(parameters.get("public")), clientCert.getPublicKey());
            String encryptedServerDHGeneratorValue =
                    PublicKeyUtil.encrypt(String.valueOf(parameters.get("generatorValue")),
                            clientCert.getPublicKey());
            String encryptedServerDHPrimeValue =
                    PublicKeyUtil.encrypt(String.valueOf(parameters.get("primeValue")),
                            clientCert.getPublicKey());
            
            // Send encrypted g,p,A values to client
            dhParametersToSend.put("public", encryptedServerDHPublic);
            dhParametersToSend.put("generatorValue", encryptedServerDHGeneratorValue);
            dhParametersToSend.put("primeValue", encryptedServerDHPrimeValue);
            oos.writeObject(dhParametersToSend);

            // Receive encrypted g,p,B values from client
            HashMap<String, String> tmp = (HashMap<String, String>) ois.readObject();
            HashMap<String, BigInteger> clientDhParameters = new HashMap<String, BigInteger>();

            // Decrypt received DH parameters using chat room's private key
            KeyPair kp = kpArr[roomNumber - 1];

            BigInteger decryptedClientDHPublic =
                    new BigInteger(PublicKeyUtil.decrypt(tmp.get("public"), kp.getPrivate()));
            BigInteger decryptedClientDHGeneratorValue =
                    new BigInteger(PublicKeyUtil.decrypt(tmp.get("generatorValue"), kp.getPrivate()));
            BigInteger decryptedClientDHPrimeValue =
                    new BigInteger(PublicKeyUtil.decrypt(tmp.get("primeValue"), kp.getPrivate()));

            clientDhParameters.put("public", decryptedClientDHPublic);
            clientDhParameters.put("generatorValue", decryptedClientDHGeneratorValue);
            clientDhParameters.put("primeValue", decryptedClientDHPrimeValue);
            
            // Calculate DH shared key
            BigInteger sharedKey =
                    DH.getSharedKey(clientDhParameters.get("public"),
                            dhParameters.get(_clientID).get("secret"),
                            dhParameters.get(_clientID).get("primeValue"));

            // Calculate hash of shared key
            byte[] hashOfSharedKey =
                    SymmetricKeyUtil.generateMD5Hash(String.valueOf(sharedKey)).getBytes();

            byte[] hashOfSharedKey16Bytes = Arrays.copyOf(hashOfSharedKey, 16);
            byte[] zeroIV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            // Encrypt chat room's key with hash of shared key and send to client
            byte[] encryptedAES =
                    SymmetricKeyUtil
                            .encrypt(hashOfSharedKey16Bytes, zeroIV, symmetricAESkeys[roomNumber - 1]);

            String toSend = Base64.encodeBase64String(encryptedAES);// new String(encryptedAES, "UTF-8");
            _out.println(toSend);
            logger.log(Level.CONFIG, "Symmetric key: "
                    + Base64.encodeBase64String(symmetricAESkeys[roomNumber - 1]));
            
            // Save parameters of client
            clientRecord.setClientDHParameters(clientDhParameters);
            clientRecord.setSharedKey(sharedKey);
            clientRecord.setSymmetricAESKey(symmetricAESkeys[roomNumber - 1]);
            clientRecord.setPublicKey(clientCert.getPublicKey());

            logger.log(Level.INFO, "Obtained chat room AES key");

        } catch (Exception e) {
            logger.log(Level.SEVERE, "AS thread error: " + e.getMessage());
            e.printStackTrace();
        }

        return clientRecord;
    }

    /**
     * Check if the client is already connected
     * @param client
     * @return
     */
    private boolean isMultipleLogin(ClientRecord client) {

        int room = client.getRoom();
        Collection<ClientRecord> records = null;

        switch (room){

            case 1:
                records = _clientsRoom1.values();
                break;
            case 2:
                records = _clientsRoom2.values();
                break;
        }
        for (ClientRecord c : records){
            if(c.getLoginName().equals(client.getLoginName()))
                return true; // there is a connected client already  with the same login name
        }
        return false;
    }

    /**
     * Reads keystore and sets keypair variable of the chat room
     * @param keyStoreFilename
     * @param alias
     * @param keyStorePassword
     * @param keyPassword
     * @param roomNumber
     * @return
     */
    private int readKeyStore(String keyStoreFilename, String alias, char[] keyStorePassword,
                             char[] keyPassword, int roomNumber) {

        KeyPair kp = null;
        int result = ChatServer.ERROR;
        try {
            kp = PublicKeyUtil.getKeyPairFromKeyStore(keyStoreFilename, alias, keyStorePassword,
                    keyPassword);
            if (kp != null) {
                result = ChatServer.SUCCESS;

            } else
                result = ChatServer.ERROR;

        } catch (NoSuchAlgorithmException e) {
            result = ChatServer.ERROR;
        } catch (CertificateException e) {
            result = ChatServer.ERROR;
        } catch (UnrecoverableEntryException e) {
            result = ChatServer.ERROR;
        } catch (KeyStoreException e) {
            result = ChatServer.ERROR;
        } catch (IOException e) {
            result = ChatServer.WRONG_PASSWORD;
            if (e instanceof FileNotFoundException) {
                result = ChatServer.KEYSTORE_FILE_NOT_FOUND;
            }
        }

        this.kpArr[roomNumber - 1] = kp;

        logger.log(Level.INFO, "Read Keystore: " + keyStoreFilename + "\n\tStatus: " + result);

        return result;
    }
    
    /**
     * Generates a new symmetric 128 bit AES key for given chat room and sends to all clients
     * @param roomNumber
     */
    void refreshSymmetricAESKey(int roomNumber) {

        logger.log(Level.CONFIG, "Request for key refreshment");
        symmetricAESkeys[roomNumber - 1] = SymmetricKeyUtil.generateSymmetricAESKey();
        Collection<ClientRecord> clients = null;
        if (roomNumber == 1) {
            clients = _clientsRoom1.values();
        } else if (roomNumber == 2) {
            clients = _clientsRoom2.values();
        }

        if (clients != null) {
            for (ClientRecord c : clients) {
                String keyRefreshMsg = "0#";

                Socket socket = c.getClientSocket();

                if (socket.isConnected()) {
                    PrintWriter out;
                    try {
                        out = new PrintWriter(socket.getOutputStream(), true);
                        // encrypt new AES key with client's public key
                        String encryptedNewKey =
                                PublicKeyUtil.encrypt(Base64.encodeBase64String(symmetricAESkeys[roomNumber - 1]), c.getPublicKey());
                        keyRefreshMsg = keyRefreshMsg + encryptedNewKey;
                        // send new encrypted AES key to client
                        out.println(keyRefreshMsg);
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
            logger.log(Level.INFO, "Published new chat room AES key");
        }
    }

    class ChatServerHelperThread extends Thread {

        private ChatServer _cs;
        private int _port;

        public ChatServerHelperThread(ChatServer cs, int port) {
            super("ChatServerHelperThread");
            _cs = cs;
            _port = port;
        }

        @Override
        public void run() {
            super.run();
            try {

                _serverSocket = new ServerSocket(_port);
                logger.log(Level.INFO, "Running on " + _hostName + ":" + _port);

                while (true) {

                    Socket socket = _serverSocket.accept();
                    logger.log(Level.INFO, "Accepted new connection");
                    ClientRecord clientRecord = new ClientRecord(_clientID, socket);

                    clientRecord = authenticate(clientRecord);
                    if (clientRecord == null){
                        return;
                    }

                    int roomNumber = clientRecord.getRoom();
                    logger.log(Level.INFO, "Connection authenticated");

                    if (roomNumber == 1)
                        _clientsRoom1.put(_clientID++, clientRecord);
                    else if (roomNumber == 2)
                        _clientsRoom2.put(_clientID++, clientRecord);

                    clientRecord.setRoom(roomNumber);

                    _clientsPanel.updateClientLists();
                    ChatServerThread thread = new ChatServerThread(_cs, clientRecord);
                    thread.start();
                }

            } catch (IOException e) {

                logger.log(Level.SEVERE, "Could not listen on port: " + _port);
                System.exit(-1);

            } catch (Exception e) {

                e.printStackTrace();
                System.exit(1);
            }
        }
    }
}
