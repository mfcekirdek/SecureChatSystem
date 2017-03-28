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

    private final static Logger logger = Logger.getLogger(ChatServer.class.getName());
    public static final int SUCCESS = 0;
    public static final int KEYSTORE_FILE_NOT_FOUND = 1;
    public static final int ERROR = 2;
    public static final int WRONG_PASSWORD = 3;

    // private Hashtable _clients;
    private HashMap<Integer, ClientRecord> _clientsRoom1;
    private HashMap<Integer, ClientRecord> _clientsRoom2;

    private int _clientID = 0;
    private String _hostName = null;

    private static final String ALIAS_A = "Server1";
    private static final String ALIAS_B = "Server2";
    private static final char[] KEY_PASSWORD_A = "s3rv3r1k3y".toCharArray();
    private static final char[] KEY_PASSWORD_B = "s3rv3r2k3y".toCharArray();

    JFrame _app;
    CardLayout _layout;
    ChatServerConnectedClientsPanel _clientsPanel;
    private ChatServerLoginPanel _loginPanel;
    private ServerSocket _serverSocket = null;

    private X509Certificate clientCert;

    private KeyPair[] kpArr = new KeyPair[2];
    private X509Certificate[] chatRoomCertArr = new X509Certificate[2];
    private byte[][] symmetricAESkeys = new byte[2][16]; // 128 bit key
    private byte[][] initVector = new byte[2][16]; // 128 bit key


    private HashMap<Integer, HashMap<String, BigInteger>> dhParameters =
            new HashMap<Integer, HashMap<String, BigInteger>>(); // clientID,HashMap


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

    public static void main(String args[]) {


        ChatServer server = new ChatServer();
        server.run();

    }

    /***
     *
     * Your methods for setting up secure connection
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
        _app.setMinimumSize(new Dimension(360, 310));
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
        logger.log(Level.INFO, "Started server GUI.");

    }

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
    }

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


    public int[] startup(String keyStoreFilenameA, char[] keyStorePasswordA,
                         String keyStoreFilenameB, char[] keyStorePasswordB, int portNumber) {

        int[] results = new int[2];
        results[0] = readKeyStore(keyStoreFilenameA, ALIAS_A, keyStorePasswordA, KEY_PASSWORD_A, 1);

        results[1] = readKeyStore(keyStoreFilenameB, ALIAS_B, keyStorePasswordB, KEY_PASSWORD_B, 2);
        logger.log(Level.INFO, "Read Keystore B. Status: " + results[0]);

        readChatRoomCertificatesFromFile();

        generateAESKeys();

        return results;
    }

    private void generateAESKeys() {

        symmetricAESkeys[0] = SymmetricKeyUtil.generateSymmetricAESKey();
        symmetricAESkeys[1] = SymmetricKeyUtil.generateSymmetricAESKey();
        initVector[0] = SymmetricKeyUtil.generate16BytesIV();
        initVector[1] = SymmetricKeyUtil.generate16BytesIV();
        logger.log(Level.INFO, "Generated chat room AES keys");

    }

    private void readChatRoomCertificatesFromFile() {

        String selectedChatRoom = "Server" + 1 + "_CA_.cer";
        chatRoomCertArr[0] = PublicKeyUtil.getCertFromFile(selectedChatRoom);

        selectedChatRoom = "Server" + 2 + "_CA_.cer";
        chatRoomCertArr[1] = PublicKeyUtil.getCertFromFile(selectedChatRoom);

        logger.log(Level.INFO, "Read chat room certificates");
    }


    private int authenticate(ClientRecord clientRecord) {

        int roomNumber = -1;
        Socket socket = clientRecord.getClientSocket();

        try {
            BufferedReader _in;
            PrintWriter _out;

            _in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            _out = new PrintWriter(socket.getOutputStream(), true);

            X509Certificate caCert = PublicKeyUtil.getCertFromFile("ca.cer");

            String msg;

            if ((msg = _in.readLine()) != null)
                roomNumber = Integer.parseInt(msg.substring(msg.indexOf("#") + 1));

            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            X509Certificate serverCert = this.chatRoomCertArr[roomNumber - 1];

            oos.writeObject(serverCert);
            clientCert = (X509Certificate) ois.readObject();

            try {
                clientCert.verify(caCert.getPublicKey());
            } catch (Exception e) {
                socket.close();
                logger.log(Level.SEVERE, "Client certificate is not verified. Socket is closed.");
            }

            _out.println("true");
            logger.log(Level.INFO, "Verified client certificate");

            dhParameters.put(_clientID, DH.getDHParameters());
            HashMap<String, BigInteger> parameters = dhParameters.get(_clientID);

            HashMap<String, String> dhParametersToSend = new HashMap<String, String>();

            String encryptedServerDHPublic =
                    PublicKeyUtil
                            .encrypt(String.valueOf(parameters.get("public")), clientCert.getPublicKey());
            String encryptedServerDHGeneratorValue =
                    PublicKeyUtil.encrypt(String.valueOf(parameters.get("generatorValue")),
                            clientCert.getPublicKey());
            String encryptedServerDHPrimeValue =
                    PublicKeyUtil.encrypt(String.valueOf(parameters.get("primeValue")),
                            clientCert.getPublicKey());

            dhParametersToSend.put("public", encryptedServerDHPublic);
            dhParametersToSend.put("generatorValue", encryptedServerDHGeneratorValue);
            dhParametersToSend.put("primeValue", encryptedServerDHPrimeValue);
            oos.writeObject(dhParametersToSend);


            HashMap<String, String> tmp = (HashMap<String, String>) ois.readObject();
            HashMap<String, BigInteger> clientDhParameters = new HashMap<String, BigInteger>();

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

            BigInteger sharedKey =
                    DH.getSharedKey(clientDhParameters.get("public"),
                            dhParameters.get(_clientID).get("secret"),
                            dhParameters.get(_clientID).get("primeValue"));


            byte[] hashOfSharedKey =
                    SymmetricKeyUtil.generateMD5Hash(String.valueOf(sharedKey)).getBytes();

            byte[] hashOfSharedKey16Bytes = Arrays.copyOf(hashOfSharedKey, 16);
            byte[] zeroIV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            byte[] encryptedAES =
                    SymmetricKeyUtil
                            .encrypt(hashOfSharedKey16Bytes, zeroIV, symmetricAESkeys[roomNumber - 1]);

            String toSend = Base64.encodeBase64String(encryptedAES);// new String(encryptedAES, "UTF-8");
            _out.println(toSend);
            logger.log(Level.CONFIG, "Symmetric key: "
                    + Base64.encodeBase64String(symmetricAESkeys[roomNumber - 1]));

            clientRecord.setClientDHParameters(clientDhParameters);
            clientRecord.setSharedKey(sharedKey);
            clientRecord.setSymmetricAESKey(symmetricAESkeys[roomNumber - 1]);
            clientRecord.setPublicKey(clientCert.getPublicKey());

            logger.log(Level.INFO, "Obtained chat room AES key");

        } catch (Exception e) {
            System.out.println("AS thread error: " + e.getMessage());
            e.printStackTrace();
        }

        _app.setTitle(_app.getTitle() + String.valueOf(roomNumber));
        return roomNumber;
    }


    private int readKeyStore(String keyStoreFilename, String alias, char[] keyStorePassword,
                             char[] keyPassword, int roomNumber) {

        KeyPair kp = null;
        int result = ChatServer.ERROR;
        try {
            kp =
                    PublicKeyUtil.getKeyPairFromKeyStore(keyStoreFilename, alias, keyStorePassword,
                            keyPassword);
            if (kp != null) {
                result = ChatServer.SUCCESS;

                // _layout.show(_appFrame.getContentPane(), "ActivityPanel");
                // _thread = new AuthServerThread(this);
                // _thread.start();
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
            System.out.println(e);
            result = ChatServer.WRONG_PASSWORD;
            if (e instanceof FileNotFoundException) {
                result = ChatServer.KEYSTORE_FILE_NOT_FOUND;
                System.out.println("LOL");
            }
        }


        this.kpArr[roomNumber - 1] = kp;

        logger.log(Level.INFO, "Read Keystore: " + keyStoreFilename + "Status: " + result);

        return result;
    }

    void refreshSymmetricAESKey(int roomNumber) {

        logger.log(Level.CONFIG, "Request for key refreshment");
        symmetricAESkeys[roomNumber - 1] = SymmetricKeyUtil.generateSymmetricAESKey();
        Collection<ClientRecord> clients = null;
        if (roomNumber == 1) {
            clients = _clientsRoom1.values();
        } else if (roomNumber == 2) {
            clients = _clientsRoom2.values();
        }

        String keyRefreshMsg = "0#";
        if (clients != null) {
            for (ClientRecord c : clients) {

                Socket socket = c.getClientSocket();

                if (socket.isConnected()) {
                    PrintWriter out;
                    try {
                        out = new PrintWriter(socket.getOutputStream(), true);
                        String encryptedNewKey =
                                PublicKeyUtil.encrypt(Base64.encodeBase64String(symmetricAESkeys[roomNumber - 1]), c.getPublicKey());
                        keyRefreshMsg = keyRefreshMsg + encryptedNewKey;
                        out.println(keyRefreshMsg);
                        logger.log(Level.INFO, "Published new chat room AES key");
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
            }
        }
    }


    class ChatServerHelperThread extends Thread {

        private ChatServer _cs;
        private int _port;

        public ChatServerHelperThread(ChatServer cs, int port) {
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

                    int roomNumber = authenticate(clientRecord);
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

                System.err.println("Could not listen on port: " + _port);
                System.exit(-1);

            } catch (Exception e) {

                e.printStackTrace();
                System.exit(1);
            }
        }
    }
}
