//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package server;

// Java General

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
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;

import javax.swing.JFrame;

import org.apache.commons.codec.binary.Base64;

import util.DH;
import util.PublicKeyUtil;
import util.SymmetricKeyUtil;

public class ChatServer {


  public static final int SUCCESS = 0;
  public static final int KEYSTORE_FILE_NOT_FOUND = 1;
  public static final int ERROR = 2;
  public static final int WRONG_PASSWORD = 3;

  // private Hashtable _clients;
  private Hashtable _clientsRoomA;
  private Hashtable _clientsRoomB;

  private int _clientID = 0;
  private int _port;
  private String _hostName = null;
  // Some hints: security related fields.
  private static final String ALIAS_A = "Server1";
  private static final String ALIAS_B = "Server2";
  private static final char[] KEY_PASSWORD_A = "s3rv3r1k3y".toCharArray();
  private static final char[] KEY_PASSWORD_B = "s3rv3r2k3y".toCharArray();

  private ServerSocket _serverSocket = null;

  // private HashMap<String, BigInteger> dhParameters;
  // private HashMap<String, BigInteger> clientDhParameters;
  // private BigInteger sharedKey;

  private KeyPair[] kpArr = new KeyPair[2];
  private X509Certificate[] chatRoomCertArr = new X509Certificate[2];
  private byte[][] symmetricAESkeys = new byte[2][16]; // 128 bit key
  private byte[][] initVector = new byte[2][16]; // 128 bit key


  private HashMap<Integer, HashMap<String, BigInteger>> dhParameters =
      new HashMap<Integer, HashMap<String, BigInteger>>(); // clientID,HashMap


  public ChatServer() {

    try {

      _clientsRoomA = new Hashtable();
      _clientsRoomB = new Hashtable();
      _serverSocket = null;
      _clientID = -1;
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

    JFrame app = new JFrame();
    ChatServerLoginPanel login = new ChatServerLoginPanel(this);
    app.getContentPane().add(login);
    app.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    app.pack();
    app.show();
  }

  public void connect(int port) {
    try {
      _port = port;
      _serverSocket = new ServerSocket(_port);
      System.out.println("ChatServer is running on " + _hostName + " port " + _port);

      while (true) {

        Socket socket = _serverSocket.accept();
        ClientRecord clientRecord = new ClientRecord(socket);


        int roomNumber = authenticate(clientRecord);

        System.out.println("ROOMNUMBER :" + roomNumber);

        if (roomNumber == 1)
          _clientsRoomA.put(new Integer(_clientID++), clientRecord);
        else if (roomNumber == 2)
          _clientsRoomB.put(new Integer(_clientID++), clientRecord);


        ChatServerThread thread = new ChatServerThread(this, socket, roomNumber);
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


  @SuppressWarnings("unchecked")
  public Hashtable<Integer, ClientRecord> getClientRecordsA() {

    return _clientsRoomA;
  }

  @SuppressWarnings("unchecked")
  public Hashtable<Integer, ClientRecord> getClientRecordsB() {

    return _clientsRoomB;
  }


  public int[] startup(String keyStoreFilenameA, char[] keyStorePasswordA,
      String keyStoreFilenameB, char[] keyStorePasswordB, int portNumber) {

    int[] results = new int[2];
    results[0] = readKeyStore(keyStoreFilenameA, ALIAS_A, keyStorePasswordA, KEY_PASSWORD_A, 1);
    results[1] = readKeyStore(keyStoreFilenameB, ALIAS_B, keyStorePasswordB, KEY_PASSWORD_B, 2);
    readChatRoomCertificatesFromFile();
    generateAESKeys();

    return results;
  }

  private void generateAESKeys() {
    symmetricAESkeys[0] = SymmetricKeyUtil.generateSymmetricAESKey();
    symmetricAESkeys[1] = SymmetricKeyUtil.generateSymmetricAESKey();
    initVector[0] = SymmetricKeyUtil.generate16BytesIV();
    initVector[1] = SymmetricKeyUtil.generate16BytesIV();
  }

  private void readChatRoomCertificatesFromFile() {

    String selectedChatRoom = "Server" + 1 + "_CA_.cer";
    chatRoomCertArr[0] = PublicKeyUtil.getCertFromFile(selectedChatRoom);

    selectedChatRoom = "Server" + 2 + "_CA_.cer";
    chatRoomCertArr[1] = PublicKeyUtil.getCertFromFile(selectedChatRoom);
  }


  private int authenticate(ClientRecord clientRecord) {
    refreshSymmetricAESKey(1); /*TODO simdilik burada cagirip test ettim. Buradan silinip bir kullanici ciktiginde cagirilacak */
    
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
      X509Certificate clientCert = (X509Certificate) ois.readObject();

      try {
        clientCert.verify(caCert.getPublicKey());
      } catch (Exception e) {
        socket.close();
        System.out.println("VERIFY EDILEMEDI SOCKET KAPATILDI..");
      }

      _out.println("true");

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
      System.out.println("Symmetric key: "
          + Base64.encodeBase64String(symmetricAESkeys[roomNumber - 1]));

      clientRecord.setClientDHParameters(clientDhParameters);
      clientRecord.setSharedKey(sharedKey);
      clientRecord.setSymmetricAESKey(symmetricAESkeys[roomNumber - 1]);
      clientRecord.setPublicKey(clientCert.getPublicKey());

      System.out.println(clientRecord.toString());

    } catch (Exception e) {
      System.out.println("AS thread error: " + e.getMessage());
      e.printStackTrace();
    }
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
    return result;
  }

  public void refreshSymmetricAESKey(int roomNumber) {
    symmetricAESkeys[roomNumber - 1] = SymmetricKeyUtil.generateSymmetricAESKey();
    Enumeration clients = null;
    if (roomNumber == 1) {
      clients = _clientsRoomA.elements();
    } else if (roomNumber == 2) {
      clients = _clientsRoomB.elements();
    }

    String keyRefreshMsg = "0#";
    while (clients.hasMoreElements()) {

      ClientRecord c = (ClientRecord) clients.nextElement();

      Socket socket = c.getClientSocket();

      if (socket.isConnected()) {
        PrintWriter out;
        try {
          out = new PrintWriter(socket.getOutputStream(), true);
          String encryptedNewKey= PublicKeyUtil.encrypt(Base64.encodeBase64String(symmetricAESkeys[roomNumber - 1]), c.getPublicKey());
          keyRefreshMsg = keyRefreshMsg + encryptedNewKey;
          System.out.println(keyRefreshMsg);
          out.println(keyRefreshMsg);
        } catch (IOException e) {
          e.printStackTrace();
        } catch (Exception e) {
          e.printStackTrace();
        }

      }
    }
  }
}
