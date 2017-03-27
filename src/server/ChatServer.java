//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package server;

// Java General
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
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
import java.util.HashMap;
import java.util.Hashtable;
// import sun.security.x509.*;



import javax.swing.JFrame;

import org.apache.commons.codec.binary.Base64;

import util.DH;
import util.PublicKeyUtil;
import util.SymmetricKeyUtil;

// Crypto

public class ChatServer {


  public static final int SUCCESS = 0;
  public static final int KEYSTORE_FILE_NOT_FOUND = 1;
  // public static final int PERMISSIONS_FILE_NOT_FOUND = 2;
  // public static final int PERMISSIONS_FILE_TAMPERED = 3;
  public static final int ERROR = 4;
  public static final int WRONG_PASSWORD = 5;

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
  // private KeyManagerFactory keyManagerFactory;
  // private TrustManagerFactory trustManagerFactory;


  private HashMap<String, BigInteger> dhParameters;
  private HashMap<String, BigInteger> clientDhParameters;
  private BigInteger sharedKey;

  private KeyPair[] kpArr = new KeyPair[2];
  private X509Certificate[] chatRoomCertArr = new X509Certificate[2];
  private String[] symmetricAESkeys = new String[2]; // 128 bit key
  private byte[][] initVector = new byte[16][2]; // 128 bit key


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

    try {

      if (args.length != 1) {

        // Might need more arguments if extending for extra credit
        System.out.println("Usage: java ChatServer portNum");
        return;

      } else {

        ChatServer server = new ChatServer();
        server.run();
      }

    } catch (NumberFormatException e) {

      System.out.println("Useage: java ChatServer host portNum");
      e.printStackTrace();
      return;

    } catch (Exception e) {

      System.out.println("ChatServer error: " + e.getMessage());
      e.printStackTrace();
    }
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


        int roomNumber = authenticate(socket);

        System.out.println("ROOMNUMBER :" + roomNumber);

        if (roomNumber == 1)
          _clientsRoomA.put(new Integer(_clientID++), clientRecord);
        else if (roomNumber == 2)
          _clientsRoomB.put(new Integer(_clientID++), clientRecord);


        ChatServerThread thread = new ChatServerThread(this, socket, roomNumber);
        thread.start();
      }

      // _serverSocket.close();

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

    //
    // System.out.println(keyStoreFilenameA);
    // System.out.println(keyStorePasswordA);
    // System.out.println(keyStoreFilenameB);
    // System.out.println(keyStorePasswordB);
    // System.out.println(portNumber);

    int[] results = new int[2];
    results[0] = readKeyStore(keyStoreFilenameA, ALIAS_A, keyStorePasswordA, KEY_PASSWORD_A, 1);
    results[1] = readKeyStore(keyStoreFilenameB, ALIAS_B, keyStorePasswordB, KEY_PASSWORD_B, 2);
    readChatRoomCertificatesFromFile();
    generateAESKeys();

    return results;
  }
  
  private void generateAESKeys() {
    symmetricAESkeys[0] = Base64.encodeBase64String(SymmetricKeyUtil.generateSymmetricAESKey());
    symmetricAESkeys[1] = Base64.encodeBase64String(SymmetricKeyUtil.generateSymmetricAESKey());
    initVector[0] = SymmetricKeyUtil.generate16bitIV();
    initVector[1] = SymmetricKeyUtil.generate16bitIV();
  }


  private void readChatRoomCertificatesFromFile() {

    String selectedChatRoom = "Server" + 1 + "_CA_.cer";
    chatRoomCertArr[0] = PublicKeyUtil.getCertFromFile(selectedChatRoom);

    selectedChatRoom = "Server" + 2 + "_CA_.cer";
    chatRoomCertArr[1] = PublicKeyUtil.getCertFromFile(selectedChatRoom);
  }



  private int authenticate(Socket socket) {
    int roomNumber = -1;

    try {
      BufferedReader _in;
      PrintWriter _out;

      _in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      _out = new PrintWriter(socket.getOutputStream(), true);

      X509Certificate caCert = PublicKeyUtil.getCertFromFile("ca.cer");

      String msg;

      if ((msg = _in.readLine()) != null)
        roomNumber = Integer.parseInt(msg.substring(msg.indexOf("#") + 1));


      X509Certificate serverCert = this.chatRoomCertArr[roomNumber - 1];

      ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
      ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

      oos.writeObject(serverCert);
      X509Certificate clientCert = (X509Certificate) ois.readObject();

      try {
        clientCert.verify(caCert.getPublicKey());
      } catch (Exception e) {
        socket.close();
        System.out.println("VERIFY EDILEMEDI SOCKET KAPATILDI..");
      }

      _out.println("true");

      // TODO encrypt edilecek..
      dhParameters = DH.getDHParameters();
      HashMap<String, String> dhParametersToSend = new HashMap<String, String>();

      String encryptedServerDHPublic =
          PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("public")),
              clientCert.getPublicKey());
      String encryptedServerDHGeneratorValue =
          PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("generatorValue")),
              clientCert.getPublicKey());
      String encryptedServerDHPrimeValue =
          PublicKeyUtil.encrypt(String.valueOf(dhParameters.get("primeValue")),
              clientCert.getPublicKey());

      dhParametersToSend.put("public", encryptedServerDHPublic);
      dhParametersToSend.put("generatorValue", encryptedServerDHGeneratorValue);
      dhParametersToSend.put("primeValue", encryptedServerDHPrimeValue);
      oos.writeObject(dhParametersToSend);


      // TODO decrypt edilecek..
      HashMap<String, String> tmp = (HashMap<String, String>) ois.readObject();
      clientDhParameters = new HashMap<String, BigInteger>();

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
      System.out.println("SERVER : " + clientDhParameters);

      sharedKey =
          DH.getSharedKey(clientDhParameters.get("public"), dhParameters.get("secret"),
              dhParameters.get("primeValue"));
      System.err.println(sharedKey);

      // aynı
      
      byte[] hashOfSharedKey = SymmetricKeyUtil.generateMD5Hash(String.valueOf(sharedKey)).getBytes();
      //System.out.println("hashOfSharedKey : " + Base64.encode(hashOfSharedKey));
      
      hashOfSharedKey = Arrays.copyOf(hashOfSharedKey, 16);
      //System.out.println("hashOfSharedKey 16: " + hashOfSharedKey.length);
      // aynı
      byte [] zeroIV = "0000000000000000".getBytes();
      
      System.out.println("Symmetric AES: " + symmetricAESkeys[0]);
      //System.out.println("String Symm Aes :  " + new String(symmetricAESkeys[0]));
      String chatRoomKey = SymmetricKeyUtil.encrypt(hashOfSharedKey, zeroIV, symmetricAESkeys[0].getBytes());
      _out.println(chatRoomKey);
      System.out.println("Gonderilen:" + chatRoomKey);
      
      
      
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
        // System.out.println(kp.getPublic().toString());
        // System.out.println(kp.getPrivate().toString());
        result = ChatServer.SUCCESS;

        // _layout.show(_appFrame.getContentPane(), "ActivityPanel");
        // _thread = new AuthServerThread(this);
        // _thread.start();
      }

      else
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
}
