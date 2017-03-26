//
//  AuthServerThread.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Accepts connection requests and processes them
package authserver;

// socket
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.HashMap;



// Swing
import javax.swing.JTextArea;
//  Crypto



import util.DH;
import util.PublicKeyUtil;

public class AuthServerThread extends Thread {

    private AuthServer _as;
    private ServerSocket _serverSocket = null;
    private int _portNum;
    private String _hostName;
    private JTextArea _outputArea;
    private BufferedReader _in;
    private PrintWriter _out;
    private HashMap<String,BigInteger> dhParameters;
    private HashMap<String,BigInteger> clientDhParameters;
    private BigInteger sharedKey;

    public AuthServerThread(AuthServer as) {

        super("AuthServerThread");
        _as = as;
        _portNum = as.getPortNumber();
        _outputArea = as.getOutputArea();
        _serverSocket = null;

        try {

            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

        } catch (UnknownHostException e) {
            _hostName = "0.0.0.0";
        }
    }
    
    //  Accept connections and service them one at a time
    public void run() {
        try {
            _serverSocket = new ServerSocket(_portNum);
            _outputArea.append("AS waiting on " + _hostName + " port " + _portNum);
            while (true) {
                Socket socket = _serverSocket.accept();
                
                _in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                _out = new PrintWriter(socket.getOutputStream(), true);
               
                X509Certificate caCert = PublicKeyUtil.getCertFromFile("ca.cer");

                String msg;
                int roomNumber = -1;
               
               if((msg = _in.readLine()) != null)
                 roomNumber = Integer.parseInt(msg.substring(msg.indexOf("#")+1));
                
               
                String selectedChatRoom = "Server"+roomNumber+"_CA_.cer";
                X509Certificate serverCert =PublicKeyUtil.getCertFromFile(selectedChatRoom);
                
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
                HashMap<String,BigInteger> dhParametersToSend = (HashMap<String, BigInteger>) dhParameters.clone();
                dhParametersToSend.remove("secret");
                oos.writeObject(dhParametersToSend);
                
                
                // TODO decrypt edilecek..
                clientDhParameters = (HashMap<String, BigInteger>) ois.readObject();
                System.out.println("SERVER : " + clientDhParameters);
               
                sharedKey = DH.getSharedKey(clientDhParameters.get("public"), dhParameters.get("secret"), dhParameters.get("primeValue"));
                System.err.println(sharedKey);
                
                //
                //  Got the connection, now do what is required
                //  
            }
        } catch (Exception e) {
            System.out.println("AS thread error: " + e.getMessage());
            e.printStackTrace();
        }

    }
    
    
}
