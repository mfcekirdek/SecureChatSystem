//
//  CertificateAuthorityThread.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Accepts connection requests and processes them
package ca;

// socket
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

// Swing
import javax.swing.JTextArea;
//  Crypto

public class CertificateAuthorityThread extends Thread {

    private CertificateAuthority _ca;
    private ServerSocket _serverSocket = null;
    private int _portNum;
    private String _hostName;
    private JTextArea _outputArea;

    public CertificateAuthorityThread(CertificateAuthority ca) {

        super("CertificateAuthorityThread");
        _ca = ca;
        _portNum = ca.getPortNumber();
        _outputArea = ca.getOutputArea();
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

            _outputArea.append("CA waiting on " + _hostName + " port " + _portNum);

            while (true) {

                Socket socket = _serverSocket.accept();

                //
                //  Got the connection, now do what is required
                //  First complete the handshake
                //  Determine who sent it
                //  verify the username and password hash
                //  issue a certificate signed with the private key
                //

            }
        } catch (Exception e) {
            System.out.println("CA thread error: " + e.getMessage());
            e.printStackTrace();
        }

    }
}
