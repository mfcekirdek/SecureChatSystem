//  ClientRecord.java
package server;

// Java
// socket
import java.net.Socket;
// Crypto

// You may need to expand this class for anonymity and revocation control.
public class ClientRecord {

    Socket _socket = null;

    public ClientRecord(Socket socket) {

        _socket = socket;
    }

    public Socket getClientSocket() {

        return _socket;
    }
}
