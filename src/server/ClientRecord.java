//  ClientRecord.java
package server;

import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

// You may need to expand this class for anonymity and revocation control.
public class ClientRecord {

    private final static Logger logger = Logger.getLogger(ClientRecord.class.getName());
    private int _clientID;
    private Socket _socket = null;
    private HashMap<String, BigInteger> clientDHParameters;
    private BigInteger sharedKey;
    private PublicKey publicKey;
    private byte[] symmetricAESKey;
    private int _room;

    public ClientRecord(int clientID, Socket socket) {
        logger.setLevel(Level.INFO);
        _clientID = clientID;
        _socket = socket;
    }

    @Override
    public String toString() {
        return "ClientRecord [_socket=" + _socket + ", clientDHParameters=" + clientDHParameters
                + ", sharedKey=" + sharedKey + ", publicKey=" + publicKey + ", symmetricAESKey="
                + Arrays.toString(symmetricAESKey) + "]";
    }

    public Socket getClientSocket() {
        return _socket;
    }

    public HashMap<String, BigInteger> getClientDHParameters() {
        return clientDHParameters;
    }

    public void setClientDHParameters(HashMap<String, BigInteger> clientDHParameters) {
        this.clientDHParameters = clientDHParameters;
    }

    public BigInteger getSharedKey() {
        return sharedKey;
    }

    public void setSharedKey(BigInteger sharedKey) {
        this.sharedKey = sharedKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getSymmetricAESKey() {
        return symmetricAESKey;
    }

    public void setSymmetricAESKey(byte[] symmetricAESKey) {
        this.symmetricAESKey = symmetricAESKey;
    }

    public void setRoom(int _room) {
        this._room = _room;

    }

    public int getRoom() {
        return this._room;
    }

    public int getClientID() {
        return _clientID;
    }
}
