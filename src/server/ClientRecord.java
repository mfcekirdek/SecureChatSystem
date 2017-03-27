//  ClientRecord.java
package server;

// Java
// socket
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Arrays;
// Crypto
import java.util.HashMap;

// You may need to expand this class for anonymity and revocation control.
public class ClientRecord {

    private Socket _socket = null;
    private HashMap<String, BigInteger> clientDHParameters;
    private BigInteger sharedKey;
    private PublicKey publicKey;
    private byte [] symmetricAESKey;

    public ClientRecord(Socket socket) {

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

    public byte [] getSymmetricAESKey() {
      return symmetricAESKey;
    }

    public void setSymmetricAESKey(byte [] symmetricAESKey) {
      this.symmetricAESKey = symmetricAESKey;
    }
}
