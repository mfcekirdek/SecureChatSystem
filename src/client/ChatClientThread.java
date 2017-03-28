/**
 * Created 2/16/2003 by Ting Zhang Part of implementation of the ChatClient to receive all the
 * messages posted to the chat room.
 */
package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JTextArea;

import org.apache.commons.codec.binary.Base64;

import util.PublicKeyUtil;
import util.SymmetricKeyUtil;

public class ChatClientThread extends Thread {

    private final static Logger logger = Logger.getLogger(ChatClientThread.class.getName());
    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;

    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        logger.setLevel(Level.INFO);
        _client = client;
        _socket = client.getSocket();
        _outputArea = client.getOutputArea();
    }

    public void run() {

        try {

            BufferedReader in = new BufferedReader(new InputStreamReader(_socket.getInputStream()));

            String msg;

            while ((msg = in.readLine()) != null) {

                consumeMessage(msg);
            }
            in.close();
            closeConnection();

        } catch (SocketException e) {
            closeConnection();
            logger.log(Level.INFO, "Closed connection");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void consumeMessage(String msg) {

        if (msg != null) {

            String[] msgParts = msg.split("#");
            int msgType = Integer.valueOf(msgParts[0]);

            if (msgType == 1) {

                byte[] encryptedMsg = Base64.decodeBase64(msgParts[1]);
                byte[] iv = Base64.decodeBase64(msgParts[2]);
                String hmac = msgParts[3];
                String calculatedHMAC =
                        SymmetricKeyUtil.getHMACMD5(_client.getSymmetricAESkey().getBytes(), msgParts[1]);

                byte[] decryptedMsg =
                        SymmetricKeyUtil.decrypt(Base64.decodeBase64(_client.getSymmetricAESkey()), iv,
                                encryptedMsg);

                if (hmac.equals(calculatedHMAC)) { // Authenticated
                    try {
                        _outputArea.append(new String(decryptedMsg, "UTF-8"));
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                }
            } else if (msgType == 0) { // Refresh sym key
                try {
                    String decryptedMsg = PublicKeyUtil.decrypt(msgParts[1], _client.getPrivateKey());
                    _client.setSymmetricAESKey(decryptedMsg);
                    logger.log(Level.INFO, "Key refreshment is done");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        }
    }

    private void closeConnection() {
        try {
            _socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
