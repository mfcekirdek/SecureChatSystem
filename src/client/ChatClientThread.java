/**
 * Created 2/16/2003 by Ting Zhang
 * Part of implementation of the ChatClient to receive
 * all the messages posted to the chat room.
 */
package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;

import javax.swing.JTextArea;

import org.apache.commons.codec.binary.Base64;
import util.SymmetricKeyUtil;

public class ChatClientThread extends Thread {

    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;

    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        _client = client;
        _socket = client.getSocket();
        _outputArea = client.getOutputArea();
    }

    public void run() {

        try {

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            _socket.getInputStream()));

            String msg;

            while ((msg = in.readLine()) != null) {

                consumeMessage(msg);
            }

            _socket.close();

        } catch (IOException e) {

            e.printStackTrace();
        }

    }

    public void consumeMessage(String msg) {

        if (msg != null) {

            String[] msgParts = msg.split("#");

            byte[] encryptedMsg = Base64.decodeBase64(msgParts[0]);
            byte[] iv = Base64.decodeBase64(msgParts[1]);
            String hmac = msgParts[2]; 
            String calculatedHMAC = SymmetricKeyUtil.getHMACMD5(_client.getSymmetricAESkey().getBytes(), msgParts[0]);

            byte[] decryptedMsg =
                    SymmetricKeyUtil.decrypt(Base64.decodeBase64(_client.getSymmetricAESkey()), iv, encryptedMsg);

            if (hmac.equals(calculatedHMAC)) { // Authenticated
                try {
                    _outputArea.append(new String(decryptedMsg, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
