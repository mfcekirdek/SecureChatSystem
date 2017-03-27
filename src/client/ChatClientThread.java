/**
 *  Created 2/16/2003 by Ting Zhang 
 *  Part of implementation of the ChatClient to receive
 *  all the messages posted to the chat room.
 */
package client;

// socket
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

//  Swing
import javax.swing.JTextArea;

import util.SymmetricKeyUtil;
//  Crypto

public class ChatClientThread extends Thread {

    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;
    
    private String hmacKey = "qnscAdgRlkIhAUPY44oiexBKtQbGY0orf7OV1I50";


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
             byte[] iv = msg.substring(msg.length()-26, msg.length()-24).getBytes();
             String hmac = msg.substring(msg.length()-26);
             String encryptedMsg = msg.substring(0, msg.length()-26);
             String calculatedHMAC = SymmetricKeyUtil.getHMACMD5(hmacKey, encryptedMsg);
             String decryptedMsg = SymmetricKeyUtil.decrypt(_client.getSymmetricAESkey().getBytes(), iv, encryptedMsg.getBytes());

             if(hmac.equals(calculatedHMAC)) { // Authenticated
               _outputArea.append(decryptedMsg);
             }
        }

    }
}
