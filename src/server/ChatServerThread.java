//
// ChatServerThread.java
// created 02/18/03 by Ting Zhang
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package server;

// Java

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
// socket
import java.net.Socket;
import java.net.SocketException;
import java.util.Collection;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ChatServerThread extends Thread {

    private final static Logger logger = Logger.getLogger(ChatServer.class.getName());
    private ClientRecord _client = null;
    private Socket _socket = null;
    private ChatServer _server = null;
    private HashMap<Integer, ClientRecord> _records = null;
    private int _roomNumber;

    public ChatServerThread(ChatServer cs, ClientRecord client) {

        super("ChatServerThread");
        logger.setLevel(Level.CONFIG);
        _server = cs;
        _client = client;
        _socket = client.getClientSocket();
        _roomNumber = client.getRoom();

        if (_roomNumber == 1)
            _records = cs.getClientRecordsA();
        else if (_roomNumber == 2)
            _records = cs.getClientRecordsB();

    }


    public void run() {

        try {

            BufferedReader in = new BufferedReader(new InputStreamReader(_socket.getInputStream()));
            String receivedMsg;
            Collection<ClientRecord> theClients;
            /* TODO: connection reset exception */
            while ((receivedMsg = in.readLine()) != null) {

                theClients = _records.values();

                for (ClientRecord c : theClients) {

                    Socket socket = c.getClientSocket();

                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    out.println(receivedMsg);

                }
            }

            logger.log(Level.INFO, "Closed connection: Client " + _client.getClientID());
            removeClient();
            _server.refreshSymmetricAESKey(_roomNumber);
            _server._clientsPanel.updateClientLists();
            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (SocketException e) {
            logger.log(Level.SEVERE, e.getMessage());
        } catch (IOException e) {
            logger.log(Level.SEVERE, e.getMessage());
        }

    }

    private void removeClient() {
        HashMap<Integer, ClientRecord> records = null;
        switch (_roomNumber) {
            case 1:
                records = _server.getClientRecordsA();
                records.remove(_client.getClientID());
                break;
            case 2:
                records = _server.getClientRecordsB();
                records.remove(_client.getClientID());
                break;
        }
    }
}
