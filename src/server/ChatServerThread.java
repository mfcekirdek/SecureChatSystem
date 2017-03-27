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
import java.util.Enumeration;
import java.util.Hashtable;

// Crypto

public class ChatServerThread extends Thread {


  private Socket _socket = null;
  private ChatServer _server = null;
  private Hashtable _records = null;

  public ChatServerThread(ChatServer server, Socket socket, int roomNumber) {

    super("ChatServerThread");
    _server = server;
    _socket = socket;
    if (roomNumber == 1)
      _records = server.getClientRecordsA();
    else if (roomNumber == 2)
      _records = server.getClientRecordsB();
  }

  public void run() {

    try {

      BufferedReader in = new BufferedReader(new InputStreamReader(_socket.getInputStream()));

      String receivedMsg;

      while ((receivedMsg = in.readLine()) != null) {

        Enumeration theClients = _records.elements();

        while (theClients.hasMoreElements()) {

          ClientRecord c = (ClientRecord) theClients.nextElement();

          Socket socket = c.getClientSocket();

          if (socket.isConnected()) {
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            out.println(receivedMsg);
          }

          else {
            System.out.println("Socket kapali, client odadan cikariliyor..");
            _records.remove(c);
            socket.close();
          }


        }
      }

      _socket.shutdownInput();
      _socket.shutdownOutput();
      _socket.close();

    } catch (IOException e) {

      e.printStackTrace();
    }

  }
}
