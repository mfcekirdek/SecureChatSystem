package server;

import java.awt.Dimension;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.TitledBorder;

public class ChatServerConnectedClientsPanel extends JPanel {

    private final static Logger logger = Logger.getLogger(ChatServerConnectedClientsPanel.class.getName());
    private static final String ROOM_A_STR = "Room A";
    private static final String ROOM_B_STR = "Room B";
    private ChatServer _cs;
    private JList _room1List, _room2List;
    private DefaultListModel<String> modelRoom1, modelRoom2;


    public ChatServerConnectedClientsPanel(ChatServer cs) {
        super(true);
        logger.setLevel(Level.INFO);
        _cs = cs;

        try {
            componentInit();
        } catch (Exception e) {
            logger.log(Level.SEVERE, e.getMessage());
            e.printStackTrace();
        }
    }

    private void componentInit() {


        this.setLayout(null);
        initRoom1Panel();
        initRoom2Panel();
    }

    private void initRoom1Panel() {
        JPanel panel = new JPanel();
        TitledBorder titled = new TitledBorder(ROOM_A_STR);
        panel.setBorder(titled);
        panel.setBounds(5,5, 165, 260);
        panel.setLayout(null);
        modelRoom1 = new DefaultListModel<>();
        _room1List = new JList(modelRoom1);
        JScrollPane pane = new JScrollPane(_room1List);

        pane.setBounds(8,17, 150, 235);
        panel.add(pane);
        add(panel);
    }

    private void initRoom2Panel() {

        JPanel panel = new JPanel();
        TitledBorder titled = new TitledBorder(ROOM_B_STR);
        titled.setTitleJustification(TitledBorder.TRAILING);
        panel.setBorder(titled);
        panel.setBounds(175,5, 165, 260);
        panel.setLayout(null);
        modelRoom2 = new DefaultListModel<>();
        _room2List = new JList(modelRoom2);
        JScrollPane pane = new JScrollPane(_room2List);

        pane.setBounds(8,17, 150, 235);
        panel.add(pane);
        add(panel);
    }

    public void updateClientLists() {

        modelRoom1 = new DefaultListModel<String>();
        modelRoom2 = new DefaultListModel<String>();
        Collection<ClientRecord> clientsA = _cs.getClientRecordsA().values();
        Collection<ClientRecord> clientsB = _cs.getClientRecordsB().values();


        for(ClientRecord c : clientsA){
            String item = c.getLoginName();
            if(!modelRoom1.contains(item)){
                modelRoom1.addElement(item);
            }
        }

        for(ClientRecord c : clientsB){
            String item = c.getLoginName();
            if(!modelRoom2.contains(item)){
                modelRoom2.addElement(item);
            }
        }
        _room1List.setModel(modelRoom1);
        _room2List.setModel(modelRoom2);
    }

    public static void main(String[] args) {
        JFrame app = new JFrame();
        ChatServerConnectedClientsPanel panel = new ChatServerConnectedClientsPanel(null);
        app.getContentPane().add(panel);
        app.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        app.setMinimumSize(new Dimension(350, 300));
        app.pack();
        app.setLocationByPlatform(true);
        app.setResizable(false);
        app.setVisible(true);
    }


}
