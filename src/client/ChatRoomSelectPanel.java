package client;

import javax.swing.*;
import java.awt.*;

public class ChatRoomSelectPanel extends JPanel {

    JComboBox<String> _chatRoomComboBox;
    JButton _connectButton;
    private String[] _roomArr;


    public ChatRoomSelectPanel() {

        _roomArr = new String[] {"Room 1", "Room 2", "Room 3", "Room 4"};

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("ChatLoginPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }



    private void componentInit() throws Exception {

        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();

        setLayout(gridBag);

        addLabel(gridBag, "Chat Room: ", SwingConstants.RIGHT, 1, 1, 1, 1);

        addComboBox(gridBag,3, 1, 2, 1);

        _connectButton = new JButton("Connect");
        c.insets = new Insets(20, 10, 10, 0);
        c.gridx = 1;
        c.gridy = 10;
        c.gridwidth = 4;
        c.gridheight = 1;

        gridBag.setConstraints(_connectButton, c);
        add(_connectButton);

    }

    private JComboBox<String> addComboBox(GridBagLayout gridBag, int x, int y, int width, int height) {

        GridBagConstraints c = new GridBagConstraints();
        _chatRoomComboBox = new JComboBox<>();

        ComboBoxModel roomsModel = new DefaultComboBoxModel<String>(_roomArr);
        _chatRoomComboBox.setModel(roomsModel);

        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        c.insets = new Insets(10, 0, 0, 10);
        gridBag.setConstraints(_chatRoomComboBox, c);
        add(_chatRoomComboBox);

        return _chatRoomComboBox;

    }

    JLabel addLabel(GridBagLayout gridBag, String labelStr, int align,
                    int x, int y, int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        JLabel label = new JLabel(labelStr);
        if (align == SwingConstants.LEFT) {
            c.anchor = GridBagConstraints.WEST;
        } else {
            c.insets = new Insets(10, 0, 10, 0);
        }
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        c.insets = new Insets(10, 10, 0, 10);
        gridBag.setConstraints(label, c);
        add(label);

        return label;
    }

    public static void main(String[] args) {
        JFrame frame = new JFrame("Select a Chat Room");
        frame.getContentPane().add(new ChatRoomSelectPanel());
        frame.pack();
        frame.show();
    }

}
