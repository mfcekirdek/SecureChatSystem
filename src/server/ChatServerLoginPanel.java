package server;

import authserver.AuthServer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ChatServerLoginPanel extends JPanel {

    JPasswordField _privateKeyPassAField;
    JPasswordField _privateKeyPassBField;
    JTextField _portField;
    JTextField _keystoreFileNameAField;
    JTextField _keystoreFileNameBField;
    JLabel _errorLabel;
    JButton _startupButton;
    ChatServer _as;

    public ChatServerLoginPanel(ChatServer as) {
        _as = as;

        try {
            componentInit();
        } catch (Exception e) {
            System.out.println("AuthServerPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    void componentInit() throws Exception {
        /* TODO: TitledBorderLayout */
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();
        JLabel label;

        setLayout(gridBag);

        addLabel(gridBag, "Chat Server Startup Panel", SwingConstants.CENTER, 1, 0, 2, 1);
        addLabel(gridBag, "KeyStore A File Name: ", SwingConstants.LEFT, 1, 1, 1, 1);
        addLabel(gridBag, "KeyStore A Password: ", SwingConstants.LEFT, 1, 2, 1, 1);
        addLabel(gridBag, "KeyStore B File Name: ", SwingConstants.LEFT, 1, 3, 1, 1);
        addLabel(gridBag, "KeyStore B Password: ", SwingConstants.LEFT, 1, 4, 1, 1);
        addLabel(gridBag, "Port Number: ", SwingConstants.LEFT, 1, 5, 1, 1);


        _keystoreFileNameAField = new JTextField();
        addField(gridBag, _keystoreFileNameAField, 2, 1, 1, 1);

        _privateKeyPassAField = new JPasswordField();
        _privateKeyPassAField.setEchoChar('*');
        addField(gridBag, _privateKeyPassAField, 2, 2, 1, 1);

        _keystoreFileNameBField = new JTextField();
        addField(gridBag, _keystoreFileNameBField, 2, 3, 1, 1);

        _privateKeyPassBField = new JPasswordField();
        _privateKeyPassBField.setEchoChar('*');
        addField(gridBag, _privateKeyPassBField, 2, 4, 1, 1);

        _portField = new JTextField();
        addField(gridBag, _portField, 2, 5, 1, 1);

        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER, 1, 6, 2, 1);

        // just for testing purposs
        _errorLabel.setForeground(Color.red);

        _startupButton = new JButton("Startup");
        c.gridx = 1;
        c.gridy = 8;
        c.gridwidth = 2;
        c.insets = new Insets(10, 10,20, 10);
        gridBag.setConstraints(_startupButton, c);
        add(_startupButton);

        _startupButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                startup();
            }
        });
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
        c.insets = new Insets(5, 5, 0, 5);
        gridBag.setConstraints(label, c);
        add(label);

        return label;
    }

    void addField(GridBagLayout gridBag, JTextField field, int x, int y,
                  int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        field.setPreferredSize(new Dimension(96,
                field.getMinimumSize().height));
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        c.insets = new Insets(5, 5, 0, 5);
        gridBag.setConstraints(field, c);
        add(field);
    }

    private void startup() {
        int _asPort;

        String _keystoreFileNameA = _keystoreFileNameAField.getText();
        char[] _privateKeyPassA = _privateKeyPassAField.getPassword();
        String _keystoreFileNameB = _keystoreFileNameBField.getText();
        char[] _privateKeyPassB = _privateKeyPassBField.getPassword();

        if (_portField.getText().equals("")
                || _privateKeyPassA.length == 0
                || _keystoreFileNameA.equals("")
                || _privateKeyPassB.length == 0
                || _keystoreFileNameB.equals("")) {

            _errorLabel.setText("Missing required field.");

            return;

        } else {
            _errorLabel.setText(" ");
        }

        try {

            _asPort = Integer.parseInt(_portField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return;
        }

        int[] status = _as.startup(_keystoreFileNameA, _privateKeyPassA, _keystoreFileNameB, _privateKeyPassB, _asPort).clone();

        if (status[0] == ChatServer.SUCCESS && status[1] == ChatServer.SUCCESS) {
            // success
            _errorLabel.setText(" ");
        } else if (status[0] == ChatServer.WRONG_PASSWORD || status[1] == ChatServer.WRONG_PASSWORD) {
            // wrong password
            _errorLabel.setText("Keystore was tampered with, or password was incorrect");
        } else if (status[0] == ChatServer.KEYSTORE_FILE_NOT_FOUND || status[1] == ChatServer.KEYSTORE_FILE_NOT_FOUND) {
            _errorLabel.setText("KeyStore file not found!");
        } else if (status[0] == ChatServer.ERROR || status[1] == ChatServer.ERROR) {
            _errorLabel.setText("Unknown Error!");
        }
    }

    public static void main(String[] args) {
        JFrame app = new JFrame();
        ChatServerLoginPanel login = new ChatServerLoginPanel(null);
        app.getContentPane().add(login);
        app.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        app.pack();
        app.show();
    }
}
