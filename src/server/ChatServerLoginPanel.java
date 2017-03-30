package server;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ChatServerLoginPanel extends JPanel {

    private final static Logger logger = Logger.getLogger(ChatServerLoginPanel.class.getName());
    private JPasswordField _keystorePass1Field;
    private JPasswordField _keypairPass1Field;
    private JPasswordField _keystorePass2Field;
    private JPasswordField _keypairPass2Field;
    private JTextField _keystoreFile1Field;
    private JTextField _keystoreFile2Field;
    private JTextField _portField;
    private JLabel _errorLabel;
    private JButton _startupButton;
    private ChatServer _cs;

    public ChatServerLoginPanel(ChatServer cs) {

        _cs = cs;
        logger.setLevel(Level.CONFIG);

        try {
            componentInit();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "AuthServerPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void componentInit() throws Exception {

        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();

        setLayout(gridBag);

        addLabel(gridBag, "Chat Server Startup Panel", SwingConstants.CENTER, 1, 0, 2, 1);
        addLabel(gridBag, "Room1 Keystore File: ", SwingConstants.LEFT, 1, 1, 1, 1);
        addLabel(gridBag, "Room1 Keystore Password: ", SwingConstants.LEFT, 1, 2, 1, 1);
        addLabel(gridBag, "Room1 Keypair Password: ", SwingConstants.LEFT, 1, 3, 1, 1);
        addLabel(gridBag, "Room2 Keystore File: ", SwingConstants.LEFT, 1, 4, 1, 1);
        addLabel(gridBag, "Room2 Keystore Password: ", SwingConstants.LEFT, 1, 5, 1, 1);
        addLabel(gridBag, "Room2 Keypair Password: ", SwingConstants.LEFT, 1, 6, 1, 1);
        addLabel(gridBag, "Port Number: ", SwingConstants.LEFT, 1, 7, 1, 1);


        _keystoreFile1Field = new JTextField();
        addField(gridBag, _keystoreFile1Field, 2, 1, 1, 1);

        _keystorePass1Field = new JPasswordField();
        _keystorePass1Field.setEchoChar('*');
        addField(gridBag, _keystorePass1Field, 2, 2, 1, 1);

        _keypairPass1Field = new JPasswordField();
        _keypairPass1Field.setEchoChar('*');
        addField(gridBag, _keypairPass1Field, 2, 3, 1, 1);

        _keystoreFile2Field = new JTextField();
        addField(gridBag, _keystoreFile2Field, 2, 4, 1, 1);

        _keystorePass2Field = new JPasswordField();
        _keystorePass2Field.setEchoChar('*');
        addField(gridBag, _keystorePass2Field, 2, 5, 1, 1);

        _keypairPass2Field = new JPasswordField();
        _keypairPass2Field.setEchoChar('*');
        addField(gridBag, _keypairPass2Field, 2, 6, 1, 1);

        _portField = new JTextField();
        addField(gridBag, _portField, 2, 7, 1, 1);

        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER, 1, 8, 2, 1);

        _errorLabel.setForeground(Color.red);

        _startupButton = new JButton("Startup");
        addButton(gridBag, _startupButton, 1, 9, 2, 1);


        setFieldsDefaults();

        _startupButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                int status = startup();
                if (status == ChatServer.SUCCESS)
                    _cs._layout.show(_cs._app.getContentPane(), "Clients");
            }
        });
    }

    private void setFieldsDefaults() {
        _keystoreFile1Field.setText("room1keystore.jks");
        _keystorePass1Field.setText("room1keystore");
        _keypairPass1Field.setText("room1keypair");
        _keystoreFile2Field.setText("room2keystore.jks");
        _keystorePass2Field.setText("room2keystore");
        _keypairPass2Field.setText("room2keypair");
        _portField.setText("7777");
    }

    private void addButton(GridBagLayout gridBag, JButton button, int x, int y, int width, int height) {

        GridBagConstraints c = new GridBagConstraints();

        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        c.insets = new Insets(10, 10, 20, 10);
        gridBag.setConstraints(_startupButton, c);
        add(_startupButton);

    }

    private JLabel addLabel(GridBagLayout gridBag, String labelStr, int align,
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

    private int startup() {
        int _asPort;

        String _keystoreFile1 = _keystoreFile1Field.getText();
        char[] _keystorePwd1 = _keystorePass1Field.getPassword();
        char[] _keypairPwd1 = _keypairPass1Field.getPassword();

        String _keystoreFile2 = _keystoreFile2Field.getText();
        char[] _keystorePwd2 = _keystorePass2Field.getPassword();
        char[] _keypairPwd2 = _keypairPass2Field.getPassword();

        if (_portField.getText().equals("")
                || _keystoreFile1.equals("")
                || _keystorePwd1.length == 0
                || _keypairPwd1.length == 0
                || _keystoreFile2.equals("")
                || _keystorePwd2.length == 0
                || _keypairPwd2.length == 0) {

            _errorLabel.setText("Missing required field.");

            return ChatServer.ERROR;

        } else {
            _errorLabel.setText(" ");
        }

        try {

            _asPort = Integer.parseInt(_portField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return ChatServer.ERROR;
        }

        int[] status = _cs.startup(_keystoreFile1, _keystorePwd1, _keypairPwd1,
                _keystoreFile2, _keystorePwd2, _keypairPwd2, _asPort).clone();

        if (status[0] == ChatServer.SUCCESS && status[1] == ChatServer.SUCCESS) {
            // success
            _errorLabel.setText(" ");
            _cs.connect(_asPort);
            return ChatServer.SUCCESS;
        } else if (status[0] == ChatServer.WRONG_PASSWORD || status[1] == ChatServer.WRONG_PASSWORD) {
            // wrong password
            _errorLabel.setText("Keystore was tampered with, or password was incorrect");
        } else if (status[0] == ChatServer.KEYSTORE_FILE_NOT_FOUND || status[1] == ChatServer.KEYSTORE_FILE_NOT_FOUND) {
            _errorLabel.setText("KeyStore file not found!");
        } else if (status[0] == ChatServer.ERROR || status[1] == ChatServer.ERROR) {
            _errorLabel.setText("Unknown Error!");
        }

        return ChatServer.ERROR;
    }

}
