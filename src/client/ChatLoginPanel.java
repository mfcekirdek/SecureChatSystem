// ChatLoginPanel.java
//
// Last modified 1/30/2000 by Alan Frindell
// Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
// GUI class for the login panel.
//
// You should not have to modify this class.
package client;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.ComboBoxModel;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class ChatLoginPanel extends JPanel {

    private final static Logger logger = Logger.getLogger(ChatLoginPanel.class.getName());
    private JTextField _loginNameField;
    private JPasswordField _passwordField;
    private JTextField _serverHostField;
    private JTextField _serverPortField;
    private JTextField _caHostField;
    private JTextField _caPortField;
    private JTextField _keyStoreNameField;
    private JComboBox<Integer> _roomNumber;
    private JPasswordField _keyStorePasswordField;
    private JLabel _errorLabel;
    private JButton _connectButton;
    private ChatClient _client;

    public ChatLoginPanel(ChatClient client) {
        logger.setLevel(Level.INFO);
        _client = client;

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
        JLabel label;

        setLayout(gridBag);

        addLabel(gridBag, "Welcome to Chat", SwingConstants.CENTER, 1, 0, 2, 1);
        addLabel(gridBag, "Username: ", SwingConstants.LEFT, 1, 1, 1, 1);
        addLabel(gridBag, "Password: ", SwingConstants.LEFT, 1, 2, 1, 1);
        addLabel(gridBag, "KeyStore File Name: ", SwingConstants.LEFT, 1, 3, 1, 1);
        addLabel(gridBag, "KeyStore Password: ", SwingConstants.LEFT, 1, 4, 1, 1);
        addLabel(gridBag, "Server Host Name: ", SwingConstants.LEFT, 1, 5, 1, 1);
        addLabel(gridBag, "Server Port: ", SwingConstants.LEFT, 1, 6, 1, 1);
        addLabel(gridBag, "CA Host Name: ", SwingConstants.LEFT, 1, 7, 1, 1);
        addLabel(gridBag, "CA Port: ", SwingConstants.LEFT, 1, 8, 1, 1);
        addLabel(gridBag, "Room Number: ", SwingConstants.LEFT, 1, 9, 1, 1);

        _loginNameField = new JTextField();
        addField(gridBag, _loginNameField, 2, 1, 1, 1);
        _passwordField = new JPasswordField();
        _passwordField.setEchoChar('*');
        addField(gridBag, _passwordField, 2, 2, 1, 1);

        _keyStoreNameField = new JTextField();
        addField(gridBag, _keyStoreNameField, 2, 3, 1, 1);
        _keyStorePasswordField = new JPasswordField();
        _keyStorePasswordField.setEchoChar('*');
        addField(gridBag, _keyStorePasswordField, 2, 4, 1, 1);

        _serverHostField = new JTextField();
        addField(gridBag, _serverHostField, 2, 5, 1, 1);
        _serverPortField = new JTextField();
        addField(gridBag, _serverPortField, 2, 6, 1, 1);

        _caHostField = new JTextField();
        addField(gridBag, _caHostField, 2, 7, 1, 1);
        _caPortField = new JTextField();
        addField(gridBag, _caPortField, 2, 8, 1, 1);

        _roomNumber = new JComboBox<Integer>();
        addCombobox(gridBag, _roomNumber, 2, 9, 1, 1);


        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER, 1, 10, 2, 1);

        setFieldsDefaults();

        _errorLabel.setForeground(Color.red);

        _connectButton = new JButton("Connect");
        c.gridx = 1;
        c.gridy = 11;
        c.gridwidth = 2;
        gridBag.setConstraints(_connectButton, c);
        add(_connectButton);

        _connectButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                connect();
            }
        });
    }

    private JLabel addLabel(GridBagLayout gridBag, String labelStr, int align, int x, int y, int width,
                            int height) {
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
        gridBag.setConstraints(label, c);
        add(label);

        return label;
    }

    private void addField(GridBagLayout gridBag, JTextField field, int x, int y, int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        field.setPreferredSize(new Dimension(96, field.getMinimumSize().height));
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(field, c);
        add(field);
    }

    private void addCombobox(GridBagLayout gridBag, JComboBox<Integer> field, int x, int y, int width,
                             int height) {
        GridBagConstraints c = new GridBagConstraints();
        field.setPreferredSize(new Dimension(96, field.getMinimumSize().height));
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        gridBag.setConstraints(field, c);
        ComboBoxModel<Integer> model = new DefaultComboBoxModel<Integer>(new Integer[]{1, 2});
        field.setModel(model);
        add(field);
    }

    private void setFieldsDefaults() {

        _loginNameField.setText("");
        _passwordField.setText("");
        _keyStoreNameField.setText("");
        _keyStorePasswordField.setText("");
        _caHostField.setText("localhost");
        _caPortField.setText("6666");
        _serverHostField.setText("localhost");
        _serverPortField.setText("7777");
    }

    private void connect() {

        int serverPort;
        int caPort;

        String loginName = _loginNameField.getText();
        char[] password = _passwordField.getPassword();

        String keyStoreName = _keyStoreNameField.getText();
        char[] keyStorePassword = _keyStorePasswordField.getPassword();

        String serverHost = _serverHostField.getText();
        String caHost = _caHostField.getText();
        int roomNumber = (Integer) _roomNumber.getSelectedItem();

        if (loginName.equals("") || password.length == 0 || keyStoreName.equals("")
                || keyStorePassword.length == 0 || serverHost.equals("")
                || _serverPortField.getText().equals("") || caHost.equals("")
                || _caPortField.getText().equals("")) {

            _errorLabel.setText("Missing required field.");

            return;

        } else {

            _errorLabel.setText(" ");

        }

        try {

            serverPort = Integer.parseInt(_serverPortField.getText());
            caPort = Integer.parseInt(_caPortField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return;
        }

        logger.log(Level.INFO, "Connecting...");

        switch (_client.connect(loginName, password, keyStoreName, keyStorePassword, caHost, caPort,
                serverHost, serverPort, roomNumber)) {

            case ChatClient.SUCCESS:
                // Nothing happens, this panel is now hidden
                _errorLabel.setText(" ");
                break;
            case ChatClient.CONNECTION_REFUSED:
            case ChatClient.BAD_HOST:
                _errorLabel.setText("Connection Refused!");
                break;
            case ChatClient.ERROR:
                _errorLabel.setText("ERROR!  Stop That!");
                break;

        }

        logger.log(Level.INFO, "Connected");

    }
}
