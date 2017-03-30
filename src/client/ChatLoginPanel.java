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

/**
 * This class represents login panel of client application
 */
public class ChatLoginPanel extends JPanel {

    // logger
    private final static Logger logger = Logger.getLogger(ChatLoginPanel.class.getName());

    // UI variables
    private JTextField _loginNameField;
    private JPasswordField _passwordField;
    private JTextField _serverHostField;
    private JTextField _serverPortField;
    private JTextField _keyStoreNameField;
    private JComboBox<Integer> _roomNumber;
    private JPasswordField _keyStorePasswordField;
    private JLabel _errorLabel;
    private JButton _connectButton;

    // Client object
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

    /**
     * Initializes UI components
     */
    private void componentInit() {
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
        addLabel(gridBag, "Room Number: ", SwingConstants.LEFT, 1, 7, 1, 1);

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

        _roomNumber = new JComboBox<Integer>();
        addCombobox(gridBag, _roomNumber, 2, 7, 1, 1);


        _errorLabel = addLabel(gridBag, " ", SwingConstants.CENTER, 1, 8, 2, 1);

        setFieldsDefaults();

        _errorLabel.setForeground(Color.red);

        _connectButton = new JButton("Connect");
        addButton(gridBag, _connectButton, 1, 9, 2, 1);

        _connectButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                connect();
            }
        });
    }

    /**
     * Adds a label to panel
     * @param gridBag {@link GridBagLayout} object
     * @param labelStr text of label
     * @param align alignment
     * @param x x value of grid cell
     * @param y y value of grid cell
     * @param width width of object in terms of grid
     * @param height height of object in terms of grid
     * @return new label object
     */
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

    /**
     * Adds a text field to panel
     * @param gridBag {@link GridBagLayout} object
     * @param field JTextField object
     * @param x x value of grid cell
     * @param y y value of grid cell
     * @param width width of object in terms of grid
     * @param height height of object in terms of grid
     */
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


    /**
     * Adds a combobox to panel
     * @param gridBag {@link GridBagLayout} object
     * @param field JComboBox object
     * @param x x value of grid cell
     * @param y y value of grid cell
     * @param width width of object in terms of grid
     * @param height height of object in terms of grid
     */
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

    /**
     * Adds a button to panel
     * @param gridBag {@link GridBagLayout} object
     * @param button JButton object
     * @param x x value of grid cell
     * @param y y value of grid cell
     * @param width width of object in terms of grid
     * @param height height of object in terms of grid
     */
    private void addButton(GridBagLayout gridBag, JButton button, int x, int y, int width, int height) {

        GridBagConstraints c = new GridBagConstraints();

        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.gridheight = height;
        c.insets = new Insets(10, 10, 20, 10);
        gridBag.setConstraints(button, c);
        add(button);

    }

    /**
     * Sets fields to given informations.
     */
    private void setFieldsDefaults() {

        _loginNameField.setText("");
        _passwordField.setText("");
        _keyStoreNameField.setText("");
        _keyStorePasswordField.setText("");
        _serverHostField.setText("localhost");
        _serverPortField.setText("7777");
    }

    /**
     * Checks login inputs and calls client's connect method if inputs are valid.
     */
    private void connect() {

        int serverPort;

        String loginName = _loginNameField.getText();
        char[] password = _passwordField.getPassword();

        String keyStoreName = _keyStoreNameField.getText();
        char[] keyStorePassword = _keyStorePasswordField.getPassword();

        String serverHost = _serverHostField.getText();
        int roomNumber = (Integer) _roomNumber.getSelectedItem();

        if (loginName.equals("") || password.length == 0 || keyStoreName.equals("")
                || keyStorePassword.length == 0 || serverHost.equals("")
                || _serverPortField.getText().equals("")) {

            _errorLabel.setText("Missing required field.");

            return;

        } else {

            _errorLabel.setText(" ");

        }

        try {

            serverPort = Integer.parseInt(_serverPortField.getText());

        } catch (NumberFormatException nfExp) {

            _errorLabel.setText("Port field is not numeric.");

            return;
        }

        logger.log(Level.INFO, "Connecting...");

        int connectStatus = _client.connect(loginName, password, keyStoreName, keyStorePassword,
                serverHost, serverPort, roomNumber);

        switch (connectStatus) {

            case ChatClient.SUCCESS:
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
