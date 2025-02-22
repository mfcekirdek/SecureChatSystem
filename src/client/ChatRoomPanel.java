//  ChatRoomPanel.java
//
//  Last modified 1/30/2000 by Alan Frindell
//
//  GUI class for the chat room.
//
//  You should not need to modify this class.
package client;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.text.DefaultCaret;

public class ChatRoomPanel extends JPanel {

    // logger
    private final static Logger logger = Logger.getLogger(ChatClient.class.getName());

    // UI objects
    private JTextArea _inputArea;
    private JTextArea _outputArea;
    private JButton _quitButton;
    private ChatClient _client;

    public ChatRoomPanel(ChatClient client) {

        logger.setLevel(Level.INFO);
        _client = client;

        try {
            componentInit();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "ChatRoomPanel error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Initializes UI components
     */
    private void componentInit() throws Exception {
        GridBagLayout gridBag = new GridBagLayout();
        GridBagConstraints c = new GridBagConstraints();

        setLayout(gridBag);

        addLabel(gridBag, "Chat Room: ", SwingConstants.LEFT, 0, 0, 1, 1);
        _outputArea = addArea(gridBag, new Dimension(400, 192), 0, 1);
        _outputArea.setEditable(false);

        addLabel(gridBag, "Your Message: ", SwingConstants.LEFT, 0, 2, 1, 1);
        _inputArea = addArea(gridBag, new Dimension(400, 96), 0, 3);
        _inputArea.addKeyListener(new KeyAdapter() {

            public void keyTyped(KeyEvent e) {
                inputKeyTyped(e);
            }
        });

        _quitButton = new JButton("Leave Chat Room");
        _quitButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {
                quit();
            }
        });
        c.insets = new Insets(4, 4, 4, 4);
        c.weighty = 1.0;   //request any extra vertical space
        c.gridx = 2;
        c.gridy = 4;
        c.gridwidth = GridBagConstraints.REMAINDER;
        c.anchor = GridBagConstraints.SOUTHEAST; //bottom of space
        gridBag.setConstraints(_quitButton, c);
        add(_quitButton);

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
    private JLabel addLabel(GridBagLayout gridBag, String labelStr, int align,
                            int x, int y, int width, int height) {
        GridBagConstraints c = new GridBagConstraints();
        JLabel label = new JLabel(labelStr);
        if (align == SwingConstants.LEFT) {
            c.insets = new Insets(10, 4, 0, 4);
        }
        c.fill = GridBagConstraints.HORIZONTAL;
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
     * @param prefSize preferred size of area
     * @param x x value of grid cell
     * @param y y value of grid cell
     */
    private JTextArea addArea(GridBagLayout gridBag, Dimension prefSize,
                              int x, int y) {
        JScrollPane scroller;
        JTextArea area = new JTextArea();
        GridBagConstraints c = new GridBagConstraints();

        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(4, 4, 4, 4);
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = 3;
        scroller = new JScrollPane(area);
        scroller.setPreferredSize(prefSize);
        gridBag.setConstraints(scroller, c);
        add(scroller);
        DefaultCaret caret = (DefaultCaret) area.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

        return area;
    }

    /**
     * Returns the output area
     * @return JTextArea object
     */
    public JTextArea getOutputArea() {
        return _outputArea;
    }


    private void inputKeyTyped(KeyEvent e) {
        String msg;

        if (e.getKeyChar() == KeyEvent.VK_ENTER) {
            msg = _inputArea.getText();
            _inputArea.setText("");
            if (msg.length() == 0) {
                return;
            }
            _client.sendMessage(msg);
        }
    }

    /**
     * Calls client's quit method
     */
    private void quit() {
        _client.quit();
    }
}
