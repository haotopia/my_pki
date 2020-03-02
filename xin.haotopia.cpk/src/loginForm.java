import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Arrays;

public class loginForm {
    private JPanel rootpanel;
    private JPasswordField passwordField1;
    private JButton loginButton;
    private JTextField icnInput;

    public loginForm(){
        JFrame jFrame = new JFrame("loginForm");
        jFrame.setContentPane(rootpanel);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.pack();
        jFrame.setVisible(true);
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    User user = new User();
                    user.login(icnInput.getText(), Arrays.toString(passwordField1.getPassword()));
                    new pkiguiForm(user);
                    jFrame.setVisible(false);
                } catch (SQLException | IOException e) {
                    e.printStackTrace();
                }
            }
        });
    }
}

