import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.sql.SQLException;

public class registerForm {
    private JPanel rootpanel;
    private JButton registerButton;
    private JTextField nameInput;
    private JTextField pswinput;
    private JTextField icnInput;

    public registerForm(){
        JFrame jFrame = new JFrame("registerFForm");
        jFrame.setContentPane(rootpanel);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.pack();
        jFrame.setVisible(true);
        registerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                User user = new User();
                try {
                    user.register(nameInput.getText(),icnInput.getText(),pswinput.getText());
                    try {
                        new pkiguiForm(user);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        });
    }
}
