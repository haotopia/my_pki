import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.operator.OperatorCreationException;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class ReasonForm {
    private JButton loginButton;
    private JRadioButton a1RB;
    private JRadioButton a3RB;
    private JRadioButton a2RB;
    private JRadioButton a4RB;
    private JPanel rootpanel;

    public ReasonForm(User user,boolean flag) {
        JFrame jFrame = new JFrame("ReasonForm");
        jFrame.setContentPane(rootpanel);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.pack();
        jFrame.setVisible(true);

        ButtonGroup group = new ButtonGroup();
        group.add(a1RB);
        group.add(a2RB);
        group.add(a3RB);
        group.add(a4RB);

        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                int reason = 10;

                Date now = new Date();
                Calendar notBefor = new GregorianCalendar();
                notBefor.setTime(now);
                Calendar notAfter = new GregorianCalendar();
                notAfter.setTime(now);
                notAfter.add(Calendar.YEAR,10);

                if(a1RB.isSelected()){
                    reason = 1;
                }else if (a2RB.isSelected()){
                    reason = 2;
                }else if (a3RB.isSelected()){
                    reason = 3;
                }else if (a4RB.isSelected()){
                    reason = 4;
                }
                if(flag){
                    try {
                        ECC ecc = new ECC();
                        ecc.DestroyCer(user.id,reason);
                    } catch (NoSuchProviderException | NoSuchAlgorithmException | IOException | CertificateException | SQLException | OperatorCreationException | CRLException | InvalidKeySpecException e) {
                        e.printStackTrace();
                    }
                }else{
                    try {
                        ECC ecc = new ECC();
                        ECC.DestroyCer(user.id,reason);
                        ECC.certificate(user,notBefor.getTime(),notAfter.getTime(),ecc.keyPair);
                        ecc.setCertificate(ecc.keyPair,user.id_cord_number,user.id,user.name);
                    } catch (NoSuchProviderException | NoSuchAlgorithmException | IOException | CertificateException | SQLException | OperatorCreationException | CRLException | InvalidKeySpecException | ParseException | KeyStoreException | InvalidKeyException | SignatureException e) {
                        e.printStackTrace();
                    }
                }

                try {
                    new pkiguiForm(user);
                } catch (IOException | SQLException e) {
                    e.printStackTrace();
                }
                jFrame.revalidate();
                jFrame.setVisible(false);
            }
        });
    }
}
