import com.alibaba.fastjson.JSONObject;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class pkiguiForm {
    private JPanel rootpanel;
    private JTextField nameText;
    private JPanel top;
    private JButton ReigButton;
    private JButton LoginButton;
    private JButton DownButton;
    private JTextArea stateInfo;
    private JTextField icnText;
    private JTable table1;
    private JButton FlushButton;
    private JButton DestroyButton;
    private JButton MessageButton;
    private JTextField messageInput;

    public pkiguiForm() {

        JFrame jFrame = new JFrame("pkiguiForm");
        jFrame.setContentPane(rootpanel);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.pack();
        jFrame.setVisible(true);
        final Object[] columnNames ={"名称","内容"};
        TableModel tableModel = new DefaultTableModel(null,columnNames);
        table1.setModel(tableModel);
        LoginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new loginForm();
                jFrame.revalidate();
                jFrame.setVisible(false);
            }
        });
        ReigButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new registerForm();
                jFrame.revalidate();
                jFrame.setVisible(false);
            }
        });


        MessageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    ECC ecc = new ECC();
                    ECC.makeEncodeMessage(messageInput.getText());
                    String states = stateInfo.getText();
                    stateInfo.setText(states+"\n"+"加密及签发完成\n 开始演示解密和验签\n生成的加密消息、签名、加密密钥已下发\n");
                    String message = ECC.messageDecode();
                    stateInfo.setText(stateInfo.getText()+"解密完成，证书验证有效，签名有效\n"+message);
                } catch (NoSuchProviderException | NoSuchAlgorithmException | SignatureException | InvalidKeySpecException | BadPaddingException | InvalidKeyException | SQLException | NoSuchPaddingException | IOException | IllegalBlockSizeException | CertificateException | CMSException | OperatorCreationException | CRLException e) {
                    e.printStackTrace();
                }

            }
        });
    }

    public pkiguiForm(User user) throws IOException, SQLException {
        JFrame jFrame = new JFrame("pkiguiForm");
        jFrame.setContentPane(rootpanel);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.pack();
        jFrame.setVisible(true);
        nameText.setText(user.name);
        icnText.setText(user.id_cord_number);

        final Object[] columnNames ={"名称","内容"};
        /*JSONObject object =User.jsonGet(user.id);
        assert object != null;
        Object[][] data= new Object[][]{
                {"版本",object.getString("version")},
                {"序列号",object.getString("serial")},
                {"加密方式",object.getString("signature")},
                {"发证机构",object.getString("issuer")},
                {"公钥",object.getString("public_key")},
                {"生效时间",object.getString("not_befor")},
                {"到期时间",object.getString("not_after")},
                {"证书签名",object.getString("signature_algorithm")},
        };*/

        TableModel tableModel = new DefaultTableModel(null,columnNames);
        table1.setModel(tableModel);

        LoginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new loginForm();
                jFrame.revalidate();
                jFrame.setVisible(false);
            }
        });
        ReigButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new registerForm();
                jFrame.revalidate();
                jFrame.setVisible(false);
            }
        });
        DownButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                Date now = new Date();
                Calendar notBefor = new GregorianCalendar();
                notBefor.setTime(now);
                Calendar notAfter = new GregorianCalendar();
                notAfter.setTime(now);
                notAfter.add(Calendar.YEAR,10);
                try {
                    stateInfo.setText("开始生成证书");
                    ECC ecc = new ECC();
                    JSONObject object = ECC.certificate(user,notBefor.getTime(),notAfter.getTime(),ecc.keyPair);
                    stateInfo.setText("证书生成完成");
                    ecc.setCertificate(ecc.keyPair,user.id_cord_number,user.id,user.name);
                    final Object[] columnNames ={"名称","内容"};
                    Object[][] data={
                            {"版本",object.getString("version")},
                            {"序列号",object.getString("serial")},
                            {"加密方式",object.getString("signature")},
                            {"发证机构",object.getString("issuer")},
                            {"公钥",object.getString("public_key")},
                            {"生效时间",object.getString("not_befor")},
                            {"到期时间",object.getString("not_after")},
                            {"证书签名",object.getString("signature_algorithm")},
                    };
                    TableModel tableModel = new DefaultTableModel(data,columnNames);
                    table1.setModel(tableModel);

                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException | NoSuchProviderException | SQLException | CertificateException | ParseException | OperatorCreationException | KeyStoreException | InvalidKeySpecException e) {
                    e.printStackTrace();
                }
            }
        });

        FlushButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ReasonForm(user,false);
                jFrame.revalidate();
                jFrame.setVisible(false);
            }
        });

        DestroyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ReasonForm(user,true);
                jFrame.revalidate();
                jFrame.setVisible(false);
            }
        });

        MessageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {

            }
        });

        MessageButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    ECC ecc = new ECC();
                    ECC.makeEncodeMessage(messageInput.getText());
                    String states = stateInfo.getText();
                    stateInfo.setText(states+"\n"+"加密及签发完成\n 开始演示解密和验签\n生成的加密消息、签名、加密密钥已下发\n");
                    String message = ECC.messageDecode();
                    stateInfo.setText(stateInfo.getText()+"解密完成，证书验证有效，签名有效\n"+message);
                } catch (NoSuchProviderException | NoSuchAlgorithmException | SignatureException | InvalidKeySpecException | BadPaddingException | InvalidKeyException | SQLException | NoSuchPaddingException | IOException | IllegalBlockSizeException | CertificateException | CMSException | OperatorCreationException | CRLException e) {
                    e.printStackTrace();
                }

            }
        });
    }

    public static void main(String[] args) {
        new pkiguiForm();
    }

}
