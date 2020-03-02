import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import netscape.javascript.JSObject;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.util.test.FixedSecureRandom;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class User {
    public  String name;
    public String id_cord_number;
    public String id;

    private String pswReCode(String psw) {

        RIPEMD160Digest md = new RIPEMD160Digest();
        md.update(psw.getBytes(StandardCharsets.UTF_8),0,psw.length());
        byte[] result = new byte[md.getDigestSize()];
        md.doFinal(result,0);
        String ret = new String(result);
        return ret;
    }

    public void login(String icn,String psw) throws SQLException {


        if(icn.isEmpty()||psw.isEmpty()){
            new ShowAlter("请输入信息");
        }else {
            String q = "SELECT user_info.name,user_log_info.password,user_info.ID FROM user_info LEFT OUTER JOIN user_log_info ON user_info.ID=user_log_info.ID WHERE user_info.id_card_number =";
            Sqllink sqllink = new Sqllink();
            Statement state = sqllink.con.createStatement();
            ResultSet res = state.executeQuery(q+icn);
            String recodePsw = pswReCode(psw);
            long regTime = System.currentTimeMillis();
            if(res.next()) {
                if (!res.getString("password").equals(recodePsw)) {
                    name = res.getString("name");
                    id_cord_number = icn;
                    this.id=res.getString("ID");
                    sqllink.con.close();
                    String q2 = "UPDATE user_log_info SET latest_login = '"+regTime+"' WHERE ID = '"+id+"'";
                    Sqllink db2 = new Sqllink();
                    Statement state2 = db2.con.createStatement();
                    state2.executeUpdate(q2);
                    db2.con.close();
                } else {
                    sqllink.con.close();
                    new ShowAlter("密码错误");
                }
            }else{
                new ShowAlter("查无此人");
            }

        }
    }

    public void register(String name,String icn,String psw) throws SQLException {
        if(icn.isEmpty()||psw.isEmpty()||name.isEmpty()) {
            new ShowAlter("请输入信息");
        }else {
//            SimpleDateFormat sdf=new SimpleDateFormat("yyyy-MM-dd");
//            String regTime = sdf.format(new Date());

            String mid = "SELECT max(ID) FROM user_info";
            Sqllink mdb = new Sqllink();
            Statement idstate = mdb.con.createStatement();
            ResultSet max = idstate.executeQuery(mid);
            int uid = Integer.parseInt(max.getString(1))+1;
            mdb.con.close();


            long regTime = System.currentTimeMillis();
            String q="INSERT INTO user_info(ID, name, id_card_number, reigest_date) VALUES ("+uid+","+name+","+icn+","+regTime+")";
            Sqllink db = new Sqllink();
            Statement state = db.con.createStatement();
            int res = state.executeUpdate(q);
            db.con.close();

            String reCode = pswReCode(psw);
            String q2="INSERT INTO user_log_info(ID,password,latest_login) VALUES("+uid+",'"+reCode+"',"+regTime+")";
            Sqllink db2 = new Sqllink();
            Statement state2 = db2.con.createStatement();
            int res2 = state2.executeUpdate(q2);
            db2.con.close();

            this.id = String.valueOf(uid);
            this.name=name;
            this.id_cord_number=icn;
        }

    }
    public static void saveCer(String serial,String path,String u_id,byte[] public_key,byte[] private_key,String cer) throws SQLException, IOException {
        String puk=Base64.getEncoder().encodeToString(public_key);
        String prk=Base64.getEncoder().encodeToString(private_key);



        String q="INSERT INTO certificates(serial, local_file, u_id,public_key,private_key,cer_file) VALUES ('"+serial+"','"+path+"','"+u_id+"','"+saveFile(u_id+"Pub",public_key,".key")+"','"+saveFile(u_id+"Pre",private_key,".key")+"','"+cer+"')";
        Sqllink db = new Sqllink();
        Statement state = db.con.createStatement();
        int res = state.executeUpdate(q);
        db.con.close();
    }
    public static JSONObject jsonGet(String id) throws SQLException, IOException {
        String q = "SELECT local_file FROM certificates WHERE u_id =";
        Sqllink sqllink = new Sqllink();
        Statement state = sqllink.con.createStatement();
        ResultSet res = state.executeQuery(q+id);
        if(res.next()) {
            BufferedReader br = new BufferedReader(new FileReader(res.getString("local_file")));
            String line;
            line=br.readLine();
            br.close();
            return JSON.parseObject(line);
        }else{
            return null;
        }

    }

    private static String saveFile(String name,byte[] content,String ex) throws IOException {
        String wc=Base64.getEncoder().encodeToString(content);
        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\";
        File cer = new File(path,name+ex);
        FileOutputStream fop = new FileOutputStream(cer);
        fop.write(wc.getBytes());
        fop.flush();
        fop.close();
        return path+name+ex;
    }


}
