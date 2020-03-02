import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.dvcs.Data;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jcajce.provider.symmetric.ARC4;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class ECC {
    public ECPublicKey publicKey;
    public ECPrivateKey privateKey;
    public KeyPair keyPair;
    public JSONObject certificate;
    public boolean[] UNIQUE_IDENTIFIER;

    public ECC() throws NoSuchProviderException, NoSuchAlgorithmException, UnsupportedEncodingException {
        setKeys();
        MessageDigest md = MessageDigest.getInstance("RipeMD160");
        md.update("NCEPU.xin.haotopia".getBytes(StandardCharsets.UTF_8));
        byte[] result = md.digest();
        String suid = new BigInteger(1,result).toString(16);

        BitSet bitSet = BitSet.valueOf(suid.getBytes());
        boolean[] uid = new boolean[bitSet.size()];
        for(int i =0;i<bitSet.size();i++){
            uid[i]=bitSet.get(i);
        }
        UNIQUE_IDENTIFIER = uid;
    }
    private void setKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        //生成公钥和私钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECIES", "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        publicKey = ecPublicKey;
        privateKey = ecPrivateKey;
        this.keyPair=keyPair;
    }

    public static ECPublicKey string2PublicKey(String pubstr) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(pubstr);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC","BC");
        ECPublicKey publicKey = (ECPublicKey)keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static PrivateKey string2PrivateKey(String priStr) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(priStr);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC","BC");
        PrivateKey privateKey =keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public static byte[] publicEncrypt(byte[] content,PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    public static byte[] privateEncrypt(byte[] content,PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
        byte[] bytes=cipher.doFinal(content);
        return bytes;
    }

    public static byte[] publicDecrypt(byte[] content,PublicKey publickey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.DECRYPT_MODE,publickey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    public static byte[] privateDecrypt(byte[] content,PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    public static JSONObject certificate(User user, Date notBefore, Date notAfter,KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, SQLException {

        String version = "3";
        BigInteger serial = getCerId();
        //String serial = UUID.randomUUID().toString();



        String signature = "SHA1withECDSA";
        String issuer = "C=CN,O=NCEPU,OU=NCEPU";
        byte[] publickey = keyPair.getPublic().getEncoded();
        String pka = "ECDSAEncryption";
        byte[] encodepk = ecdsaEncode(keyPair);

        MessageDigest sha1 = MessageDigest.getInstance("SHA");
        sha1.update("haotopia.xin".getBytes());
        byte[] iui = sha1.digest();

        MessageDigest sha2 = MessageDigest.getInstance("SHA");
        sha2.update(user.id_cord_number.getBytes());
        byte[] sui = sha1.digest();


        //组装json
        JSONObject object = new JSONObject();
        object.put("version",version);
        object.put("serial",serial);
        object.put("signature",signature);
        object.put("issuer",issuer);
        object.put("public_key", publickey);
        object.put("public_key_algorithm",pka);
        object.put("public_key_hash",encodepk);
        object.put("not_befor",date2string(notBefore));
        object.put("not_after",date2string(notAfter));
        object.put("issuer_unique_identifier",iui);
        object.put("subject_unique_identifier",sui);
        object.put("Certificate_signature_algorithm","SHA1withECDSA");
        String cer = object.toJSONString();
        object.put("signature_algorithm",encodepk);

        String fullCer = object.toJSONString();
        fileOutput(user.id_cord_number,fullCer);
        String filePath = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\";
        User.saveCer(serial.toString(),filePath+user.id_cord_number+".txt",user.id,keyPair.getPublic().getEncoded(),keyPair.getPrivate().getEncoded(),filePath+user.id_cord_number+".crt");

        return object;
    }

    private static byte[] ecdsaEncode(KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        Signature signature = Signature.getInstance("SHA1withECDSA");
        signature.initSign(privateKey);
        signature.update(publicKey.getEncoded());
        return signature.sign();
    }

    private static byte[] cerEncode(KeyPair keyPair, String str) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signature = Signature.getInstance("SHA1withECDSA");
        signature.initSign(privateKey);
        signature.update(Byte.parseByte(str.toString()));
        return signature.sign();
    }


    private static String date2string(Date date){
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        return sdf.format(date);
    }
    public void setCertificate(KeyPair keyPair,String fil,String u_id,String name) throws IOException, SQLException, ParseException, OperatorCreationException, CertificateException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, InvalidKeySpecException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        JSONObject object = User.jsonGet(u_id);
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        assert object != null;
        Date notBefor = sdf.parse(object.getString("not_befor"));
        Date notAfter = sdf.parse(object.getString("not_after"));
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
          new X500Name("CN=Haotopia"),
                object.getBigInteger("serial"),
                notBefor,
                notAfter,
                new X500Name("CN="+name),
                subjectPublicKeyInfo
        );


        PrivateKey CaPriKey = file2PriKey("C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\1Pre.key");

        //builder.setIssuerUniqueID(UNIQUE_IDENTIFIER);
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(CaPriKey);
        X509CertificateHolder x509CertificateHolder = builder.build(contentSigner);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(x509CertificateHolder.toASN1Structure()
                .getEncoded());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(inputStream);
        inputStream.close();



        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates";
        File cer = new File(path,fil+".crt");
        FileOutputStream fop = new FileOutputStream(cer);
        fop.write(certificate.getEncoded());
        fop.flush();
        fop.close();


    }
    private static void fileOutput(String file,String str) throws IOException {
        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates";
        File cer = new File(path,file+".txt");
        FileOutputStream fop = new FileOutputStream(cer);
        fop.write(str.getBytes());
        fop.flush();
        fop.close();
    }

    public static X509Certificate file2Cer(String name) throws IOException, CertificateException {
        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\";
        File file = new File(path+name+".crt");
        InputStream input =new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate oCer = (X509Certificate)cf.generateCertificate(input);
        input.close();
        return oCer;
    }
    public static boolean isExceed(X509Certificate cer){
        Date now = new Date();
        Date after=cer.getNotAfter();
        return now.after(after);
    }

    public static boolean isAbolished(X509Certificate cer) throws SQLException {
        String serial = cer.getSerialNumber().toString();
        String q = "SELECT state FROM certificates WHERE serial = ";
        Sqllink mdb = new Sqllink();
        Statement qstate = mdb.con.createStatement();
        ResultSet res = qstate.executeQuery(q+"'"+serial+"'");
        int state = Integer.parseInt(res.getString("state"));
        mdb.con.close();
        return state<1;
    }



    public static BigInteger getCerId() throws SQLException, NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("RipeMD160");
        md.update("NCEPU.xin.haotopia".getBytes(StandardCharsets.UTF_8));
        byte[] result = md.digest();
        BigInteger suid = new BigInteger(1,result);

        String mid = "SELECT max(ID) FROM certificates";
        Sqllink mdb = new Sqllink();
        Statement idstate = mdb.con.createStatement();
        ResultSet max = idstate.executeQuery(mid);
        int uid = Integer.parseInt(max.getString(1))+1;
        mdb.con.close();

        return (new BigInteger(String.valueOf(uid))).add(suid);

    }

    public static void makeCrl(PrivateKey privateKey,String fil) throws IOException, CertificateException, CRLException, OperatorCreationException, SQLException {
        List<BigInteger> serial = new ArrayList<>();
        List<Integer> reason = new ArrayList<>();
        List<Date> desData = new ArrayList<>();

        String q = "SELECT serial,reason,des_date FROM certificates WHERE state = 0";
        Sqllink sqllink = new Sqllink();
        Statement state = sqllink.con.createStatement();
        ResultSet res = state.executeQuery(q);

        while(res.next()){
            serial.add(new BigInteger(res.getString("serial")));
            reason.add(res.getInt("reason"));
            desData.add(new Date(Long.parseLong(res.getString("des_date"))));
        }


        X509v2CRLBuilder builder = new X509v2CRLBuilder(
          new X500Name("CN=Haotopia"),new Date()
        );

        for(int i=0;i<serial.size();i++) {
            System.out.println(serial.get(i));
            builder.addCRLEntry(serial.get(i), desData.get(i), reason.get(i));
        }

        ContentSigner signer =  new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(privateKey);
        X509CRLHolder holder = builder.build(signer);

        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates";
        File cer = new File(path,fil+".crl");
        FileOutputStream fop = new FileOutputStream(cer);
        fop.write(holder.getEncoded());
        fop.flush();
        fop.close();


    }

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, OperatorCreationException, CertificateException, CRLException, IOException, SQLException, InvalidKeySpecException, CMSException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, SignatureException {

      /* ECC ecc = new ECC();
       makeEncodeMessage("hello word");

        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\1Pre.key";

        byte[] message =  decodeMessage(decodeKey("signkey.txt",file2PriKey(path)),"encodeMessage.txt");

        MessageDigest md = MessageDigest.getInstance("SHA256");
        md.update(message);
        byte[] result = md.digest();
        if(checkHash(result,file2Cer("456"),"messageHash.txt")){
            System.out.println("ok");
        }
        System.out.println(new String(message));
*/

    }

    public static  String messageDecode() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, CertificateException, OperatorCreationException, SQLException, SignatureException, CMSException, CRLException {
        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\1Pre.key";

        byte[] message =  decodeMessage(decodeKey("signkey.txt",file2PriKey(path)),"encodeMessage.txt");

        MessageDigest md = MessageDigest.getInstance("SHA256");
        md.update(message);
        byte[] result = md.digest();
        if(checkHash(result,file2Cer("456"),"messageHash.txt")){
            System.out.println("ok");
        }
        return new String(message);
    }

    public static void checkCer(X509Certificate cer) throws IOException, CertificateException, SQLException, NoSuchPaddingException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, OperatorCreationException, BadPaddingException, CRLException, NoSuchProviderException, CMSException {
        if(isAbolished(cer)){
            System.out.println("已经废除");
        }else if(isExceed(cer)){
            System.out.println("已过期");
        }else if (!isCaCreated(cer)){
            System.out.println("非法证书");
        }else{
            System.out.println("证书状态正常");
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

    private static PrivateKey file2PriKey(String name) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\";
        //BufferedReader br = new BufferedReader(new FileReader(path+name+".key"));

        BufferedReader br = new BufferedReader(new FileReader(name));
        String line;
        line=br.readLine();
        br.close();
        return string2PrivateKey(line);
    }

    private static PublicKey file2Publickey(String name) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\";
        //BufferedReader br = new BufferedReader(new FileReader(path+name+".key"));

        BufferedReader br = new BufferedReader(new FileReader(name));
        String line;
        line=br.readLine();
        br.close();
        return string2PublicKey(line);
    }


    public static void DestroyCer(String u_id,int reason) throws NoSuchProviderException, NoSuchAlgorithmException, SQLException, IOException, InvalidKeySpecException, CertificateException, CRLException, OperatorCreationException {
        ECC ecc = new ECC();
        String q = "SELECT private_key FROM certificates WHERE id =15";
        Sqllink sqllink = new Sqllink();
        Statement state = sqllink.con.createStatement();
        ResultSet res = state.executeQuery(q);
        PrivateKey prikey = file2PriKey(res.getString("private_key"));
        sqllink.con.close();
        Date date = new Date();
        long times = date.getTime();
        String upq="UPDATE certificates SET state =0,reason="+reason+",des_date="+times+" WHERE u_id = "+u_id+" AND state=1";
        Sqllink db = new Sqllink();
        Statement state2 = db.con.createStatement();
        state2.executeUpdate(upq);
        db.con.close();
        makeCrl(prikey,"HaotopiaCrl");
    }

    public static boolean isCaCreated(X509Certificate cer) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException, CRLException, OperatorCreationException, CMSException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, SignatureException, SQLException {
        ECC ecc = new ECC();

        String q = "SELECT public_key FROM certificates WHERE id =15";
        Sqllink sqllink = new Sqllink();
        Statement state = sqllink.con.createStatement();
        ResultSet res = state.executeQuery(q);
        PublicKey prikey = file2Publickey(res.getString("public_key"));
        sqllink.con.close();
/*
        byte[] content = MessageDigest.getInstance("SHA-1").digest(cer.getEncoded());

        Signature signature = Signature.getInstance("SHA256withECDSA");//"SHA256withECDSA"
        signature.initVerify(prikey);
        signature.update(cer.getEncoded());*/
        Certificate checkCer = (Certificate)cer;
        checkCer.verify(prikey);
        return true;

    }

    public static String encodeMessage(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        String key = RandomStringUtils.randomAlphanumeric(16);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(),"AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,keySpec);
        byte[] encrypted =cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        saveFile("encodeMessage",encrypted,".txt");

        return key;
    }

    public static byte[] sigKey(PublicKey pubkey,String key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.ENCRYPT_MODE,pubkey);
        return cipher.doFinal(key.getBytes());
    }

    public static void makeEncodeMessage(String message) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, SQLException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, SignatureException {
        ECC ecc = new ECC();

        String q = "SELECT public_key FROM certificates WHERE id=15";
        Sqllink sqllink = new Sqllink();
        Statement state = sqllink.con.createStatement();
        ResultSet res = state.executeQuery(q);
        PublicKey pubkey = file2Publickey(res.getString("public_key"));
        sqllink.con.close();

        MessageDigest md = MessageDigest.getInstance("SHA256");
        md.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] result = md.digest();

        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\2Pre.key";

        PrivateKey prikey = file2PriKey(path);
        byte[] encodeHash = encodeHash(result,prikey);

        saveFile("messageHash",encodeHash,".txt");

        byte[] enKey = sigKey(pubkey,encodeMessage(message));

        saveFile("signKey",enKey,".txt");
    }

    public static byte[] encodeHash(byte[] content,PrivateKey prikey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature=Signature.getInstance("SHA256withECDSA");
        signature.initSign(prikey);
        signature.update(content);
        return signature.sign();
    }


    public static byte[] decodeKey(String name,PrivateKey privatekey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] key = getFileContent(name);
        Cipher cipher = Cipher.getInstance("ECIES","BC");
        cipher.init(Cipher.DECRYPT_MODE,privatekey);
        return cipher.doFinal(key);
    }

    public static byte[] decodeMessage(byte[] key ,String name) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        byte[] content = getFileContent(name);
        SecretKey skeyspec = new SecretKeySpec(key,"AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,skeyspec);
        return cipher.doFinal(content);
    }

    private static byte[] getFileContent(String name) throws IOException {
        String path = "C:\\Users\\lflx1\\IdeaProjects\\CPK\\certificates\\";
        BufferedReader br = new BufferedReader(new FileReader(path+name));
        String line;
        line=br.readLine();
        br.close();

        return Base64.getDecoder().decode(line);
    }

    public static boolean checkHash(byte[] sign,X509Certificate cer,String name) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, SQLException, CMSException, NoSuchPaddingException, BadPaddingException, OperatorCreationException, InvalidKeySpecException, IllegalBlockSizeException, CRLException {
        checkCer(cer);
        PublicKey pubkey=cer.getPublicKey();
        byte[] content = getFileContent(name);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(pubkey);
        signature.update(sign);

        return signature.verify(content);

    }

}
