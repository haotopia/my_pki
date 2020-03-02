import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;


public class TestCa {
    public static void main(String[] args) throws  Exception {
        byte[] plainText = "Hello World!".getBytes();
        byte[] cipherText = null;

        Security.addProvider(new BouncyCastleProvider());
        //生成公钥和私钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECIES", "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        System.out.println(ecPublicKey);
        System.out.println(ecPrivateKey);

/*
        MessageDigest md = MessageDigest.getInstance("RipeMD160");
        md.update("Hello word".getBytes("UTF-8"));
        byte[] result = md.digest();
        System.out.println(new BigInteger(1,result).toString(16));*/
    }

}
