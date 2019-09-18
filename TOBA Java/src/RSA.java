import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {
    private static final String UTF_8 = "UTF-8";
    private static final String Hash_Alg = "SHA-256";

    private static final String KeyPair_Alg = "RSA";
    private static final String Alg = "RSA/ECB/PKCS1Padding";
    private static final String KeyPair_Verify_Alg = "SHA1withRSA";

    static byte[] HASH(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(Hash_Alg);
        md.reset();
        md.update(data);
        return md.digest();
    }

    //Encrypt
    static PublicKey getPublicKey(String filename) throws Exception {
        byte[] keyBytes = Utils.getFileInBytes(filename);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(KeyPair_Alg);
        return kf.generatePublic(spec);
    }

    /*static PublicKey getPublicKey(String filename) throws Exception {
        FileInputStream fin = new FileInputStream(filename);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
        return certificate.getPublicKey();
    }*/

    static String encrypt(String plainText, String publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance(Alg);
        encryptCipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return Utils.toBase64(encryptCipher.doFinal(plainText.getBytes()));
    }

    //Decrypt
    static PrivateKey getPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Utils.getFileInBytes(filename);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(KeyPair_Alg);
        return kf.generatePrivate(spec);
    }

    static String decrypt(String cipherText, String privateKey) throws Exception {
        byte[] bytes = Utils.fromBase64(cipherText);
        Cipher decriptCipher = Cipher.getInstance(KeyPair_Alg);
        decriptCipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    //Verify
    static String sign(String plainText, String path) throws Exception {
        Signature privateSignature = Signature.getInstance(KeyPair_Verify_Alg);
        privateSignature.initSign(getPrivateKey(path));
        privateSignature.update(plainText.getBytes(UTF_8));
        return Utils.toBase64(privateSignature.sign());
    }

    static boolean verify(String plainText, String signature, String path) throws Exception {
        Signature publicSignature = Signature.getInstance(KeyPair_Verify_Alg);
        publicSignature.initVerify(getPublicKey(path));
        publicSignature.update(plainText.getBytes(UTF_8));
        return publicSignature.verify(Utils.fromBase64(signature));
    }
}
