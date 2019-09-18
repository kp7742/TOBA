import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.security.cert.*;

import javax.crypto.*;

public class RSA {
    private static final String UTF_8 = "UTF-8";
    private static final String UID = "KP7742,F7f059d4e72f7ac6f,CriticalOps";
    //samsungSM-G900KP7742F7f059d4e72f7ac6fCriticalOps

    public static void main(String[] args) throws Exception {
        String en = encrypt(UID,"PublicKey.puk");
        System.out.println("EnData: " + en.length() + " " + en + "\n");

		String de = decrypt(en,"PrivateKey.prk");
        System.out.println("DeData: " + de.length() + " " + de + "\n");
    }

    /*
     * Hashes
     */
    private static final String Hash_Alg = "SHA-256";

    private static byte[] HASH(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(Hash_Alg);
        md.reset();
        md.update(data);
        return md.digest();
    }

    /*
     * Key Pair Methods(Asymmetric)
     */
    private static final String KeyPair_Alg = "RSA";
    private static final String KeyPair_Verify_Alg = "SHA256withRSA";

    //Encrypt
    private static PublicKey getPublicKey1(String filename) throws Exception {
        byte[] keyBytes = getFileInBytes(new File(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(KeyPair_Alg);
        return kf.generatePublic(spec);
    }
	
	private static PublicKey getPublicKey(String filename) throws Exception {
        FileInputStream fin = new FileInputStream(filename);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
		return certificate.getPublicKey();
    }

    private static String encrypt(String plainText, String publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance(KeyPair_Alg);
        encryptCipher.init(Cipher.ENCRYPT_MODE, getPublicKey1(publicKey));
        return bytesToHex(Base64.getEncoder().encode(encryptCipher.doFinal(plainText.getBytes(UTF_8))));
    }

    //Decrypt
    private static PrivateKey getPrivateKey(String filename) throws Exception {
        byte[] keyBytes = getFileInBytes(new File(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(KeyPair_Alg);
        return kf.generatePrivate(spec);
    }

    private static String decrypt(String cipherText, String privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(hex2b(cipherText));
        Cipher decriptCipher = Cipher.getInstance(KeyPair_Alg);
        decriptCipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    //Verify
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance(KeyPair_Verify_Alg);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(privateSignature.sign());
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(KeyPair_Verify_Alg);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));
        return publicSignature.verify(Base64.getDecoder().decode(signature));
    }

    //Other
    private static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] hex2b(String str) {
        int length = str.length();
        if((length % 2) != 0){
            str = "0" + str;
            length = str.length();
        }
        byte[] bArr = new byte[(length / 2)];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }

    private static byte[] getFileInBytes(File f) throws IOException{
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;
    }

    private static void writeToFile(File output, byte[] toWrite) throws IllegalBlockSizeException, BadPaddingException, IOException{
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }
}
