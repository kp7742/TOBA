package com.kmods.toba;

import android.util.Base64;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

class Utils {
    static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    static String bytesToHex2(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    static byte[] hex2b(String str) {
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

    static byte[] getFileInBytes(String path) throws IOException {
        File f = new File(path);
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;
    }

    static void writeToFile(String path, byte[] toWrite) throws IOException{
        File f = new File(path);
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

    static boolean isFileExist(String path){
        File f = new File(path);
        return f.exists();
    }

    static String readStream(InputStream in) {
        BufferedReader reader = null;
        StringBuilder response = new StringBuilder();
        try {
            reader = new BufferedReader(new InputStreamReader(in));
            String line = "";
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return response.toString();
    }

    static String SHA256(String data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.reset();
        md.update(data.getBytes());
        return bytesToHex(md.digest());
    }

    static String toBase64(String s){
        return Base64.encodeToString(s.getBytes(), Base64.DEFAULT);
    }

    static String toBase64(byte[] s){
        return Base64.encodeToString(s, Base64.DEFAULT);
    }

    static byte[] fromBase64(String s){
        return Base64.decode(s, Base64.DEFAULT);
    }

    static String fromBase64String(String s){
        return new String(Base64.decode(s, Base64.DEFAULT));
    }
}
