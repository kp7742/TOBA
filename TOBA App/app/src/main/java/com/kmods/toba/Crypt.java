package com.kmods.toba;

import java.util.*;

class Crypt {
    private final static int SUGAR = 0x9E3779B9;
    private final static int CUPS  = 32;
    private static int[] S = new int[4];

    static String Main(String darg) {
        int inc = new Random().nextInt(0xFF);
        byte[] keys = genKey();
        byte[] en = encrypt(keys, darg.getBytes());
        byte[] keybreak = Arrays.copyOfRange(keys,keys.length-2,keys.length);
        return hex(inc) + bytesToHex(cipher(Arrays.copyOfRange(keys,0,keys.length-2),inc)) + "-"
                + bytesToHex(cipher(keybreak,inc))  + bytesToHex(cipher(Arrays.copyOfRange(en,0,(en.length/3)-1),inc)) + "-"
                + bytesToHex(cipher(Arrays.copyOfRange(en,(en.length/3)-1,((2 * en.length)/3)-1),inc)) + "-"
                + bytesToHex(cipher(Arrays.copyOfRange(en,((2 * en.length)/3)-1,en.length),inc));
    }

    private static byte[] genKey() {
        byte[] b = new byte[16]; // 16*8=128 bit
        new Random().nextBytes(b);
        return b;
    }

    private static void setKey(byte[] key) {
        if (key == null)
            throw new RuntimeException("Invalid key: Key was null");
        if (key.length < 16)
            throw new RuntimeException("Invalid key: Length was less than 16 bytes");
        for (int off=0, i=0; i<4; i++) {
            S[i] = ((key[off++] & 0xff)) |
                    ((key[off++] & 0xff) <<  8) |
                    ((key[off++] & 0xff) << 16) |
                    ((key[off++] & 0xff) << 24);
        }
    }

    private static byte[] encrypt(byte[] key,byte[] clear) {
        setKey(key);
        int paddedSize = ((clear.length/8) + (((clear.length%8)==0)?0:1)) * 2;
        int[] buffer = new int[paddedSize + 1];
        buffer[0] = clear.length;
        pack(clear, buffer, 1);
        brew(buffer);
        return unpack(buffer, 0, buffer.length * 4);
    }

    private static void brew(int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;
        while (i<buf.length) {
            n = CUPS;
            v0 = buf[i];
            v1 = buf[i+1];
            sum = 0;
            while (n-->0) {
                sum += SUGAR;
                v0  += ((v1 << 4 ) + S[0] ^ v1) + (sum ^ (v1 >>> 5)) + S[1];
                v1  += ((v0 << 4 ) + S[2] ^ v0) + (sum ^ (v0 >>> 5)) + S[3];
            }
            buf[i] = v0;
            buf[i+1] = v1;
            i+=2;
        }
    }

    private static void pack(byte[] src, int[] dest, int destOffset) {
        assert destOffset + (src.length / 4) <= dest.length;
        int i = 0, shift = 24;
        int j = destOffset;
        dest[j] = 0;
        while (i<src.length) {
            dest[j] |= ((src[i] & 0xff) << shift);
            if (shift==0) {
                shift = 24;
                j++;
                if (j<dest.length) dest[j] = 0;
            }
            else {
                shift -= 8;
            }
            i++;
        }
    }

    private static byte[] unpack(int[] src, int srcOffset, int destLength) {
        assert destLength <= (src.length - srcOffset) * 4;
        byte[] dest = new byte[destLength];
        int i = srcOffset;
        int count = 0;
        for (int j = 0; j < destLength; j++) {
            dest[j] = (byte) ((src[i] >> (24 - (8*count))) & 0xff);
            count++;
            if (count == 4) {
                count = 0;
                i++;
            }
        }
        return dest;
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

    private static String hex(int n) {//Convert int hex to String
        return String.format("%2s", new Object[]{Integer.toHexString(n)}).replace(' ', '0');
    }

    private static byte[] cipher(byte[] srcdata,int inc){
        for(int i = 0;i<srcdata.length;i++){
            srcdata[i] = (byte)(inc ^ srcdata[i]);
        }
        return srcdata;
    }
}
