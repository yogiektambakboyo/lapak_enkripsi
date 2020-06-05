package com.lapakkreatiflamongan.lapak_enkripsi;

import android.os.Build;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static String initVector = "new_erp_bcp_iv";
    private static String sKey = "new_erp_bcp_key";

    // https://developer.android.com/reference/javax/crypto/Cipher
    private static String cipherTransfomation = "AES/CBC/PKCS5PADDING";

    public static String hashSHA256(String input)
            throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA-256");

        byte[] shaByteArr = mDigest.digest(input.getBytes(Charset.forName("UTF-8")));
        StringBuilder hexStrBuilder = new StringBuilder();
        for (int i = 0; i < shaByteArr.length; i++) {
            hexStrBuilder.append(String.format("%02x", shaByteArr[i]));
        }
        return hexStrBuilder.toString();
    }

    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-256");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String doEncrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(hashSHA256(initVector).substring(0,16).getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(hashSHA256(sKey).substring(0,16).getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance(cipherTransfomation);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return new String(Base64.encodeToString(encrypted,Base64.NO_WRAP));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String doDecrypt(String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(hashSHA256(initVector).substring(0,16).getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(hashSHA256(sKey).substring(0,16).getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance(cipherTransfomation);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = new byte[0];
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                original = cipher.doFinal(Base64.decode(encrypted,Base64.NO_WRAP));
            }else{
                original = cipher.doFinal(Base64.decode(encrypted,Base64.NO_WRAP));
            }

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static String getToken(String word){
        String result = "",username="";
        if (word.contains("~")&&word.length()>0){
            username = word.split("~")[0];
            result = word.split("~")[1];
            String tgl = "";
            String jam = "";
            if (result.length()==12){
                if (result.length() > 15) {
                    tgl = result.substring(0,6);
                } else {
                    tgl = result.substring(0,8);
                }
                tgl = tgl.substring(4,6)+""+tgl.substring(2,4)+""+tgl.substring(0,2);
                jam = result.substring(6,result.length());
                jam = jam.substring(4,6)+""+jam.substring(2,4)+""+jam.substring(0,2);
                int sumDateTime = Integer.parseInt(tgl)+Integer.parseInt(jam);
                String usernameASCII = "";
                String[] arrUsername = username.toUpperCase().split("");
                int sumusernameASCII = 0;
                String rightASCII = "";

                for (int i = 0; i < username.length() ; i++) {
                    usernameASCII = usernameASCII+""+(int)(username.toUpperCase().charAt(i));
                    sumusernameASCII += (int)(username.toUpperCase().charAt(i));
                }

                if (usernameASCII.length() <= 6) {
                    rightASCII = usernameASCII;
                } else {
                    rightASCII = usernameASCII.substring(usernameASCII.length()-6,usernameASCII.length());
                }

                Double ASCIITgl = Double.parseDouble(rightASCII) * Double.parseDouble(sumDateTime+"");
                Double rawToken = sumusernameASCII*ASCIITgl;
                String token = String.valueOf(rawToken).substring(6,10);
                result = token;
            }
        }

        return result;
    }

    public static String getUser(String word){
        String result = "";
        if (word.contains("~")&&word.length()>0){
            result = word.split("~")[0];
        }
        return result;
    }


    public static String getInitVector() {
        return initVector;
    }

    public static String getsKey() {
        return sKey;
    }

    public static void setInitVector(String initVector) {
        Encryption.initVector = initVector;
    }

    public static void setsKey(String sKey) {
        Encryption.sKey = sKey;
    }

    public static void setCipherTransfomation(String cipherTransfomation) {
        Encryption.cipherTransfomation = cipherTransfomation;
    }

}

