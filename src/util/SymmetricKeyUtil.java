package util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SymmetricKeyUtil {

    public static String getHMACMD5(byte[] key, String input) {

        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacMD5");

        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacMD5");
            mac.init(keySpec);

        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte[] result = mac.doFinal(input.getBytes());
        String hmac = Base64.encodeBase64String(result);

        return hmac;

    }

    public static byte[] encrypt(byte[] key, byte[] initVector, byte[] value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

            byte[] encrypted = cipher.doFinal(value);

            return encrypted;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static byte[] decrypt(byte[] key, byte[] initVector, byte[] encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector);
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

            byte[] original = cipher.doFinal(encrypted);

            return original;

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {

        try {

            byte[] key = generateSymmetricAESKey();
            byte[] iv = generate16BytesIV();
            String hash = null;
            hash = generateMD5Hash(new String(key, "UTF-8")).substring(0, 16);
            System.out.println("hash.substring(0,16) = " + hash.substring(0, 16));

            String input = "ASDF";
            String kStr = new String(key, "UTF-8");

            byte[] k = hash.getBytes();

            byte[] cipher = encrypt(k, iv, kStr.getBytes());
            byte[] plain = decrypt(k, iv, cipher);

            System.out.println(new String(plain, "UTF-8"));

        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String generateMD5Hash(String msg) {
        return DigestUtils.md5Hex(msg);
    }

    public static byte[] generateSymmetricAESKey() {

        KeyGenerator keyGen;
        SecretKey secretKey = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return secretKey.getEncoded();

    }

    public static byte[] generate16BytesIV() {

        final int AES_KEYLENGTH = 128;
        byte[] iv = new byte[AES_KEYLENGTH / 8];

        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);
        return iv;
    }


}
