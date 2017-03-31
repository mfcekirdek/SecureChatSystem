package util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class SymmetricKeyUtil {
  
  
    /**
     * Calculate MD5 HMAC of given string
     * @param key
     * @param input
     * @return
     */
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
    
    /**
     * AES Block encryption with Counter Mode
     * Encrypts the given value with 128 bit AES Key 
     * 
     * @param key
     * @param initVector
     * @param value
     * @return
     */

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

    /**
     * AES Block decryption with Counter Mode
     * Decrypts the given encrypted value with 128 bit AES Key 
     * @param key
     * @param initVector
     * @param encrypted
     * @return
     */
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

    /**
     * Calculates MD5 Hash of given string
     * @param msg
     * @return
     */
    public static String generateMD5Hash(String msg) {
        return DigestUtils.md5Hex(msg);
    }

    /**
     * Generates 128 bit symmetric AES Key
     * @return
     */
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

    /**
     * Generates initialization vector
     * @return
     */
    public static byte[] generate16BytesIV() {

        final int AES_KEYLENGTH = 128;
        byte[] iv = new byte[AES_KEYLENGTH / 8];

        SecureRandom prng = new SecureRandom();
        prng.nextBytes(iv);
        return iv;
    }


}
