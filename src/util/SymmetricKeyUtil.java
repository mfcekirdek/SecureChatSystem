package util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
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

  public static String getHMACMD5(String key, String input) {
    SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "HmacMD5");

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
    System.out.println(hmac);

    return hmac;

  }

  public static String encrypt(Key key, byte [] initVector, String value) {
    try {
      IvParameterSpec iv = new IvParameterSpec(initVector);

      Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);

      byte[] encrypted = cipher.doFinal(value.getBytes());
      System.out.println("encrypted string: " + Base64.encodeBase64String(encrypted));

      return Base64.encodeBase64String(encrypted);
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return null;
  }

  public static String decrypt(Key key, byte [] initVector, String encrypted) {
    try {
      IvParameterSpec iv = new IvParameterSpec(initVector);

      Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
      cipher.init(Cipher.DECRYPT_MODE, key, iv);

      byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

      return new String(original);
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return null;
  }

  public static void main(String[] args) throws UnsupportedEncodingException {
    String key = "123456789abcdefg";
    String initVector = "123456789abcdefg"; // 16 bytes IV

//    String input = "yarrak";// "zaaa";
    
    System.out.println(generateSymmetricAESKey());
   
    String hash = generateMD5Hash(generateSymmetricAESKey()).substring(0,16);
    
//    
//    SecretKeySpec keyyy = new SecretKeySpec(hash.getBytes("UTF-8"), "AES");
//
//    
//    
//    System.out.println("Input: " + input);
//
//    Key k = generateSymmetricAESKey();
//    byte [] initVector2 = generate16bitIV();
//    
//    String enc = encrypt(keyyy, initVector2, input);
//    String dec = decrypt(keyyy,initVector2, enc);
//
//    System.out.println("Enc: " + enc);
//    System.out.println("Dec: " + dec);
//    System.out.println(dec.equals(input));

    //
    // System.out.println(getHMACMD5(key, input).length());
    //
    // System.out.println(generateMD5Hash(input));


  }

  public static String generateMD5Hash(String msg) {
    return DigestUtils.md5Hex(msg);
  }
//
//
//
  public static Key generateSymmetricAESKey() throws UnsupportedEncodingException {

    KeyGenerator keyGen;
    SecretKey secretKey = null;
    try {
      keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(128);
      secretKey = keyGen.generateKey();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    
    return secretKey;

  }

  public static byte [] generate16bitIV() throws UnsupportedEncodingException {

    final int AES_KEYLENGTH = 128;
    byte[] iv = new byte[AES_KEYLENGTH / 8];

    SecureRandom prng = new SecureRandom();
    prng.nextBytes(iv);
    return iv;
  }



}
