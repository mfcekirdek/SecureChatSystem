package util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

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

  public static String encrypt(String key, String initVector, String value) {
    try {
      IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
      SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

      Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
      cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

      byte[] encrypted = cipher.doFinal(value.getBytes());
      System.out.println("encrypted string: " + Base64.encodeBase64String(encrypted));

      return Base64.encodeBase64String(encrypted);
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return null;
  }

  public static String decrypt(String key, String initVector, String encrypted) {
    try {
      IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
      SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

      Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5PADDING");
      cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

      byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

      return new String(original);
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return null;
  }
  
  public static void main(String[] args) {
    String key = "xcvxcvsdfsafsqeww";
    String input = "foo";
    
    System.out.println(getHMACMD5(key, input).length());
  }
}
