package util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.apache.commons.codec.binary.Base64;


import javax.crypto.Cipher;


public class PublicKeyUtil {

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes("UTF-8"));

        return Base64.encodeBase64String(cipherText);
    }


    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {

        byte[] bytes = Base64.decodeBase64(cipherText);

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decryptCipher.doFinal(bytes), "UTF-8");
    }

    public static KeyPair getKeyPairFromKeyStore(String fileName, String alias, char[] keyStorePw,
                                                 char[] keyPw) throws NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableEntryException, KeyStoreException {

        InputStream ins;
        String path = "certificates/" + alias + "/" + fileName;
        ins = new FileInputStream(new File(path));

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, keyStorePw); // Keystore password
        KeyStore.PasswordProtection keyPassword = // Key password
                new KeyStore.PasswordProtection(keyPw);

        KeyStore.PrivateKeyEntry privateKeyEntry =
                (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate(alias);

        if (cert == null)
            return null;

        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));

        byte[] signature = privateSignature.sign();

        return Base64.encodeBase64String(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey)
            throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));

        byte[] signatureBytes = Base64.decodeBase64(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static X509Certificate getCertFromFile(String alias, String file) {
        FileInputStream fis;
        X509Certificate caCert = null;
        try {
            fis = new FileInputStream("certificates/" + alias + "/" + file);
            BufferedInputStream bis = new BufferedInputStream(fis);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            caCert = (X509Certificate) cf.generateCertificate(bis);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return caCert;
    }
}
