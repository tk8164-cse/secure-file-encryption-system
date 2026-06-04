package com.security.fileencryptionsystem.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class CryptoUtils {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_BIT_LENGTH = 128;

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE);
        return keyGen.generateKey();
    }

    public static byte[] encryptFile(byte[] fileData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] encryptedData = cipher.doFinal(fileData);

        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);

        return combined;
    }

    public static byte[] decryptFile(byte[] combinedData, SecretKey key) throws Exception {
        if (combinedData == null || combinedData.length <= IV_SIZE) {
            throw new IllegalArgumentException("Cipher data payload is empty or corrupted.");
        }

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(combinedData, 0, iv, 0, IV_SIZE);

        int encryptedSize = combinedData.length - IV_SIZE;
        byte[] encryptedData = new byte[encryptedSize];
        System.arraycopy(combinedData, IV_SIZE, encryptedData, 0, encryptedSize);

        GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(encryptedData);
    }
}