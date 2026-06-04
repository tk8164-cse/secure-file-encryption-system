package com.example.fileencryptionsystem.crypto;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

public class KeyStorage {
    // Maps filename/owner to their generated SecretKey
    private static final Map<String, SecretKey> userKeys = new HashMap<>();

    public static void storeKey(String filename, SecretKey key) {
        userKeys.put(filename, key);
    }

    public static SecretKey getKey(String filename) {
        return userKeys.get(filename);
    }
}