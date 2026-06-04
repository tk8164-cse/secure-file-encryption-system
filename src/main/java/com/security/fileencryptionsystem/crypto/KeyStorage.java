package com.security.fileencryptionsystem.crypto;

import javax.crypto.SecretKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class KeyStorage {
    // Upgraded to ConcurrentHashMap to ensure dynamic thread safety across web channels
    private static final Map<String, SecretKey> userKeys = new ConcurrentHashMap<>();

    public static void storeKey(String filename, SecretKey key) {
        System.out.println("[KEY STORED] Registered key reference for: " + filename);
        userKeys.put(filename, key);
    }

    public static SecretKey getKey(String filename) {
        System.out.println("[KEY RETRIEVAL] Looking up key reference for: " + filename);
        return userKeys.get(filename);
    }
}