package com.security.fileencryptionsystem.controllers;

import com.security.fileencryptionsystem.crypto.CryptoUtils;
import com.security.fileencryptionsystem.crypto.KeyStorage;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

@Controller
public class FileController {

    // CHOOSE YOUR LOCAL TESTING DIRECTORY HERE
    private static final String TEST_DIR = "C:/encrypt-test/";
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/")
    public String index() {
        // Ensure directory exists when page loads
        File directory = new File(TEST_DIR);
        if (!directory.exists()) {
            directory.mkdirs();
        }
        return "index";
    }

    @PostMapping("/encrypt")
    public ResponseEntity<?> handleEncryption(@RequestParam("file") MultipartFile file) {
        try {
            String originalFileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
            if (originalFileName.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("File name cannot be empty.");
            }

            byte[] fileBytes = file.getBytes();
            SecretKey key = CryptoUtils.generateAESKey();
            KeyStorage.storeKey(originalFileName, key);

            // 1. Generate encrypted payload bytes
            byte[] encryptedData = CryptoUtils.encryptFile(fileBytes, key);

            // 2. Save it LOCALLY on your hard drive to prevent browser stream corruption
            Path outputPath = Paths.get(TEST_DIR + originalFileName + ".enc");
            Files.write(outputPath, encryptedData);
            System.out.println("[LOCAL SAVE SUCCESS] Saved raw encrypted file to: " + outputPath.toAbsolutePath());

            // Still send a copy to the browser so the UI is happy
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + originalFileName + ".enc\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Encryption processing failure.");
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<?> handleDecryption(@RequestParam("file") MultipartFile file,
                                              @RequestParam("keyOwner") String originalName) {
        try {
            String targetKeyName = StringUtils.cleanPath(originalName.trim());
            SecretKey key = KeyStorage.getKey(targetKeyName);

            if (key == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Decryption failed: No encryption key found for '" + targetKeyName + "'.");
            }

            // 1. READ DIRECTLY FROM THE HARD DRIVE to guarantee byte-per-byte perfect data matching
            Path inputPath = Paths.get(TEST_DIR + targetKeyName + ".enc");
            if (!Files.exists(inputPath)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("File error: Could not find the encrypted file locally at " + TEST_DIR);
            }

            byte[] pristineLocalBytes = Files.readAllBytes(inputPath);
            System.out.println("[LOCAL READ SUCCESS] Pulled pristine encrypted file size: " + pristineLocalBytes.length + " bytes");

            // 2. Decrypt using the untouched hard drive bytes
            byte[] decryptedData = CryptoUtils.decryptFile(pristineLocalBytes, key);
            System.out.println("[SUCCESS] Decrypted target successfully: " + targetKeyName);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"DECRYPTED_" + targetKeyName + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(decryptedData);
        } catch (Exception e) {
            System.out.println("[CRITICAL ERROR] Decryption process failed.");
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Decryption failed: Integrity check error or invalid cipher data.");
        }
    }
}