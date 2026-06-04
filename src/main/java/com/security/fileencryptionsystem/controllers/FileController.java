package com.example.fileencryptionsystem.controllers;

import com.example.fileencryptionsystem.crypto.CryptoUtils;
import com.example.fileencryptionsystem.crypto.KeyStorage;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.util.Objects;

@Controller
public class FileController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/encrypt")
    public ResponseEntity<byte[]> handleEncryption(@RequestParam("file") MultipartFile file, Model model) {
        try {
            // Clean and extract the exact complete filename to prevent character buffer cutoffs
            String originalFileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));

            if (originalFileName.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            SecretKey key = CryptoUtils.generateAESKey();
            KeyStorage.storeKey(originalFileName, key);

            byte[] encryptedData = CryptoUtils.encryptFile(file.getBytes(), key);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + originalFileName + ".enc\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(encryptedData);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<byte[]> handleDecryption(@RequestParam("file") MultipartFile file,
                                                   @RequestParam("keyOwner") String originalName) {
        try {
            String targetKeyName = StringUtils.cleanPath(originalName.trim());
            SecretKey key = KeyStorage.getKey(targetKeyName);

            // Explicit tracking indicator fallback if file entry missing or mismatched
            if (key == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            byte[] decryptedData = CryptoUtils.decryptFile(file.getBytes(), key);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"DECRYPTED_" + targetKeyName + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(decryptedData);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}