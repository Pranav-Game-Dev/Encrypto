package core;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Encryptor class for the Encrypto file encryption system.
 * Uses AES-GCM with 256-bit keys for strong encryption with built-in integrity checking.
 * Encrypted files have the structure: [12-byte IV][Encrypted Data + Auth Tag]
 */
public class Encryptor {

    // AES-GCM standard parameters
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 12 bytes recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag
    private static final int BUFFER_SIZE = 8192; // 8KB buffer for streaming

    /**
     * Encrypts a file using AES-GCM encryption with a 256-bit key.
     * The encrypted output file structure is: [12-byte IV][Encrypted Data + Auth Tag]
     * 
     * @param inputFile The file to encrypt
     * @param outputFile The destination for encrypted data
     * @param key The 256-bit AES SecretKey for encryption
     * @throws IOException If file I/O operations fail
     * @throws GeneralSecurityException If encryption operations fail
     * @throws IllegalArgumentException If input parameters are invalid
     */
    public static void encryptFile(File inputFile, File outputFile, SecretKey key) 
            throws IOException, GeneralSecurityException {
        
        // Validate input parameters
        if (inputFile == null || outputFile == null || key == null) {
            throw new IllegalArgumentException("Input file, output file, and key must not be null");
        }
        
        if (!inputFile.exists()) {
            throw new IOException("Input file does not exist: " + inputFile.getAbsolutePath());
        }
        
        if (!inputFile.isFile()) {
            throw new IOException("Input path is not a file: " + inputFile.getAbsolutePath());
        }
        
        if (!inputFile.canRead()) {
            throw new IOException("Cannot read input file: " + inputFile.getAbsolutePath());
        }
        
        // Verify key length is 256 bits (32 bytes)
        if (key.getEncoded().length != 32) {
            throw new IllegalArgumentException("Key must be 256 bits (32 bytes), got: " 
                    + (key.getEncoded().length * 8) + " bits");
        }
        
        // Generate a secure random IV for this encryption operation
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        
        // Initialize cipher with AES-GCM mode
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        
        // Create parent directories if they don't exist
        if (outputFile.getParentFile() != null) {
            Files.createDirectories(outputFile.getParentFile().toPath());
        }
        
        // Write IV first, then stream encrypted data
        // Using try-with-resources for automatic resource management
        try (OutputStream fileOut = Files.newOutputStream(outputFile.toPath(), 
                StandardOpenOption.CREATE, 
                StandardOpenOption.TRUNCATE_EXISTING);
             CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
            
            // Write the IV at the beginning of the file
            fileOut.write(iv);
            
            // Stream the file through the cipher for memory-efficient encryption
            Files.copy(inputFile.toPath(), cipherOut);
            
        } // Streams are automatically closed, finalizing the GCM authentication tag
    }
}
