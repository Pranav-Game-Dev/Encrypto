package core;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;

/**
 * Decryptor class for the Encrypto file encryption system.
 * Decrypts files encrypted by Encryptor.java using AES-GCM with 256-bit keys.
 * Automatically validates integrity using GCM authentication tag.
 */
public class Decryptor {

    // AES-GCM standard parameters (must match Encryptor settings)
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 12 bytes for GCM IV
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag
    private static final int BUFFER_SIZE = 8192; // 8KB buffer for streaming

    /**
     * Decrypts a file that was encrypted using Encryptor.encryptFile().
     * Expects file structure: [12-byte IV][Encrypted Data + Auth Tag]
     * GCM mode automatically validates integrity during decryption.
     *
     * @param encryptedFile The encrypted file to decrypt
     * @param outputFile The destination for decrypted data
     * @param key The 256-bit AES SecretKey for decryption (same key used for encryption)
     * @throws IOException If file I/O operations fail
     * @throws GeneralSecurityException If decryption fails or authentication tag is invalid
     * @throws IllegalArgumentException If input parameters are invalid
     */
    public static void decryptFile(File encryptedFile, File outputFile, SecretKey key)
            throws IOException, GeneralSecurityException {

        // Validate input parameters
        if (encryptedFile == null || outputFile == null || key == null) {
            throw new IllegalArgumentException("Encrypted file, output file, and key must not be null");
        }

        if (!encryptedFile.exists()) {
            throw new IOException("Encrypted file does not exist: " + encryptedFile.getAbsolutePath());
        }

        if (!encryptedFile.isFile()) {
            throw new IOException("Encrypted path is not a file: " + encryptedFile.getAbsolutePath());
        }

        if (!encryptedFile.canRead()) {
            throw new IOException("Cannot read encrypted file: " + encryptedFile.getAbsolutePath());
        }

        // Verify key length is 256 bits (32 bytes)
        if (key.getEncoded().length != 32) {
            throw new IllegalArgumentException("Key must be 256 bits (32 bytes), got: "
                    + (key.getEncoded().length * 8) + " bits");
        }

        // Check minimum file size (IV + at least some encrypted data)
        long fileSize = encryptedFile.length();
        if (fileSize < GCM_IV_LENGTH) {
            throw new IOException("Encrypted file is too small to contain valid data. " +
                    "Expected at least " + GCM_IV_LENGTH + " bytes for IV, got: " + fileSize + " bytes");
        }

        // Read the IV from the beginning of the encrypted file
        byte[] iv = new byte[GCM_IV_LENGTH];
        try (InputStream fileIn = Files.newInputStream(encryptedFile.toPath())) {
            int bytesRead = fileIn.read(iv);
            if (bytesRead != GCM_IV_LENGTH) {
                throw new IOException("Failed to read complete IV from encrypted file. " +
                        "Expected " + GCM_IV_LENGTH + " bytes, got: " + bytesRead + " bytes");
            }
        }

        // Initialize cipher with AES-GCM mode for decryption
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        // Create parent directories if they don't exist
        if (outputFile.getParentFile() != null) {
            Files.createDirectories(outputFile.getParentFile().toPath());
        }

        // Stream decryption for memory efficiency
        // CipherInputStream will automatically validate the GCM authentication tag
        try (InputStream fileIn = Files.newInputStream(encryptedFile.toPath());
             CipherInputStream cipherIn = new CipherInputStream(fileIn, cipher)) {

            // Skip the IV bytes (already read them)
            long skipped = fileIn.skip(GCM_IV_LENGTH);
            if (skipped != GCM_IV_LENGTH) {
                throw new IOException("Failed to skip IV bytes in encrypted file");
            }

            // Stream the decrypted data to output file
            try (OutputStream fileOut = Files.newOutputStream(outputFile.toPath(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {

                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = cipherIn.read(buffer)) != -1) {
                    fileOut.write(buffer, 0, bytesRead);
                }
            }

        } catch (IOException e) {
            // GCM authentication failures often manifest as IOException during stream read
            // Provide more context for common authentication failures
            if (e.getMessage() != null &&
                    (e.getMessage().contains("Tag mismatch") ||
                            e.getMessage().contains("mac check"))) {
                throw new GeneralSecurityException(
                        "Authentication failed: File may be corrupted or wrong key was used", e);
            }
            throw e;
        }
    }
}