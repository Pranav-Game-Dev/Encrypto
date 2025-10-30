package keys;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * PBKDF2Util provides key derivation functionality using PBKDF2 with HMAC-SHA256.
 * This utility performs password-based key stretching to create cryptographically
 * strong AES-256 keys from passwords.
 */
public class PBKDF2Util {

    // PBKDF2 algorithm identifier
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    // AES-256 requires 256 bits (32 bytes)
    private static final int AES_KEY_LENGTH = 256;

    // AES algorithm identifier for SecretKeySpec
    private static final String AES_ALGORITHM = "AES";

    // Recommended minimum iterations for PBKDF2 (OWASP 2023 recommendation)
    public static final int MINIMUM_ITERATIONS = 100000;

    // Default iterations if not specified
    public static final int DEFAULT_ITERATIONS = 210000;

    /**
     * Generates an AES-256 key from a password using PBKDF2-HMAC-SHA256.
     *
     * This method uses Password-Based Key Derivation Function 2 (PBKDF2) to
     * derive a cryptographically strong key from a password. The process is
     * intentionally slow to make brute-force attacks impractical.
     *
     * @param password The password as a character array (for security reasons)
     * @param salt The cryptographic salt (must be unique per key)
     * @param iterations The number of PBKDF2 iterations (minimum 100,000 recommended)
     * @return A SecretKey object containing the derived AES-256 key
     * @throws IllegalArgumentException If password, salt, or iterations are invalid
     * @throws RuntimeException If key generation fails due to algorithm issues
     */
    public static SecretKey generateAESKey(char[] password, byte[] salt, int iterations) {

        // Validate input parameters
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }

        if (iterations < MINIMUM_ITERATIONS) {
            throw new IllegalArgumentException(
                    "Iterations must be at least " + MINIMUM_ITERATIONS +
                            " for security, got: " + iterations);
        }

        try {
            // Create PBKDF2 key specification
            KeySpec keySpec = new PBEKeySpec(password, salt, iterations, AES_KEY_LENGTH);

            // Get PBKDF2 secret key factory
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);

            // Generate the key from password
            SecretKey tempKey = keyFactory.generateSecret(keySpec);

            // Convert to AES key format
            byte[] keyBytes = tempKey.getEncoded();

            // Create and return the AES SecretKey
            return new SecretKeySpec(keyBytes, AES_ALGORITHM);

        } catch (NoSuchAlgorithmException e) {
            // This should not happen on modern JVMs
            throw new RuntimeException(
                    "PBKDF2WithHmacSHA256 algorithm not available. " +
                            "Ensure you are using Java 8 or higher.", e);

        } catch (InvalidKeySpecException e) {
            // This indicates a problem with the key specification
            throw new RuntimeException("Failed to generate key from password: " + e.getMessage(), e);
        }
    }

    /**
     * Generates an AES-256 key using the default iteration count.
     *
     * @param password The password as a character array
     * @param salt The cryptographic salt
     * @return A SecretKey object containing the derived AES-256 key
     * @throws IllegalArgumentException If password or salt are invalid
     * @throws RuntimeException If key generation fails
     */
    public static SecretKey generateAESKey(char[] password, byte[] salt) {
        return generateAESKey(password, salt, DEFAULT_ITERATIONS);
    }

    /**
     * Validates that the iteration count meets minimum security requirements.
     *
     * @param iterations The iteration count to validate
     * @return true if the iteration count is acceptable
     */
    public static boolean isValidIterationCount(int iterations) {
        return iterations >= MINIMUM_ITERATIONS;
    }
}