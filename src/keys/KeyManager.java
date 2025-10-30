package keys;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * KeyManager handles AES-256 key generation and management for the CipherVibe encryption system.
 * This class provides secure password-to-key derivation using PBKDF2 with proper salt generation
 * and password validation.
 */
public class KeyManager {

    // Password policy constants
    private static final int MINIMUM_PASSWORD_LENGTH = 8;
    private static final int MAXIMUM_PASSWORD_LENGTH = 128; // Reasonable upper limit
    
    // Salt length in bytes (128 bits recommended for PBKDF2)
    private static final int SALT_LENGTH = 16;
    
    // SecureRandom instance for cryptographic operations
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Derives an AES-256 key from a password using PBKDF2-HMAC-SHA256.
     * This method uses the PBKDF2Util for the actual key derivation process.
     * 
     * The password is provided as a char array for security reasons - char arrays
     * can be cleared from memory after use, unlike Strings which are immutable.
     * 
     * @param password The password as a character array (will not be modified)
     * @param salt The cryptographic salt (must be the same for encryption/decryption)
     * @return A SecretKey object containing the derived AES-256 key
     * @throws IllegalArgumentException If password or salt are invalid
     * @throws RuntimeException If key derivation fails
     */
    public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) {
        
        // Validate password
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        if (password.length < MINIMUM_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                "Password must be at least " + MINIMUM_PASSWORD_LENGTH + 
                " characters long, got: " + password.length);
        }
        
        if (password.length > MAXIMUM_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                "Password must not exceed " + MAXIMUM_PASSWORD_LENGTH + 
                " characters, got: " + password.length);
        }
        
        // Validate salt
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }
        
        if (salt.length < SALT_LENGTH) {
            throw new IllegalArgumentException(
                "Salt must be at least " + SALT_LENGTH + 
                " bytes long for security, got: " + salt.length);
        }
        
        // Derive the key using PBKDF2
        return PBKDF2Util.generateAESKey(password, salt);
    }

    /**
     * Generates a cryptographically secure random salt for key derivation.
     * The salt should be unique for each password and stored alongside the
     * encrypted data for later decryption.
     * 
     * A 128-bit (16-byte) salt is generated, which meets NIST recommendations
     * for PBKDF2.
     * 
     * @return A byte array containing the random salt
     */
    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a random salt with a custom length.
     * 
     * @param length The desired salt length in bytes (minimum 16 bytes recommended)
     * @return A byte array containing the random salt
     * @throws IllegalArgumentException If length is less than minimum required
     */
    public static byte[] generateRandomSalt(int length) {
        if (length < SALT_LENGTH) {
            throw new IllegalArgumentException(
                "Salt length must be at least " + SALT_LENGTH + 
                " bytes for security, got: " + length);
        }
        
        byte[] salt = new byte[length];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Validates a password against security policy requirements.
     * Throws an exception if the password does not meet requirements.
     * 
     * Current requirements:
     * - Minimum length: 8 characters
     * - Maximum length: 128 characters
     * - Cannot be null or empty
     * 
     * @param password The password to validate
     * @throws IllegalArgumentException If password does not meet requirements
     */
    public static void validatePassword(String password) {
        
        // Check for null or empty
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        // Check minimum length
        if (password.length() < MINIMUM_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                "Password must be at least " + MINIMUM_PASSWORD_LENGTH + 
                " characters long. Current length: " + password.length());
        }
        
        // Check maximum length
        if (password.length() > MAXIMUM_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                "Password must not exceed " + MAXIMUM_PASSWORD_LENGTH + 
                " characters. Current length: " + password.length());
        }
        
        // Check for common weak passwords (basic check)
        String lowerPassword = password.toLowerCase();
        String[] commonWeakPasswords = {
            "password", "12345678", "qwerty123", "password123", 
            "abcdefgh", "00000000", "11111111"
        };
        
        for (String weak : commonWeakPasswords) {
            if (lowerPassword.equals(weak)) {
                throw new IllegalArgumentException(
                    "Password is too common and easily guessable. Please choose a stronger password.");
            }
        }
    }

    /**
     * Validates a password provided as a character array.
     * 
     * @param password The password to validate as a char array
     * @throws IllegalArgumentException If password does not meet requirements
     */
    public static void validatePassword(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        
        // Convert to String for validation (temporary)
        String passwordStr = new String(password);
        validatePassword(passwordStr);
    }

    /**
     * Securely compares two byte arrays in constant time.
     * This prevents timing attacks when comparing salts or keys.
     * 
     * @param a First byte array
     * @param b Second byte array
     * @return true if arrays are equal, false otherwise
     */
    public static boolean secureCompare(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        
        if (a.length != b.length) {
            return false;
        }
        
        // Use constant-time comparison to prevent timing attacks
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        
        return result == 0;
    }

    /**
     * Securely clears a character array by overwriting it with zeros.
     * This should be called after using passwords to prevent them from
     * remaining in memory.
     * 
     * @param chars The character array to clear
     */
    public static void clearPassword(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Securely clears a byte array by overwriting it with zeros.
     * 
     * @param bytes The byte array to clear
     */
    public static void clearBytes(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Gets the minimum required password length.
     * 
     * @return The minimum password length
     */
    public static int getMinimumPasswordLength() {
        return MINIMUM_PASSWORD_LENGTH;
    }

    /**
     * Gets the recommended salt length in bytes.
     * 
     * @return The salt length in bytes
     */
    public static int getSaltLength() {
        return SALT_LENGTH;
    }
}
