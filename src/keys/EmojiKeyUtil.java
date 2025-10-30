package keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * EmojiKeyUtil enables users to use emoji sequences as encryption passwords.
 * Emojis are normalized to UTF-8 encoding and converted to secure AES-256 keys
 * using PBKDF2, just like regular passwords.
 * 
 * This provides a fun and potentially memorable alternative to traditional passwords,
 * though users should be aware that emoji keyboards vary across platforms.
 */
public class EmojiKeyUtil {

    // Minimum number of emojis required for a secure key
    private static final int MINIMUM_EMOJI_COUNT = 2;
    
    // Maximum number of emojis allowed (to prevent excessive memory use)
    private static final int MAXIMUM_EMOJI_COUNT = 50;
    
    // Regex pattern to detect emojis (covers most common emoji ranges)
    // This matches emoji characters, emoji with modifiers, and zero-width joiners
    private static final Pattern EMOJI_PATTERN = Pattern.compile(
        "[\\x{1F300}-\\x{1F9FF}]|" +      // Emoticons, symbols, pictographs
        "[\\x{1F600}-\\x{1F64F}]|" +      // Emoticons
        "[\\x{1F680}-\\x{1F6FF}]|" +      // Transport and map symbols
        "[\\x{2600}-\\x{26FF}]|" +        // Miscellaneous symbols
        "[\\x{2700}-\\x{27BF}]|" +        // Dingbats
        "[\\x{1F900}-\\x{1F9FF}]|" +      // Supplemental symbols and pictographs
        "[\\x{1F1E0}-\\x{1F1FF}]|" +      // Flags
        "[\\x{1FA70}-\\x{1FAFF}]|" +      // Symbols and pictographs extended-A
        "[\\x{2300}-\\x{23FF}]|" +        // Miscellaneous technical
        "[\\x{FE00}-\\x{FE0F}]|" +        // Variation selectors
        "[\\x{200D}]"                      // Zero-width joiner
    );

    /**
     * Derives an AES-256 key from an emoji sequence.
     * The emoji string is normalized using UTF-8 encoding and then
     * processed through PBKDF2 just like a regular password.
     * 
     * @param emojiString The emoji sequence (at least 2 emojis required)
     * @param salt The cryptographic salt (same as used for password-based keys)
     * @return A SecretKey object containing the derived AES-256 key
     * @throws IllegalArgumentException If emoji string is invalid
     * @throws RuntimeException If key derivation fails
     */
    public static SecretKey deriveKeyFromEmojis(String emojiString, byte[] salt) {
        
        // Validate the emoji string
        if (!isValidEmojiKey(emojiString)) {
            throw new IllegalArgumentException(
                "Invalid emoji key. Must contain at least " + MINIMUM_EMOJI_COUNT + 
                " emojis and no more than " + MAXIMUM_EMOJI_COUNT + " emojis.");
        }
        
        // Validate salt
        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt cannot be null or empty");
        }
        
        // Normalize the emoji string to ensure consistent encoding
        // UTF-8 normalization ensures emojis are represented consistently
        String normalized = normalizeEmojiString(emojiString);
        
        // Convert to char array for secure handling
        char[] emojiChars = normalized.toCharArray();
        
        try {
            // Use PBKDF2Util to derive the key (same as password-based derivation)
            return PBKDF2Util.generateAESKey(emojiChars, salt);
            
        } finally {
            // Clear the char array from memory for security
            KeyManager.clearPassword(emojiChars);
        }
    }

    /**
     * Validates whether an emoji string meets the requirements for use as a key.
     * 
     * Requirements:
     * - Must contain at least 2 emojis
     * - Must not exceed maximum emoji count
     * - Must not be null or empty
     * 
     * @param emojiString The emoji string to validate
     * @return true if the emoji string is valid, false otherwise
     */
    public static boolean isValidEmojiKey(String emojiString) {
        
        // Check for null or empty
        if (emojiString == null || emojiString.isEmpty()) {
            return false;
        }
        
        // Count emojis in the string
        int emojiCount = countEmojis(emojiString);
        
        // Validate emoji count
        if (emojiCount < MINIMUM_EMOJI_COUNT) {
            return false;
        }
        
        if (emojiCount > MAXIMUM_EMOJI_COUNT) {
            return false;
        }
        
        // Ensure the string actually contains emojis (not just regular text)
        // At least 50% of the string should be emoji characters
        String withoutEmojis = removeEmojis(emojiString);
        int nonEmojiLength = withoutEmojis.length();
        int totalLength = emojiString.length();
        
        // If more than 50% is non-emoji content, reject it
        if (nonEmojiLength > totalLength * 0.5) {
            return false;
        }
        
        return true;
    }

    /**
     * Counts the number of emojis in a string.
     * Note: Complex emojis with modifiers or zero-width joiners count as one emoji.
     * 
     * @param text The text to count emojis in
     * @return The number of emojis found
     */
    public static int countEmojis(String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        
        Matcher matcher = EMOJI_PATTERN.matcher(text);
        int count = 0;
        
        while (matcher.find()) {
            count++;
        }
        
        return count;
    }

    /**
     * Removes all emoji characters from a string.
     * Used for validation purposes.
     * 
     * @param text The text to remove emojis from
     * @return The text with all emojis removed
     */
    private static String removeEmojis(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        
        return EMOJI_PATTERN.matcher(text).replaceAll("");
    }

    /**
     * Normalizes an emoji string for consistent encoding.
     * Ensures the string is properly encoded in UTF-8 and handles
     * any platform-specific emoji representations.
     * 
     * @param emojiString The emoji string to normalize
     * @return The normalized emoji string
     */
    private static String normalizeEmojiString(String emojiString) {
        if (emojiString == null) {
            return "";
        }
        
        // Convert to UTF-8 bytes and back to ensure consistent encoding
        byte[] utf8Bytes = emojiString.getBytes(StandardCharsets.UTF_8);
        String normalized = new String(utf8Bytes, StandardCharsets.UTF_8);
        
        // Trim any whitespace
        normalized = normalized.trim();
        
        return normalized;
    }

    /**
     * Validates an emoji key and throws an exception with a detailed message
     * if validation fails.
     * 
     * @param emojiString The emoji string to validate
     * @throws IllegalArgumentException If validation fails with detailed reason
     */
    public static void validateEmojiKey(String emojiString) {
        
        // Check for null or empty
        if (emojiString == null || emojiString.isEmpty()) {
            throw new IllegalArgumentException("Emoji key cannot be null or empty");
        }
        
        // Count emojis
        int emojiCount = countEmojis(emojiString);
        
        // Check minimum
        if (emojiCount < MINIMUM_EMOJI_COUNT) {
            throw new IllegalArgumentException(
                "Emoji key must contain at least " + MINIMUM_EMOJI_COUNT + 
                " emojis. Found: " + emojiCount);
        }
        
        // Check maximum
        if (emojiCount > MAXIMUM_EMOJI_COUNT) {
            throw new IllegalArgumentException(
                "Emoji key must not exceed " + MAXIMUM_EMOJI_COUNT + 
                " emojis. Found: " + emojiCount);
        }
        
        // Check for too much non-emoji content
        String withoutEmojis = removeEmojis(emojiString);
        int nonEmojiLength = withoutEmojis.length();
        int totalLength = emojiString.length();
        
        if (nonEmojiLength > totalLength * 0.5) {
            throw new IllegalArgumentException(
                "Emoji key contains too much non-emoji content. " +
                "Please use primarily emojis for your key.");
        }
    }

    /**
     * Gets the minimum number of emojis required.
     * 
     * @return The minimum emoji count
     */
    public static int getMinimumEmojiCount() {
        return MINIMUM_EMOJI_COUNT;
    }

    /**
     * Gets the maximum number of emojis allowed.
     * 
     * @return The maximum emoji count
     */
    public static int getMaximumEmojiCount() {
        return MAXIMUM_EMOJI_COUNT;
    }

    /**
     * Provides a hint about emoji key requirements.
     * Useful for displaying to users in the UI/CLI.
     * 
     * @return A string describing emoji key requirements
     */
    public static String getEmojiKeyRequirements() {
        return "Emoji key must contain between " + MINIMUM_EMOJI_COUNT + 
               " and " + MAXIMUM_EMOJI_COUNT + " emojis. " +
               "Example: 🔒🐱🌟 or 🚀💎🎨🔥";
    }
}
