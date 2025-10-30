package cli;

import core.Decryptor;
import core.Encryptor;
import keys.KeyManager;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;

/**
 * Commands class handles the encryption and decryption workflows for the CLI interface.
 */
public class Commands {

    private static final int SALT_LENGTH = 16;
    private static final String ENCRYPTED_FILE_EXTENSION = ".encrypted";
    private static final String FOLDER_MARKER = "###FOLDER###";
    private static final String FILE_MARKER = "###FILE###";

    /**
     * Executes the encryption workflow.
     */
    public static void encryptFlow(Scanner scanner) {
        System.out.println("\n=== FILE/FOLDER ENCRYPTION ===\n");

        try {
            // Get input path
            System.out.print("Enter path to file or folder to encrypt: ");
            String inputPath = scanner.nextLine().trim();
            inputPath = removeQuotes(inputPath);

            File inputFile = new File(inputPath);

            if (!inputFile.exists()) {
                System.out.println("ERROR: Path does not exist.");
                return;
            }

            boolean isDirectory = inputFile.isDirectory();

            // Get output directory
            System.out.print("Enter output directory path: ");
            String outputDirPath = scanner.nextLine().trim();
            outputDirPath = removeQuotes(outputDirPath);

            File outputDir = new File(outputDirPath);

            // Create output directory if it doesn't exist
            if (!outputDir.exists()) {
                outputDir.mkdirs();
            }

            if (!outputDir.isDirectory()) {
                System.out.println("ERROR: Output path is not a directory.");
                return;
            }

            // Generate random filename for encrypted output
            String randomFileName = generateRandomFileName() + ENCRYPTED_FILE_EXTENSION;
            File outputFile = new File(outputDir, randomFileName);

            // Choose key input method
            System.out.println("\nChoose key input method:");
            System.out.println("  1. Enter key manually (password/emoji/mixed)");
            System.out.println("  2. Auto-generate random key");
            System.out.print("Enter choice (1 or 2): ");
            String keyChoice = scanner.nextLine().trim();

            SecretKey key;
            byte[] salt = KeyManager.generateRandomSalt();
            String generatedKey = null;

            if (keyChoice.equals("1")) {
                // Manual key input
                System.out.print("\nEnter your encryption key (min 8 characters, can include emoji): ");
                String password = scanner.nextLine();

                if (password.length() < 8) {
                    System.out.println("ERROR: Key must be at least 8 characters long.");
                    return;
                }

                char[] passwordChars = password.toCharArray();
                key = KeyManager.deriveKeyFromPassword(passwordChars, salt);
                KeyManager.clearPassword(passwordChars);

            } else if (keyChoice.equals("2")) {
                // Auto-generate key
                generatedKey = generateRandomKey();
                System.out.println("\nGenerated encryption key: " + generatedKey);
                System.out.println("IMPORTANT: Save this key securely! You'll need it for decryption.");

                char[] keyChars = generatedKey.toCharArray();
                key = KeyManager.deriveKeyFromPassword(keyChars, salt);
                KeyManager.clearPassword(keyChars);

            } else {
                System.out.println("ERROR: Invalid choice.");
                return;
            }

            // Create temporary file for the data to encrypt
            File tempDataFile = File.createTempFile("encrypto_", ".tmp");

            if (isDirectory) {
                // Pack folder into temporary file
                System.out.println("\nPacking folder...");
                packFolder(inputFile, tempDataFile);
            } else {
                // Pack single file with metadata
                System.out.println("\nPreparing file...");
                packSingleFile(inputFile, tempDataFile);
            }

            // Encrypt the temporary file
            File tempEncryptedFile = File.createTempFile("encrypto_enc_", ".tmp");
            System.out.println("Encrypting...");
            Encryptor.encryptFile(tempDataFile, tempEncryptedFile, key);

            // Prepend salt to create final file
            prependSaltToFile(tempEncryptedFile, outputFile, salt);

            // Clean up
            tempDataFile.delete();
            tempEncryptedFile.delete();

            System.out.println("SUCCESS: " + (isDirectory ? "Folder" : "File") + " encrypted successfully!");
            System.out.println("Output: " + outputFile.getAbsolutePath());

            if (generatedKey != null) {
                System.out.println("\n*** SAVE THIS KEY ***");
                System.out.println("Key: " + generatedKey);
                System.out.println("*** SAVE THIS KEY ***");
            } else {
                System.out.println("\nIMPORTANT: Remember your key! It cannot be recovered.");
            }

        } catch (Exception e) {
            System.out.println("ERROR: Encryption failed - " + e.getMessage());
        }
    }

    /**
     * Executes the decryption workflow.
     */
    public static void decryptFlow(Scanner scanner) {
        System.out.println("\n=== FILE/FOLDER DECRYPTION ===\n");

        try {
            // Get encrypted file
            System.out.print("Enter path to encrypted file: ");
            String inputPath = scanner.nextLine().trim();
            inputPath = removeQuotes(inputPath);

            File encryptedFile = new File(inputPath);

            if (!encryptedFile.exists() || !encryptedFile.isFile()) {
                System.out.println("ERROR: Encrypted file does not exist.");
                return;
            }

            if (encryptedFile.length() < SALT_LENGTH + 12) {
                System.out.println("ERROR: File is too small to be valid.");
                return;
            }

            // Get output directory
            System.out.print("Enter output directory path: ");
            String outputDirPath = scanner.nextLine().trim();
            outputDirPath = removeQuotes(outputDirPath);

            File outputDir = new File(outputDirPath);

            // Create output directory if it doesn't exist
            if (!outputDir.exists()) {
                outputDir.mkdirs();
            }

            if (!outputDir.isDirectory()) {
                System.out.println("ERROR: Output path is not a directory.");
                return;
            }

            // Extract salt
            byte[] salt = new byte[SALT_LENGTH];
            try (InputStream in = Files.newInputStream(encryptedFile.toPath())) {
                if (in.read(salt) != SALT_LENGTH) {
                    System.out.println("ERROR: Failed to read salt.");
                    return;
                }
            }

            // Get decryption key
            System.out.print("\nEnter decryption key: ");
            String password = scanner.nextLine();

            if (password.length() < 8) {
                System.out.println("ERROR: Key must be at least 8 characters long.");
                return;
            }

            char[] passwordChars = password.toCharArray();
            SecretKey key = KeyManager.deriveKeyFromPassword(passwordChars, salt);
            KeyManager.clearPassword(passwordChars);

            // Create temp file without salt
            File tempEncryptedFile = File.createTempFile("encrypto_dec_", ".tmp");
            extractFileWithoutSalt(encryptedFile, tempEncryptedFile, SALT_LENGTH);

            // Decrypt to temp file
            File tempDecryptedFile = File.createTempFile("encrypto_plain_", ".tmp");
            System.out.println("\nDecrypting...");
            Decryptor.decryptFile(tempEncryptedFile, tempDecryptedFile, key);

            // Check if it's a packed folder or single file
            String contentType = detectContentType(tempDecryptedFile);

            if (contentType.equals(FOLDER_MARKER)) {
                System.out.println("Unpacking folder...");
                unpackFolder(tempDecryptedFile, outputDir);
                System.out.println("SUCCESS: Folder decrypted successfully!");
                System.out.println("Output: " + outputDir.getAbsolutePath());
            } else if (contentType.equals(FILE_MARKER)) {
                System.out.println("Extracting file...");
                unpackSingleFile(tempDecryptedFile, outputDir);
                System.out.println("SUCCESS: File decrypted successfully!");
                System.out.println("Output: " + outputDir.getAbsolutePath());
            } else {
                System.out.println("ERROR: Unknown encrypted content format.");
            }

            // Clean up
            tempEncryptedFile.delete();
            tempDecryptedFile.delete();

        } catch (Exception e) {
            System.out.println("ERROR: Decryption failed - " + e.getMessage());
            System.out.println("Possible causes: Wrong key, corrupted file, or tampered data.");
        }
    }

    /**
     * Packs a single file with metadata.
     */
    private static void packSingleFile(File file, File outputFile) throws IOException {
        try (DataOutputStream out = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(outputFile)))) {

            // Write marker
            out.writeUTF(FILE_MARKER);

            // Write metadata
            out.writeUTF(file.getName());
            out.writeLong(file.lastModified());

            // Write file content
            byte[] data = Files.readAllBytes(file.toPath());
            out.writeInt(data.length);
            out.write(data);
        }
    }

    /**
     * Unpacks a single file with metadata.
     */
    private static void unpackSingleFile(File packedFile, File outputDir) throws IOException {
        try (DataInputStream in = new DataInputStream(
                new BufferedInputStream(new FileInputStream(packedFile)))) {

            // Read and verify marker
            String marker = in.readUTF();
            if (!marker.equals(FILE_MARKER)) {
                throw new IOException("Not a packed file");
            }

            // Read metadata
            String fileName = in.readUTF();
            long lastModified = in.readLong();

            // Read content
            int dataLength = in.readInt();
            byte[] data = new byte[dataLength];
            in.readFully(data);

            // Write to output directory
            File outputFile = new File(outputDir, fileName);

            // Handle duplicate names
            if (outputFile.exists()) {
                outputFile = createUniqueFileName(outputDir, fileName);
            }

            Files.write(outputFile.toPath(), data);
            outputFile.setLastModified(lastModified);
        }
    }

    /**
     * Packs a folder and all its contents into a single file.
     */
    private static void packFolder(File folder, File outputFile) throws IOException {
        try (DataOutputStream out = new DataOutputStream(
                new BufferedOutputStream(new FileOutputStream(outputFile)))) {

            // Write marker
            out.writeUTF(FOLDER_MARKER);
            out.writeUTF(folder.getName()); // Root folder name

            // Get all files recursively
            List<FileEntry> entries = new ArrayList<>();
            collectFiles(folder, folder, entries);

            // Write number of entries
            out.writeInt(entries.size());

            // Write each file
            for (FileEntry entry : entries) {
                out.writeUTF(entry.relativePath);
                out.writeBoolean(entry.isDirectory);

                if (!entry.isDirectory) {
                    out.writeLong(entry.file.lastModified());
                    byte[] data = Files.readAllBytes(entry.file.toPath());
                    out.writeInt(data.length);
                    out.write(data);
                }
            }
        }
    }

    /**
     * Unpacks a folder from a packed file.
     */
    private static void unpackFolder(File packedFile, File outputLocation) throws IOException {
        try (DataInputStream in = new DataInputStream(
                new BufferedInputStream(new FileInputStream(packedFile)))) {

            // Read and verify marker
            String marker = in.readUTF();
            if (!marker.equals(FOLDER_MARKER)) {
                throw new IOException("Not a packed folder");
            }

            String rootName = in.readUTF();
            File rootFolder = new File(outputLocation, rootName);

            // Handle duplicate folder names
            if (rootFolder.exists()) {
                rootFolder = createUniqueFolderName(outputLocation, rootName);
            }

            Files.createDirectories(rootFolder.toPath());

            int entryCount = in.readInt();

            for (int i = 0; i < entryCount; i++) {
                String relativePath = in.readUTF();
                boolean isDirectory = in.readBoolean();

                File targetFile = new File(rootFolder, relativePath);

                if (isDirectory) {
                    Files.createDirectories(targetFile.toPath());
                } else {
                    long lastModified = in.readLong();
                    Files.createDirectories(targetFile.getParentFile().toPath());
                    int dataLength = in.readInt();
                    byte[] data = new byte[dataLength];
                    in.readFully(data);
                    Files.write(targetFile.toPath(), data);
                    targetFile.setLastModified(lastModified);
                }
            }
        }
    }

    /**
     * Detects content type of decrypted file.
     */
    private static String detectContentType(File file) {
        try (DataInputStream in = new DataInputStream(
                new BufferedInputStream(new FileInputStream(file)))) {
            return in.readUTF();
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    /**
     * Generates a random filename.
     */
    private static String generateRandomFileName() {
        SecureRandom random = new SecureRandom();
        StringBuilder name = new StringBuilder("enc_");
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";

        for (int i = 0; i < 12; i++) {
            name.append(chars.charAt(random.nextInt(chars.length())));
        }

        return name.toString();
    }

    /**
     * Generates a random encryption key.
     */
    private static String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        StringBuilder key = new StringBuilder();

        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

        for (int i = 0; i < 24; i++) {
            key.append(chars.charAt(random.nextInt(chars.length())));
        }

        return key.toString();
    }

    /**
     * Creates a unique filename if file already exists.
     */
    private static File createUniqueFileName(File dir, String fileName) {
        String nameWithoutExt;
        String extension;

        int lastDot = fileName.lastIndexOf('.');
        if (lastDot > 0) {
            nameWithoutExt = fileName.substring(0, lastDot);
            extension = fileName.substring(lastDot);
        } else {
            nameWithoutExt = fileName;
            extension = "";
        }

        int counter = 1;
        File newFile;
        do {
            newFile = new File(dir, nameWithoutExt + "_" + counter + extension);
            counter++;
        } while (newFile.exists());

        return newFile;
    }

    /**
     * Creates a unique folder name if folder already exists.
     */
    private static File createUniqueFolderName(File parentDir, String folderName) {
        int counter = 1;
        File newFolder;
        do {
            newFolder = new File(parentDir, folderName + "_" + counter);
            counter++;
        } while (newFolder.exists());

        return newFolder;
    }

    /**
     * Collects all files in a directory recursively.
     */
    private static void collectFiles(File rootFolder, File currentFolder, List<FileEntry> entries)
            throws IOException {
        File[] files = currentFolder.listFiles();
        if (files == null) return;

        for (File file : files) {
            String relativePath = rootFolder.toPath().relativize(file.toPath()).toString();

            if (file.isDirectory()) {
                entries.add(new FileEntry(file, relativePath, true));
                collectFiles(rootFolder, file, entries);
            } else {
                entries.add(new FileEntry(file, relativePath, false));
            }
        }
    }

    /**
     * Helper class for file entries.
     */
    private static class FileEntry {
        File file;
        String relativePath;
        boolean isDirectory;

        FileEntry(File file, String relativePath, boolean isDirectory) {
            this.file = file;
            this.relativePath = relativePath;
            this.isDirectory = isDirectory;
        }
    }

    private static void prependSaltToFile(File sourceFile, File targetFile, byte[] salt)
            throws IOException {
        try (OutputStream out = Files.newOutputStream(targetFile.toPath(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            out.write(salt);
            Files.copy(sourceFile.toPath(), out);
        }
    }

    private static void extractFileWithoutSalt(File sourceFile, File targetFile, int saltLength)
            throws IOException {
        try (InputStream in = Files.newInputStream(sourceFile.toPath());
             OutputStream out = Files.newOutputStream(targetFile.toPath(),
                     StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {

            if (in.skip(saltLength) != saltLength) {
                throw new IOException("Failed to skip salt");
            }

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
    }

    private static String removeQuotes(String path) {
        if (path == null || path.length() < 2) return path;
        if ((path.startsWith("\"") && path.endsWith("\"")) ||
                (path.startsWith("'") && path.endsWith("'"))) {
            return path.substring(1, path.length() - 1);
        }
        return path;
    }
}