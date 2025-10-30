package core;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

/**
 * FileUtils provides common file operation utilities for the Encrypto system.
 * All methods are cross-platform compatible (Windows/Linux/macOS).
 * No encryption logic is contained in this class.
 */
public class FileUtils {

    private static final int SECURE_DELETE_PASSES = 3; // Number of overwrite passes for secure deletion
    private static final int BUFFER_SIZE = 8192; // 8KB buffer for file operations

    /**
     * Creates a directory and all necessary parent directories if they don't exist.
     * If the directory already exists, this method does nothing.
     * 
     * @param directory The directory to create
     * @throws IOException If directory creation fails
     * @throws IllegalArgumentException If directory parameter is null
     */
    public static void createDirectories(File directory) throws IOException {
        if (directory == null) {
            throw new IllegalArgumentException("Directory cannot be null");
        }
        
        Path dirPath = directory.toPath();
        if (!Files.exists(dirPath)) {
            Files.createDirectories(dirPath);
        }
    }

    /**
     * Creates a directory from a Path and all necessary parent directories if they don't exist.
     * 
     * @param directoryPath The directory path to create
     * @throws IOException If directory creation fails
     * @throws IllegalArgumentException If directoryPath parameter is null
     */
    public static void createDirectories(Path directoryPath) throws IOException {
        if (directoryPath == null) {
            throw new IllegalArgumentException("Directory path cannot be null");
        }
        
        if (!Files.exists(directoryPath)) {
            Files.createDirectories(directoryPath);
        }
    }

    /**
     * Checks if a file exists and is readable.
     * 
     * @param file The file to check
     * @return true if the file exists, is a regular file, and is readable
     * @throws IllegalArgumentException If file parameter is null
     */
    public static boolean isFileReadable(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        
        Path filePath = file.toPath();
        return Files.exists(filePath) && 
               Files.isRegularFile(filePath) && 
               Files.isReadable(filePath);
    }

    /**
     * Checks if a file exists and is writable.
     * 
     * @param file The file to check
     * @return true if the file exists and is writable, or if it doesn't exist but parent directory is writable
     * @throws IllegalArgumentException If file parameter is null
     */
    public static boolean isFileWritable(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        
        Path filePath = file.toPath();
        
        // If file exists, check if it's writable
        if (Files.exists(filePath)) {
            return Files.isWritable(filePath);
        }
        
        // If file doesn't exist, check if parent directory is writable
        Path parent = filePath.getParent();
        return parent != null && Files.exists(parent) && Files.isWritable(parent);
    }

    /**
     * Securely deletes a file by overwriting its content with random bytes multiple times
     * before deleting it. This makes data recovery much more difficult.
     * Used for the "ShredAfter" feature to ensure encrypted files cannot be recovered.
     * 
     * Note: Effectiveness may vary on SSDs and flash storage due to wear-leveling.
     * 
     * @param file The file to securely delete
     * @throws IOException If file operations fail
     * @throws IllegalArgumentException If file parameter is null or is not a regular file
     */
    public static void secureDelete(File file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        
        Path filePath = file.toPath();
        
        if (!Files.exists(filePath)) {
            throw new IOException("File does not exist: " + file.getAbsolutePath());
        }
        
        if (!Files.isRegularFile(filePath)) {
            throw new IOException("Path is not a regular file: " + file.getAbsolutePath());
        }
        
        long fileSize = Files.size(filePath);
        
        // Overwrite file content multiple times with random data
        SecureRandom secureRandom = new SecureRandom();
        byte[] buffer = new byte[BUFFER_SIZE];
        
        for (int pass = 0; pass < SECURE_DELETE_PASSES; pass++) {
            long bytesWritten = 0;
            
            // Open file for writing (overwriting existing content)
            try (var outputStream = Files.newOutputStream(filePath, 
                    StandardOpenOption.WRITE, 
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                
                while (bytesWritten < fileSize) {
                    // Generate random bytes
                    secureRandom.nextBytes(buffer);
                    
                    // Calculate how many bytes to write in this iteration
                    int bytesToWrite = (int) Math.min(buffer.length, fileSize - bytesWritten);
                    
                    // Write random bytes to file
                    outputStream.write(buffer, 0, bytesToWrite);
                    bytesWritten += bytesToWrite;
                }
                
                // Ensure data is flushed to disk
                outputStream.flush();
            }
        }
        
        // Finally, delete the file
        Files.delete(filePath);
    }

    /**
     * Gets the file extension from a filename.
     * 
     * @param file The file to get extension from
     * @return The file extension (without the dot), or empty string if no extension
     * @throws IllegalArgumentException If file parameter is null
     */
    public static String getFileExtension(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        
        String filename = file.getName();
        int lastDotIndex = filename.lastIndexOf('.');
        
        if (lastDotIndex > 0 && lastDotIndex < filename.length() - 1) {
            return filename.substring(lastDotIndex + 1);
        }
        
        return "";
    }

    /**
     * Validates that a file exists, is a regular file, and is readable.
     * Throws descriptive exceptions if validation fails.
     * 
     * @param file The file to validate
     * @throws IOException If validation fails
     * @throws IllegalArgumentException If file parameter is null
     */
    public static void validateReadableFile(File file) throws IOException {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        
        if (!file.exists()) {
            throw new IOException("File does not exist: " + file.getAbsolutePath());
        }
        
        if (!file.isFile()) {
            throw new IOException("Path is not a regular file: " + file.getAbsolutePath());
        }
        
        if (!file.canRead()) {
            throw new IOException("File is not readable: " + file.getAbsolutePath());
        }
    }

    /**
     * Safely creates a unique filename if the target file already exists.
     * Appends (1), (2), etc. to the filename before the extension.
     * 
     * @param file The original file path
     * @return A File object with a unique name if original exists, or the original file if it doesn't exist
     * @throws IllegalArgumentException If file parameter is null
     */
    public static File createUniqueFile(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        
        if (!file.exists()) {
            return file;
        }
        
        String originalPath = file.getAbsolutePath();
        String parentPath = file.getParent();
        String filename = file.getName();
        
        int lastDotIndex = filename.lastIndexOf('.');
        String nameWithoutExt;
        String extension;
        
        if (lastDotIndex > 0) {
            nameWithoutExt = filename.substring(0, lastDotIndex);
            extension = filename.substring(lastDotIndex);
        } else {
            nameWithoutExt = filename;
            extension = "";
        }
        
        int counter = 1;
        File uniqueFile;
        
        do {
            String newFilename = nameWithoutExt + " (" + counter + ")" + extension;
            uniqueFile = new File(parentPath, newFilename);
            counter++;
        } while (uniqueFile.exists());
        
        return uniqueFile;
    }
}
