package cli;

import packager.StubGenerator;
import java.util.Scanner;

/**
 * MainCLI is the command-line interface entry point for CipherVibe.
 * Provides a simple menu-driven interface for file encryption and decryption.
 *
 * First working version - implements basic encryption/decryption with
 * password and emoji key support.
 */
public class MainCLI {

    private static final String VERSION = "1.0.0";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        displayWelcome();

        boolean running = true;

        while (running) {
            displayMenu();

            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    // Encrypt file
                    Commands.encryptFlow(scanner);
                    break;

                case "2":
                    // Decrypt file
                    Commands.decryptFlow(scanner);
                    break;

                case "3":
                    // Create self-extracting file
                    StubGenerator.createExecutable(scanner);
                    break;

                case "4":
                    // Exit
                    running = false;
                    System.out.println("\nThank you for using Encrypto!");
                    break;

                default:
                    System.out.println("\nERROR: Invalid choice. Please enter 1, 2, 3, or 4.");
                    break;
            }

            // Add spacing between operations
            if (running && !choice.equals("4")) {
                System.out.println("\n" + "=".repeat(50));
            }
        }

        scanner.close();
    }

    /**
     * Displays the welcome message when the application starts.
     */
    private static void displayWelcome() {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("              Encrypto File Encryption");
        System.out.println("                 Version " + VERSION);
        System.out.println("=".repeat(50));
        System.out.println("\nSecure AES-256-GCM encryption for files & folders");
        System.out.println("Supports password, emoji, and mixed-key encryption");
        System.out.println();
    }

    /**
     * Displays the main menu options.
     */
    private static void displayMenu() {
        System.out.println("\n--- MAIN MENU ---");
        System.out.println("1. Encrypt file/folder");
        System.out.println("2. Decrypt file/folder");
        System.out.println("3. Create self-extracting encrypted file");
        System.out.println("4. Exit");
        System.out.print("\nEnter your choice: ");
    }
}