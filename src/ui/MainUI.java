package ui;

import core.Decryptor;
import core.Encryptor;
import keys.KeyManager;
import keys.PBKDF2Util;
import packager.StubGenerator;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.DragEvent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.*;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * MainUI - JavaFX interface for Encrypto file encryption system.
 * Provides GUI for encryption, decryption, and self-extracting JAR creation.
 */
public class MainUI extends Application {

    private static final String VERSION = "1.0.0";
    private static final int SALT_LENGTH = 16;
    private static final String ENCRYPTED_FILE_EXTENSION = ".encrypted";
    private static final String FOLDER_MARKER = "###FOLDER###";
    private static final String FILE_MARKER = "###FILE###";

    // UI Components
    private TextArea logArea;
    private String currentTheme = "light";
    private Scene mainScene;
    private File lastDirectory;

    // Encrypt Tab Components
    private TextField encryptInputField;
    private TextField encryptOutputField;
    private TextField encryptKeyField;
    private Button encryptStartButton;
    private ProgressBar encryptProgressBar;
    private Label encryptStatusLabel;
    private CheckBox encryptAutoKeyCheckBox;

    // Decrypt Tab Components
    private TextField decryptInputField;
    private TextField decryptOutputField;
    private TextField decryptKeyField;
    private Button decryptStartButton;
    private ProgressBar decryptProgressBar;
    private Label decryptStatusLabel;

    // Executable Tab Components
    private TextField execInputField;
    private TextField execOutputField;
    private TextField execKeyField;
    private Button execStartButton;
    private ProgressBar execProgressBar;
    private Label execStatusLabel;
    private CheckBox execAutoKeyCheckBox;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Encrypto - File Encryption v" + VERSION);

        // Main container
        BorderPane root = new BorderPane();
        root.setPadding(new Insets(10));

        // Top: Header with theme toggle
        HBox header = createHeader();
        root.setTop(header);

        // Center: Tabs
        TabPane tabPane = createTabPane();
        root.setCenter(tabPane);

        // Bottom: Log area
        VBox logSection = createLogSection();
        root.setBottom(logSection);

        // Create scene
        mainScene = new Scene(root, 900, 700);
        applyTheme();

        primaryStage.setScene(mainScene);
        primaryStage.setMinWidth(800);
        primaryStage.setMinHeight(600);
        primaryStage.show();

        logMessage("Welcome to Encrypto v" + VERSION);
        logMessage("Ready to encrypt/decrypt files and folders.");
    }

    /**
     * Creates the header with title and theme toggle.
     */
    private HBox createHeader() {
        HBox header = new HBox(20);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(10, 0, 10, 0));

        Label titleLabel = new Label("🔒 Encrypto File Encryption");
        titleLabel.setStyle("-fx-font-size: 20px; -fx-font-weight: bold;");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        header.getChildren().addAll(titleLabel, spacer);
        return header;
    }

    /**
     * Creates the main tab pane with Encrypt, Decrypt, and Executable tabs.
     */
    private TabPane createTabPane() {
        TabPane tabPane = new TabPane();
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        Tab encryptTab = new Tab("🔐 Encrypt", createEncryptTab());
        Tab decryptTab = new Tab("🔓 Decrypt", createDecryptTab());
        Tab executableTab = new Tab("📦 Self-Extractor", createExecutableTab());

        tabPane.getTabs().addAll(encryptTab, decryptTab, executableTab);
        return tabPane;
    }

    /**
     * Creates the Encrypt tab content.
     */
    private VBox createEncryptTab() {
        VBox content = new VBox(15);
        content.setPadding(new Insets(20));

        // Input section
        Label inputLabel = new Label("Input File/Folder:");
        inputLabel.setStyle("-fx-font-weight: bold;");

        HBox inputBox = new HBox(10);
        encryptInputField = new TextField();
        encryptInputField.setPromptText("Drag & drop or browse...");
        encryptInputField.setPrefWidth(500);
        setupDragAndDrop(encryptInputField, true);

        Button inputBrowseBtn = new Button("Browse");
        inputBrowseBtn.setOnAction(e -> browseInput(encryptInputField, true));

        inputBox.getChildren().addAll(encryptInputField, inputBrowseBtn);

        // Output section
        Label outputLabel = new Label("Output Directory:");
        outputLabel.setStyle("-fx-font-weight: bold;");

        HBox outputBox = new HBox(10);
        encryptOutputField = new TextField();
        encryptOutputField.setPromptText("Select output directory...");
        encryptOutputField.setPrefWidth(500);

        Button outputBrowseBtn = new Button("Browse");
        outputBrowseBtn.setOnAction(e -> browseOutputDirectory(encryptOutputField));

        outputBox.getChildren().addAll(encryptOutputField, outputBrowseBtn);

        // Key section
        Label keyLabel = new Label("Encryption Key:");
        keyLabel.setStyle("-fx-font-weight: bold;");

        HBox keyBox = new HBox(10);
        encryptKeyField = new PasswordField();
        encryptKeyField.setPromptText("Enter key (min 8 characters)...");
        encryptKeyField.setPrefWidth(400);

        encryptAutoKeyCheckBox = new CheckBox("Auto-generate key");
        encryptAutoKeyCheckBox.setOnAction(e -> {
            if (encryptAutoKeyCheckBox.isSelected()) {
                String key = generateRandomKey();
                encryptKeyField.setText(key);
                encryptKeyField.setDisable(true);
            } else {
                encryptKeyField.clear();
                encryptKeyField.setDisable(false);
            }
        });

        Button copyKeyBtn = new Button("Copy Key");
        copyKeyBtn.setOnAction(e -> copyToClipboard(encryptKeyField.getText()));

        keyBox.getChildren().addAll(encryptKeyField, encryptAutoKeyCheckBox, copyKeyBtn);

        // Progress section
        encryptProgressBar = new ProgressBar(0);
        encryptProgressBar.setPrefWidth(600);
        encryptProgressBar.setVisible(false);

        encryptStatusLabel = new Label("");
        encryptStatusLabel.setStyle("-fx-text-fill: #666;");

        // Start button
        encryptStartButton = new Button("🚀 Start Encryption");
        encryptStartButton.setPrefWidth(200);
        encryptStartButton.setStyle("-fx-font-size: 14px; -fx-font-weight: bold;");
        encryptStartButton.setOnAction(e -> startEncryption());

        content.getChildren().addAll(
                inputLabel, inputBox,
                outputLabel, outputBox,
                keyLabel, keyBox,
                new Separator(),
                encryptProgressBar,
                encryptStatusLabel,
                encryptStartButton
        );

        return content;
    }

    /**
     * Creates the Decrypt tab content.
     */
    private VBox createDecryptTab() {
        VBox content = new VBox(15);
        content.setPadding(new Insets(20));

        // Input section
        Label inputLabel = new Label("Encrypted File:");
        inputLabel.setStyle("-fx-font-weight: bold;");

        HBox inputBox = new HBox(10);
        decryptInputField = new TextField();
        decryptInputField.setPromptText("Drag & drop encrypted file or browse...");
        decryptInputField.setPrefWidth(500);
        setupDragAndDrop(decryptInputField, false);

        Button inputBrowseBtn = new Button("Browse");
        inputBrowseBtn.setOnAction(e -> browseInput(decryptInputField, false));

        inputBox.getChildren().addAll(decryptInputField, inputBrowseBtn);

        // Output section
        Label outputLabel = new Label("Output Directory:");
        outputLabel.setStyle("-fx-font-weight: bold;");

        HBox outputBox = new HBox(10);
        decryptOutputField = new TextField();
        decryptOutputField.setPromptText("Select output directory...");
        decryptOutputField.setPrefWidth(500);

        Button outputBrowseBtn = new Button("Browse");
        outputBrowseBtn.setOnAction(e -> browseOutputDirectory(decryptOutputField));

        outputBox.getChildren().addAll(decryptOutputField, outputBrowseBtn);

        // Key section
        Label keyLabel = new Label("Decryption Key:");
        keyLabel.setStyle("-fx-font-weight: bold;");

        HBox keyBox = new HBox(10);
        decryptKeyField = new PasswordField();
        decryptKeyField.setPromptText("Enter decryption key...");
        decryptKeyField.setPrefWidth(500);

        keyBox.getChildren().addAll(decryptKeyField);

        // Progress section
        decryptProgressBar = new ProgressBar(0);
        decryptProgressBar.setPrefWidth(600);
        decryptProgressBar.setVisible(false);

        decryptStatusLabel = new Label("");
        decryptStatusLabel.setStyle("-fx-text-fill: #666;");

        // Start button
        decryptStartButton = new Button("🔓 Start Decryption");
        decryptStartButton.setPrefWidth(200);
        decryptStartButton.setStyle("-fx-font-size: 14px; -fx-font-weight: bold;");
        decryptStartButton.setOnAction(e -> startDecryption());

        content.getChildren().addAll(
                inputLabel, inputBox,
                outputLabel, outputBox,
                keyLabel, keyBox,
                new Separator(),
                decryptProgressBar,
                decryptStatusLabel,
                decryptStartButton
        );

        return content;
    }

    /**
     * Creates the Self-Extractor tab content.
     */
    private VBox createExecutableTab() {
        VBox content = new VBox(15);
        content.setPadding(new Insets(20));

        // Input section
        Label inputLabel = new Label("Input File/Folder:");
        inputLabel.setStyle("-fx-font-weight: bold;");

        HBox inputBox = new HBox(10);
        execInputField = new TextField();
        execInputField.setPromptText("Drag & drop or browse...");
        execInputField.setPrefWidth(500);
        setupDragAndDrop(execInputField, true);

        Button inputBrowseBtn = new Button("Browse");
        inputBrowseBtn.setOnAction(e -> browseInput(execInputField, true));

        inputBox.getChildren().addAll(execInputField, inputBrowseBtn);

        // Output section
        Label outputLabel = new Label("Output Directory:");
        outputLabel.setStyle("-fx-font-weight: bold;");

        HBox outputBox = new HBox(10);
        execOutputField = new TextField();
        execOutputField.setPromptText("Select output directory...");
        execOutputField.setPrefWidth(500);

        Button outputBrowseBtn = new Button("Browse");
        outputBrowseBtn.setOnAction(e -> browseOutputDirectory(execOutputField));

        outputBox.getChildren().addAll(execOutputField, outputBrowseBtn);

        // Key section
        Label keyLabel = new Label("Encryption Key:");
        keyLabel.setStyle("-fx-font-weight: bold;");

        HBox keyBox = new HBox(10);
        execKeyField = new PasswordField();
        execKeyField.setPromptText("Enter key (min 8 characters)...");
        execKeyField.setPrefWidth(400);

        execAutoKeyCheckBox = new CheckBox("Auto-generate key");
        execAutoKeyCheckBox.setOnAction(e -> {
            if (execAutoKeyCheckBox.isSelected()) {
                String key = generateRandomKey();
                execKeyField.setText(key);
                execKeyField.setDisable(true);
            } else {
                execKeyField.clear();
                execKeyField.setDisable(false);
            }
        });

        Button copyKeyBtn = new Button("Copy Key");
        copyKeyBtn.setOnAction(e -> copyToClipboard(execKeyField.getText()));

        keyBox.getChildren().addAll(execKeyField, execAutoKeyCheckBox, copyKeyBtn);

        // Info label
        Label infoLabel = new Label("Creates a self-extracting JAR file that can decrypt itself.");
        infoLabel.setStyle("-fx-text-fill: #888; -fx-font-size: 11px;");

        // Progress section
        execProgressBar = new ProgressBar(0);
        execProgressBar.setPrefWidth(600);
        execProgressBar.setVisible(false);

        execStatusLabel = new Label("");
        execStatusLabel.setStyle("-fx-text-fill: #666;");

        // Start button
        execStartButton = new Button("📦 Create Self-Extractor");
        execStartButton.setPrefWidth(200);
        execStartButton.setStyle("-fx-font-size: 14px; -fx-font-weight: bold;");
        execStartButton.setOnAction(e -> startExecutableCreation());

        content.getChildren().addAll(
                inputLabel, inputBox,
                outputLabel, outputBox,
                keyLabel, keyBox,
                infoLabel,
                new Separator(),
                execProgressBar,
                execStatusLabel,
                execStartButton
        );

        return content;
    }

    /**
     * Creates the log section at the bottom.
     */
    private VBox createLogSection() {
        VBox logSection = new VBox(5);
        logSection.setPadding(new Insets(10, 0, 0, 0));

        Label logLabel = new Label("Activity Log:");
        logLabel.setStyle("-fx-font-weight: bold;");

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefHeight(150);
        logArea.setWrapText(true);
        logArea.setStyle("-fx-font-family: 'Courier New', monospace; -fx-font-size: 11px;");

        Button clearLogBtn = new Button("Clear Log");
        clearLogBtn.setOnAction(e -> logArea.clear());

        HBox logHeader = new HBox(10);
        logHeader.setAlignment(Pos.CENTER_LEFT);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        logHeader.getChildren().addAll(logLabel, spacer, clearLogBtn);

        logSection.getChildren().addAll(logHeader, logArea);
        return logSection;
    }

    /**
     * Sets up drag and drop for text fields.
     */
    private void setupDragAndDrop(TextField textField, boolean allowBoth) {
        textField.setOnDragOver((DragEvent event) -> {
            if (event.getGestureSource() != textField && event.getDragboard().hasFiles()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
            event.consume();
        });

        textField.setOnDragDropped((DragEvent event) -> {
            Dragboard db = event.getDragboard();
            boolean success = false;
            if (db.hasFiles()) {
                List<File> files = db.getFiles();
                if (!files.isEmpty()) {
                    File file = files.get(0);
                    if (allowBoth || file.isFile()) {
                        textField.setText(file.getAbsolutePath());
                        success = true;
                    } else {
                        showError("Invalid Input", "Please drop a file, not a folder.");
                    }
                }
            }
            event.setDropCompleted(success);
            event.consume();
        });
    }

    /**
     * Browse for input file or folder.
     */
    private void browseInput(TextField targetField, boolean allowFolders) {
        if (allowFolders) {
            // Show choice dialog
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Select Input Type");
            alert.setHeaderText("Choose input type:");
            alert.setContentText("Select File or Folder?");

            ButtonType fileBtn = new ButtonType("File");
            ButtonType folderBtn = new ButtonType("Folder");
            ButtonType cancelBtn = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);

            alert.getButtonTypes().setAll(fileBtn, folderBtn, cancelBtn);

            Optional<ButtonType> result = alert.showAndWait();
            if (result.isPresent()) {
                if (result.get() == fileBtn) {
                    FileChooser fc = new FileChooser();
                    fc.setTitle("Select File");
                    if (lastDirectory != null) fc.setInitialDirectory(lastDirectory);
                    File file = fc.showOpenDialog(mainScene.getWindow());
                    if (file != null) {
                        targetField.setText(file.getAbsolutePath());
                        lastDirectory = file.getParentFile();
                    }
                } else if (result.get() == folderBtn) {
                    DirectoryChooser dc = new DirectoryChooser();
                    dc.setTitle("Select Folder");
                    if (lastDirectory != null) dc.setInitialDirectory(lastDirectory);
                    File folder = dc.showDialog(mainScene.getWindow());
                    if (folder != null) {
                        targetField.setText(folder.getAbsolutePath());
                        lastDirectory = folder.getParentFile();
                    }
                }
            }
        } else {
            FileChooser fc = new FileChooser();
            fc.setTitle("Select Encrypted File");
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Encrypted Files", "*.encrypted"));
            if (lastDirectory != null) fc.setInitialDirectory(lastDirectory);
            File file = fc.showOpenDialog(mainScene.getWindow());
            if (file != null) {
                targetField.setText(file.getAbsolutePath());
                lastDirectory = file.getParentFile();
            }
        }
    }

    /**
     * Browse for output directory.
     */
    private void browseOutputDirectory(TextField targetField) {
        DirectoryChooser dc = new DirectoryChooser();
        dc.setTitle("Select Output Directory");
        if (lastDirectory != null) dc.setInitialDirectory(lastDirectory);
        File folder = dc.showDialog(mainScene.getWindow());
        if (folder != null) {
            targetField.setText(folder.getAbsolutePath());
            lastDirectory = folder;
        }
    }

    /**
     * Starts the encryption process.
     */
    private void startEncryption() {
        String inputPath = encryptInputField.getText().trim();
        String outputPath = encryptOutputField.getText().trim();
        String key = encryptKeyField.getText();

        // Validation
        if (inputPath.isEmpty() || outputPath.isEmpty()) {
            showError("Missing Input", "Please provide input and output paths.");
            return;
        }

        if (key.length() < 8) {
            showError("Invalid Key", "Encryption key must be at least 8 characters long.");
            return;
        }

        File inputFile = new File(inputPath);
        File outputDir = new File(outputPath);

        if (!inputFile.exists()) {
            showError("File Not Found", "Input path does not exist.");
            return;
        }

        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        // Disable button and show progress
        encryptStartButton.setDisable(true);
        encryptProgressBar.setVisible(true);
        encryptProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        encryptStatusLabel.setText("Encrypting...");

        // Run encryption in background
        Task<Void> task = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                logMessage("--- Starting Encryption ---");
                logMessage("Input: " + inputPath);
                logMessage("Output: " + outputPath);

                boolean isDirectory = inputFile.isDirectory();

                // Generate salt
                byte[] salt = new byte[SALT_LENGTH];
                new SecureRandom().nextBytes(salt);

                // Derive key
                char[] passwordChars = key.toCharArray();
                SecretKey secretKey = PBKDF2Util.generateAESKey(passwordChars, salt);
                KeyManager.clearPassword(passwordChars);

                // Create temp files
                File tempDataFile = File.createTempFile("encrypto_", ".tmp");
                File tempEncryptedFile = File.createTempFile("encrypto_enc_", ".tmp");

                try {
                    // Pack data
                    if (isDirectory) {
                        logMessage("Packing folder...");
                        packFolder(inputFile, tempDataFile);
                    } else {
                        logMessage("Preparing file...");
                        packSingleFile(inputFile, tempDataFile);
                    }

                    // Encrypt
                    logMessage("Encrypting data...");
                    Encryptor.encryptFile(tempDataFile, tempEncryptedFile, secretKey);

                    // Create final output
                    String randomFileName = generateRandomFileName() + ENCRYPTED_FILE_EXTENSION;
                    File outputFile = new File(outputDir, randomFileName);

                    prependSaltToFile(tempEncryptedFile, outputFile, salt);

                    logMessage("SUCCESS: Encryption completed!");
                    logMessage("Output file: " + outputFile.getAbsolutePath());

                    if (encryptAutoKeyCheckBox.isSelected()) {
                        logMessage("*** SAVE THIS KEY: " + key + " ***");
                    }

                } finally {
                    tempDataFile.delete();
                    tempEncryptedFile.delete();
                }

                return null;
            }
        };

        task.setOnSucceeded(e -> {
            encryptProgressBar.setVisible(false);
            encryptStatusLabel.setText("✅ Encryption completed successfully!");
            encryptStartButton.setDisable(false);
            showInfo("Success", "File encrypted successfully!");
        });

        task.setOnFailed(e -> {
            encryptProgressBar.setVisible(false);
            encryptStatusLabel.setText("❌ Encryption failed!");
            encryptStartButton.setDisable(false);
            Throwable ex = task.getException();
            logMessage("ERROR: " + ex.getMessage());
            showError("Encryption Failed", ex.getMessage());
        });

        new Thread(task).start();
    }

    /**
     * Starts the decryption process.
     */
    private void startDecryption() {
        String inputPath = decryptInputField.getText().trim();
        String outputPath = decryptOutputField.getText().trim();
        String key = decryptKeyField.getText();

        // Validation
        if (inputPath.isEmpty() || outputPath.isEmpty()) {
            showError("Missing Input", "Please provide input file and output directory.");
            return;
        }

        if (key.length() < 8) {
            showError("Invalid Key", "Decryption key must be at least 8 characters long.");
            return;
        }

        File encryptedFile = new File(inputPath);
        File outputDir = new File(outputPath);

        if (!encryptedFile.exists() || !encryptedFile.isFile()) {
            showError("File Not Found", "Encrypted file does not exist.");
            return;
        }

        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        // Disable button and show progress
        decryptStartButton.setDisable(true);
        decryptProgressBar.setVisible(true);
        decryptProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        decryptStatusLabel.setText("Decrypting...");

        // Run decryption in background
        Task<Void> task = new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                logMessage("--- Starting Decryption ---");
                logMessage("Input: " + inputPath);
                logMessage("Output: " + outputPath);

                // Extract salt
                byte[] salt = new byte[SALT_LENGTH];
                try (InputStream in = Files.newInputStream(encryptedFile.toPath())) {
                    if (in.read(salt) != SALT_LENGTH) {
                        throw new IOException("Failed to read salt");
                    }
                }

                // Derive key
                char[] passwordChars = key.toCharArray();
                SecretKey secretKey = PBKDF2Util.generateAESKey(passwordChars, salt);
                KeyManager.clearPassword(passwordChars);

                // Create temp files
                File tempEncryptedFile = File.createTempFile("encrypto_dec_", ".tmp");
                File tempDecryptedFile = File.createTempFile("encrypto_plain_", ".tmp");

                try {
                    // Extract file without salt
                    extractFileWithoutSalt(encryptedFile, tempEncryptedFile, SALT_LENGTH);

                    // Decrypt
                    logMessage("Decrypting...");
                    Decryptor.decryptFile(tempEncryptedFile, tempDecryptedFile, secretKey);

                    // Check content type
                    String contentType = detectContentType(tempDecryptedFile);

                    if (FOLDER_MARKER.equals(contentType)) {
                        logMessage("Unpacking folder...");
                        unpackFolder(tempDecryptedFile, outputDir);
                        logMessage("SUCCESS: Folder decrypted!");
                    } else if (FILE_MARKER.equals(contentType)) {
                        logMessage("Extracting file...");
                        unpackSingleFile(tempDecryptedFile, outputDir);
                        logMessage("SUCCESS: File decrypted!");
                    } else {
                        throw new IOException("Unknown content format");
                    }

                    logMessage("Output: " + outputDir.getAbsolutePath());

                } finally {
                    tempEncryptedFile.delete();
                    tempDecryptedFile.delete();
                }

                return null;
            }
        };

        task.setOnSucceeded(e -> {
            decryptProgressBar.setVisible(false);
            decryptStatusLabel.setText("✅ Decryption completed successfully!");
            decryptStartButton.setDisable(false);
            showInfo("Success", "File decrypted successfully!");
        });

        task.setOnFailed(e -> {
            decryptProgressBar.setVisible(false);
            decryptStatusLabel.setText("❌ Decryption failed!");
            decryptStartButton.setDisable(false);
            Throwable ex = task.getException();
            logMessage("ERROR: " + ex.getMessage());
            showError("Decryption Failed", "Wrong key or corrupted file.");
        });

        new Thread(task).start();
    }

    /**
     * Starts self-extracting executable creation.
     */
    private void startExecutableCreation() {
        String inputPath = execInputField.getText().trim();
        String outputPath = execOutputField.getText().trim();
        String key = execKeyField.getText();

        // Validation
        if (inputPath.isEmpty() || outputPath.isEmpty()) {
            showError("Missing Input", "Please provide input and output paths.");
            return;
        }

        if (key.length() < 8) {
            showError("Invalid Key", "Encryption key must be at least 8 characters long.");
            return;
        }

        File inputFile = new File(inputPath);
        File outputDir = new File(outputPath);

        if (!inputFile.exists()) {
            showError("File Not Found", "Input path does not exist.");
            return;
        }

        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        // Disable button and show progress
        execStartButton.setDisable(true);
        execProgressBar.setVisible(true);
        execProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        execStatusLabel.setText("Creating self-extractor...");

        // Run creation in background
        Task<String> task = new Task<String>() {
            @Override
            protected String call() throws Exception {
                logMessage("--- Creating Self-Extracting JAR ---");
                logMessage("Input: " + inputPath);
                logMessage("Output: " + outputPath);

                // Use StubGenerator logic
                boolean isDirectory = inputFile.isDirectory();

                // Generate salt
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);

                // Derive key
                char[] passwordChars = key.toCharArray();
                SecretKey secretKey = PBKDF2Util.generateAESKey(passwordChars, salt);
                KeyManager.clearPassword(passwordChars);

                // Pack content
                File tempPackedFile = File.createTempFile("encrypto_pack_", ".tmp");
                try {
                    if (isDirectory) {
                        logMessage("Packing folder...");
                        packFolder(inputFile, tempPackedFile);
                    } else {
                        logMessage("Packing file...");
                        packSingleFile(inputFile, tempPackedFile);
                    }

                    // Encrypt
                    logMessage("Encrypting...");
                    byte[] iv = new byte[12];
                    new SecureRandom().nextBytes(iv);

                    byte[] packedData = Files.readAllBytes(tempPackedFile.toPath());
                    byte[] encryptedData = encryptData(packedData, secretKey, iv);

                    // Create JAR
                    logMessage("Building JAR file...");
                    String jarName = "SecureFile_" + generateRandomId() + ".jar";
                    File outputFile = new File(outputDir, jarName);

                    // Call StubGenerator's internal method (we'll create a wrapper)
                    createSelfExtractingJar(outputFile, salt, iv, encryptedData);

                    logMessage("SUCCESS: Self-extractor created!");
                    logMessage("Output: " + outputFile.getAbsolutePath());
                    logMessage("To extract: Double-click the JAR file");

                    if (execAutoKeyCheckBox.isSelected()) {
                        logMessage("*** SAVE THIS KEY: " + key + " ***");
                    }

                    return outputFile.getAbsolutePath();

                } finally {
                    tempPackedFile.delete();
                }
            }
        };

        task.setOnSucceeded(e -> {
            execProgressBar.setVisible(false);
            execStatusLabel.setText("✅ Self-extractor created successfully!");
            execStartButton.setDisable(false);
            String outputFilePath = task.getValue();
            showInfo("Success", "Self-extracting JAR created!\n\n" + outputFilePath);
        });

        task.setOnFailed(e -> {
            execProgressBar.setVisible(false);
            execStatusLabel.setText("❌ Creation failed!");
            execStartButton.setDisable(false);
            Throwable ex = task.getException();
            logMessage("ERROR: " + ex.getMessage());
            showError("Creation Failed", ex.getMessage());
        });

        new Thread(task).start();
    }

    /**
     * Creates self-extracting JAR using StubGenerator logic.
     */
    private void createSelfExtractingJar(File outputFile, byte[] salt, byte[] iv, byte[] encryptedData) throws Exception {
        // Compile extractor class
        File tempDir = Files.createTempDirectory("encrypto_build_").toFile();
        File sourceFile = new File(tempDir, "SelfExtract.java");

        // Generate source code
        String sourceCode = generateExtractorSource();
        Files.write(sourceFile.toPath(), sourceCode.getBytes("UTF-8"));

        // Compile
        logMessage("Compiling extractor...");
        ProcessBuilder pb = new ProcessBuilder("javac", "-source", "8", "-target", "8", sourceFile.getAbsolutePath());
        pb.directory(tempDir);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            logMessage("Compile: " + line);
        }

        int result = process.waitFor();
        if (result != 0) {
            throw new IOException("Compilation failed. Ensure javac is in PATH.");
        }

        // Create JAR
        logMessage("Creating JAR...");
        java.util.jar.Manifest manifest = new java.util.jar.Manifest();
        manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MAIN_CLASS, "SelfExtract");

        try (java.util.jar.JarOutputStream jarOut = new java.util.jar.JarOutputStream(
                new FileOutputStream(outputFile), manifest)) {

            // Add all class files
            File[] classFiles = tempDir.listFiles((dir, name) -> name.endsWith(".class"));
            if (classFiles != null) {
                for (File classFile : classFiles) {
                    java.util.jar.JarEntry classEntry = new java.util.jar.JarEntry(classFile.getName());
                    jarOut.putNextEntry(classEntry);
                    Files.copy(classFile.toPath(), jarOut);
                    jarOut.closeEntry();
                }
            }

            // Add encrypted data
            java.util.jar.JarEntry dataEntry = new java.util.jar.JarEntry("encrypted.dat");
            jarOut.putNextEntry(dataEntry);
            jarOut.write("###ENCRYPTO_SELF_EXTRACT###".getBytes("UTF-8"));
            jarOut.write(salt);
            jarOut.write(iv);

            ByteArrayOutputStream lengthBytes = new ByteArrayOutputStream();
            DataOutputStream lengthOut = new DataOutputStream(lengthBytes);
            lengthOut.writeInt(encryptedData.length);
            jarOut.write(lengthBytes.toByteArray());

            jarOut.write(encryptedData);
            jarOut.closeEntry();
        }

        // Cleanup
        deleteDirectory(tempDir);
    }

    /**
     * Generates extractor source code.
     */
    private String generateExtractorSource() {
        return "import javax.crypto.*;\n" +
                "import javax.crypto.spec.*;\n" +
                "import javax.swing.*;\n" +
                "import java.awt.*;\n" +
                "import java.awt.event.*;\n" +
                "import java.io.*;\n" +
                "import java.security.*;\n" +
                "import java.util.*;\n\n" +

                "public class SelfExtract {\n" +
                "    private static final String SIG = \"###ENCRYPTO_SELF_EXTRACT###\";\n" +
                "    private static final int SALT_LEN = 16;\n" +
                "    private static final int IV_LEN = 12;\n" +
                "    private static final String FOLDER = \"###FOLDER###\";\n" +
                "    private static final String FILE = \"###FILE###\";\n" +
                "    private static final int PBKDF2_ITERATIONS = 210000;\n\n" +

                "    public static void main(String[] args) {\n" +
                "        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); } catch (Exception e) {}\n" +
                "        SwingUtilities.invokeLater(new ShowGUI());\n" +
                "    }\n\n" +

                "    static class ShowGUI implements Runnable {\n" +
                "        public void run() {\n" +
                "            final JFrame frame = new JFrame(\"Encrypto Self-Extractor\");\n" +
                "            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);\n" +
                "            frame.setSize(550, 350);\n" +
                "            frame.setLocationRelativeTo(null);\n\n" +

                "            JPanel panel = new JPanel(new BorderLayout(10, 10));\n" +
                "            panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));\n\n" +

                "            JLabel title = new JLabel(\"Encrypted Archive Extractor\", SwingConstants.CENTER);\n" +
                "            title.setFont(new Font(\"Arial\", Font.BOLD, 18));\n" +
                "            panel.add(title, BorderLayout.NORTH);\n\n" +

                "            JPanel center = new JPanel(new GridLayout(3, 1, 10, 10));\n" +
                "            JLabel info = new JLabel(\"Enter decryption key:\", SwingConstants.CENTER);\n" +
                "            final JPasswordField keyField = new JPasswordField();\n" +
                "            keyField.setFont(new Font(\"Monospaced\", Font.PLAIN, 14));\n" +
                "            final JButton btn = new JButton(\"Extract Files\");\n" +
                "            btn.setFont(new Font(\"Arial\", Font.BOLD, 14));\n\n" +

                "            center.add(info);\n" +
                "            center.add(keyField);\n" +
                "            center.add(btn);\n" +
                "            panel.add(center, BorderLayout.CENTER);\n\n" +

                "            final JTextArea status = new JTextArea();\n" +
                "            status.setEditable(false);\n" +
                "            status.setFont(new Font(\"Monospaced\", Font.PLAIN, 11));\n" +
                "            JScrollPane scroll = new JScrollPane(status);\n" +
                "            scroll.setPreferredSize(new Dimension(500, 150));\n" +
                "            panel.add(scroll, BorderLayout.SOUTH);\n\n" +

                "            btn.addActionListener(new ActionListener() {\n" +
                "                public void actionPerformed(ActionEvent e) {\n" +
                "                    String pwd = new String(keyField.getPassword());\n" +
                "                    if (pwd.length() < 8) {\n" +
                "                        status.setText(\"ERROR: Key must be 8+ characters.\\n\");\n" +
                "                        return;\n" +
                "                    }\n" +
                "                    btn.setEnabled(false);\n" +
                "                    keyField.setEnabled(false);\n" +
                "                    new ExtractThread(pwd, status, frame).start();\n" +
                "                }\n" +
                "            });\n\n" +

                "            keyField.addActionListener(new ActionListener() {\n" +
                "                public void actionPerformed(ActionEvent e) { btn.doClick(); }\n" +
                "            });\n\n" +

                "            frame.add(panel);\n" +
                "            frame.setVisible(true);\n" +
                "            keyField.requestFocus();\n" +
                "        }\n" +
                "    }\n\n" +

                "    static class ExtractThread extends Thread {\n" +
                "        String pwd;\n" +
                "        JTextArea status;\n" +
                "        JFrame frame;\n" +
                "        ExtractThread(String p, JTextArea s, JFrame f) { pwd = p; status = s; frame = f; }\n\n" +

                "        public void run() {\n" +
                "            try {\n" +
                "                status.append(\"Loading encrypted data...\\n\");\n" +
                "                EmbeddedData data = extractData();\n" +
                "                if (data == null) {\n" +
                "                    status.append(\"ERROR: Invalid archive.\\n\");\n" +
                "                    return;\n" +
                "                }\n\n" +

                "                status.append(\"Deriving key...\\n\");\n" +
                "                SecretKey key = deriveKey(pwd, data.salt);\n\n" +

                "                status.append(\"Decrypting...\\n\");\n" +
                "                byte[] dec = decrypt(data.payload, data.iv, key);\n" +
                "                if (dec == null) {\n" +
                "                    status.append(\"ERROR: Wrong key or corrupted.\\n\");\n" +
                "                    return;\n" +
                "                }\n\n" +

                "                File dir = new File(System.getProperty(\"user.dir\"));\n" +
                "                status.append(\"Extracting to: \" + dir.getAbsolutePath() + \"\\n\");\n\n" +

                "                String type = getType(dec);\n" +
                "                if (FOLDER.equals(type)) {\n" +
                "                    unpackFolder(dec, dir, status);\n" +
                "                } else if (FILE.equals(type)) {\n" +
                "                    unpackFile(dec, dir, status);\n" +
                "                }\n\n" +

                "                status.append(\"\\nSUCCESS! Files extracted.\\n\");\n" +
                "                status.append(\"Closing in 5 seconds...\\n\");\n" +
                "                Thread.sleep(5000);\n" +
                "                selfDelete();\n" +
                "                System.exit(0);\n" +
                "            } catch (Exception ex) {\n" +
                "                status.append(\"ERROR: \" + ex.getMessage() + \"\\n\");\n" +
                "                ex.printStackTrace();\n" +
                "            }\n" +
                "        }\n" +
                "    }\n\n" +

                "    static EmbeddedData extractData() {\n" +
                "        try {\n" +
                "            InputStream is = SelfExtract.class.getResourceAsStream(\"/encrypted.dat\");\n" +
                "            if (is == null) return null;\n" +
                "            DataInputStream in = new DataInputStream(is);\n" +
                "            byte[] sig = new byte[SIG.getBytes(\"UTF-8\").length];\n" +
                "            in.readFully(sig);\n" +
                "            if (!Arrays.equals(sig, SIG.getBytes(\"UTF-8\"))) return null;\n" +
                "            byte[] salt = new byte[SALT_LEN];\n" +
                "            in.readFully(salt);\n" +
                "            byte[] iv = new byte[IV_LEN];\n" +
                "            in.readFully(iv);\n" +
                "            int len = in.readInt();\n" +
                "            byte[] payload = new byte[len];\n" +
                "            in.readFully(payload);\n" +
                "            in.close();\n" +
                "            return new EmbeddedData(salt, iv, payload);\n" +
                "        } catch (Exception e) {\n" +
                "            return null;\n" +
                "        }\n" +
                "    }\n\n" +

                "    static SecretKey deriveKey(String pwd, byte[] salt) throws Exception {\n" +
                "        SecretKeyFactory factory = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");\n" +
                "        javax.crypto.spec.PBEKeySpec keySpec = new javax.crypto.spec.PBEKeySpec(\n" +
                "            pwd.toCharArray(),\n" +
                "            salt,\n" +
                "            PBKDF2_ITERATIONS,\n" +
                "            256\n" +
                "        );\n" +
                "        SecretKey tmpKey = factory.generateSecret(keySpec);\n" +
                "        keySpec.clearPassword();\n" +
                "        byte[] keyBytes = tmpKey.getEncoded();\n" +
                "        return new SecretKeySpec(keyBytes, \"AES\");\n" +
                "    }\n\n" +

                "    static byte[] decrypt(byte[] data, byte[] iv, SecretKey key) {\n" +
                "        try {\n" +
                "            Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n" +
                "            GCMParameterSpec spec = new GCMParameterSpec(128, iv);\n" +
                "            c.init(Cipher.DECRYPT_MODE, key, spec);\n" +
                "            return c.doFinal(data);\n" +
                "        } catch (Exception e) {\n" +
                "            return null;\n" +
                "        }\n" +
                "    }\n\n" +

                "    static String getType(byte[] data) {\n" +
                "        try {\n" +
                "            DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));\n" +
                "            return in.readUTF();\n" +
                "        } catch (Exception e) {\n" +
                "            return \"UNKNOWN\";\n" +
                "        }\n" +
                "    }\n\n" +

                "    static void unpackFile(byte[] data, File dir, JTextArea st) throws IOException {\n" +
                "        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));\n" +
                "        in.readUTF();\n" +
                "        String name = in.readUTF();\n" +
                "        long mod = in.readLong();\n" +
                "        int len = in.readInt();\n" +
                "        byte[] d = new byte[len];\n" +
                "        in.readFully(d);\n" +
                "        File out = new File(dir, name);\n" +
                "        if (out.exists()) out = uniqueFile(dir, name);\n" +
                "        FileOutputStream fos = new FileOutputStream(out);\n" +
                "        fos.write(d);\n" +
                "        fos.close();\n" +
                "        out.setLastModified(mod);\n" +
                "        st.append(\"Extracted: \" + name + \"\\n\");\n" +
                "    }\n\n" +

                "    static void unpackFolder(byte[] data, File dir, JTextArea st) throws IOException {\n" +
                "        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));\n" +
                "        in.readUTF();\n" +
                "        String root = in.readUTF();\n" +
                "        File r = new File(dir, root);\n" +
                "        if (r.exists()) r = uniqueFolder(dir, root);\n" +
                "        r.mkdirs();\n" +
                "        int cnt = in.readInt();\n" +
                "        for (int i = 0; i < cnt; i++) {\n" +
                "            String path = in.readUTF();\n" +
                "            boolean isDir = in.readBoolean();\n" +
                "            File t = new File(r, path);\n" +
                "            if (isDir) {\n" +
                "                t.mkdirs();\n" +
                "            } else {\n" +
                "                long mod = in.readLong();\n" +
                "                t.getParentFile().mkdirs();\n" +
                "                int len = in.readInt();\n" +
                "                byte[] d = new byte[len];\n" +
                "                in.readFully(d);\n" +
                "                FileOutputStream fos = new FileOutputStream(t);\n" +
                "                fos.write(d);\n" +
                "                fos.close();\n" +
                "                t.setLastModified(mod);\n" +
                "            }\n" +
                "        }\n" +
                "        st.append(\"Extracted: \" + r.getName() + \"\\n\");\n" +
                "    }\n\n" +

                "    static void selfDelete() {\n" +
                "        try {\n" +
                "            File jar = new File(SelfExtract.class.getProtectionDomain().getCodeSource().getLocation().toURI());\n" +
                "            String os = System.getProperty(\"os.name\").toLowerCase();\n" +
                "            if (os.contains(\"win\")) {\n" +
                "                Runtime.getRuntime().exec(\"cmd /c ping localhost -n 2 > nul && del \\\"\" + jar.getAbsolutePath() + \"\\\"\");\n" +
                "            } else {\n" +
                "                Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", \"sleep 2; rm '\" + jar.getAbsolutePath() + \"'\"});\n" +
                "            }\n" +
                "        } catch (Exception e) {}\n" +
                "    }\n\n" +

                "    static File uniqueFile(File dir, String name) {\n" +
                "        int dot = name.lastIndexOf('.');\n" +
                "        String base = dot > 0 ? name.substring(0, dot) : name;\n" +
                "        String ext = dot > 0 ? name.substring(dot) : \"\";\n" +
                "        int c = 1;\n" +
                "        File f;\n" +
                "        do { f = new File(dir, base + \"_\" + c + ext); c++; } while (f.exists());\n" +
                "        return f;\n" +
                "    }\n\n" +

                "    static File uniqueFolder(File dir, String name) {\n" +
                "        int c = 1;\n" +
                "        File f;\n" +
                "        do { f = new File(dir, name + \"_\" + c); c++; } while (f.exists());\n" +
                "        return f;\n" +
                "    }\n\n" +

                "    static class EmbeddedData {\n" +
                "        byte[] salt, iv, payload;\n" +
                "        EmbeddedData(byte[] s, byte[] i, byte[] p) { salt = s; iv = i; payload = p; }\n" +
                "    }\n" +
                "}\n";
    }

    // ==================== UTILITY METHODS ====================

    /**
     * Encrypts data using AES-GCM.
     */
    private byte[] encryptData(byte[] data, SecretKey key, byte[] iv) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(data);
    }

    /**
     * Packs a single file with metadata.
     */
    private void packSingleFile(File file, File outputFile) throws IOException {
        try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)))) {
            out.writeUTF(FILE_MARKER);
            out.writeUTF(file.getName());
            out.writeLong(file.lastModified());
            byte[] data = Files.readAllBytes(file.toPath());
            out.writeInt(data.length);
            out.write(data);
        }
    }

    /**
     * Unpacks a single file with metadata.
     */
    private void unpackSingleFile(File packedFile, File outputDir) throws IOException {
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(packedFile)))) {
            String marker = in.readUTF();
            if (!marker.equals(FILE_MARKER)) {
                throw new IOException("Not a packed file");
            }

            String fileName = in.readUTF();
            long lastModified = in.readLong();
            int dataLength = in.readInt();
            byte[] data = new byte[dataLength];
            in.readFully(data);

            File outputFile = new File(outputDir, fileName);
            if (outputFile.exists()) {
                outputFile = createUniqueFileName(outputDir, fileName);
            }

            Files.write(outputFile.toPath(), data);
            outputFile.setLastModified(lastModified);
        }
    }

    /**
     * Packs a folder recursively.
     */
    private void packFolder(File folder, File outputFile) throws IOException {
        try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)))) {
            out.writeUTF(FOLDER_MARKER);
            out.writeUTF(folder.getName());

            List<FileEntry> entries = new ArrayList<>();
            collectFiles(folder, folder, entries);

            out.writeInt(entries.size());

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
     * Unpacks a folder.
     */
    private void unpackFolder(File packedFile, File outputLocation) throws IOException {
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(packedFile)))) {
            String marker = in.readUTF();
            if (!marker.equals(FOLDER_MARKER)) {
                throw new IOException("Not a packed folder");
            }

            String rootName = in.readUTF();
            File rootFolder = new File(outputLocation, rootName);

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
     * Collects all files recursively.
     */
    private void collectFiles(File rootFolder, File currentFolder, List<FileEntry> entries) throws IOException {
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
     * Detects content type.
     */
    private String detectContentType(File file) {
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            return in.readUTF();
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    /**
     * Prepends salt to encrypted file.
     */
    private void prependSaltToFile(File sourceFile, File targetFile, byte[] salt) throws IOException {
        try (OutputStream out = Files.newOutputStream(targetFile.toPath(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            out.write(salt);
            Files.copy(sourceFile.toPath(), out);
        }
    }

    /**
     * Extracts file without salt.
     */
    private void extractFileWithoutSalt(File sourceFile, File targetFile, int saltLength) throws IOException {
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

    /**
     * Creates unique filename.
     */
    private File createUniqueFileName(File dir, String fileName) {
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
     * Creates unique folder name.
     */
    private File createUniqueFolderName(File parentDir, String folderName) {
        int counter = 1;
        File newFolder;
        do {
            newFolder = new File(parentDir, folderName + "_" + counter);
            counter++;
        } while (newFolder.exists());

        return newFolder;
    }

    /**
     * Generates random filename.
     */
    private String generateRandomFileName() {
        SecureRandom random = new SecureRandom();
        StringBuilder name = new StringBuilder("enc_");
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";

        for (int i = 0; i < 12; i++) {
            name.append(chars.charAt(random.nextInt(chars.length())));
        }

        return name.toString();
    }

    /**
     * Generates random key.
     */
    private String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        StringBuilder key = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";

        for (int i = 0; i < 24; i++) {
            key.append(chars.charAt(random.nextInt(chars.length())));
        }

        return key.toString();
    }

    /**
     * Generates random ID.
     */
    private String generateRandomId() {
        SecureRandom random = new SecureRandom();
        StringBuilder id = new StringBuilder();
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";

        for (int i = 0; i < 8; i++) {
            id.append(chars.charAt(random.nextInt(chars.length())));
        }

        return id.toString();
    }

    /**
     * Deletes directory recursively.
     */
    private void deleteDirectory(File dir) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDirectory(file);
                } else {
                    file.delete();
                }
            }
        }
        dir.delete();
    }

    /**
     * Logs message to the log area.
     */
    private void logMessage(String message) {
        Platform.runLater(() -> {
            logArea.appendText(message + "\n");
            logArea.setScrollTop(Double.MAX_VALUE);
        });
    }

    /**
     * Toggles theme between light and dark.
     */
    private void toggleTheme(Button themeButton) {
        if (currentTheme.equals("light")) {
            currentTheme = "dark";
            themeButton.setText("☀️ Light Mode");
        } else {
            currentTheme = "light";
            themeButton.setText("🌙 Dark Mode");
        }
        applyTheme();
    }

    /**
     * Applies the current theme CSS.
     */
    private void applyTheme() {

        // Apply theme class to root
        if (currentTheme.equals("dark")) {
            mainScene.getRoot().getStyleClass().add("dark-theme");
        } else {
            mainScene.getRoot().getStyleClass().remove("dark-theme");
        }
    }

    /**
     * Shows error alert.
     */
    private void showError(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    /**
     * Shows info alert.
     */
    private void showInfo(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    /**
     * Copies text to clipboard.
     */
    private void copyToClipboard(String text) {
        if (text == null || text.isEmpty()) {
            showError("Copy Failed", "No text to copy!");
            return;
        }

        javafx.scene.input.Clipboard clipboard = javafx.scene.input.Clipboard.getSystemClipboard();
        javafx.scene.input.ClipboardContent content = new javafx.scene.input.ClipboardContent();
        content.putString(text);
        clipboard.setContent(content);

        logMessage("Key copied to clipboard!");
        showInfo("Copied", "Key copied to clipboard!");
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

    public static void main(String[] args) {
        launch(args);
    }
}