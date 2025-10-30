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
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.animation.FadeTransition;
import javafx.util.Duration;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;

/**
 * MainUI - Modern JavaFX interface for Encrypto
 * Supports file/folder encryption, decryption, and self-extracting JAR creation
 */
public class MainUI extends Application {

    private Stage primaryStage;
    private boolean isDarkTheme = true;
    private TextArea logArea;
    private ProgressBar progressBar;
    private Label statusLabel;

    // Encrypt/Decrypt UI elements
    private TextField inputPathField;
    private TextField outputPathField;
    private TextField keyField;
    private RadioButton manualKeyRadio;
    private RadioButton autoKeyRadio;
    private Button executeButton;
    private String currentMode = "ENCRYPT"; // ENCRYPT, DECRYPT, EXECUTABLE

    @Override
    public void start(Stage stage) {
        primaryStage = stage;
        primaryStage.setTitle("Encrypto - File Encryption Suite");

        // Main container
        BorderPane root = new BorderPane();
        root.setId("root");

        // Header
        HBox header = createHeader();
        root.setTop(header);

        // Center content (tabs)
        TabPane tabPane = createTabPane();
        root.setCenter(tabPane);

        // Bottom status area
        VBox statusArea = createStatusArea();
        root.setBottom(statusArea);

        // Scene
        Scene scene = new Scene(root, 900, 700);

        // Load CSS - handle both IDE and compiled JAR scenarios
        try {
            String cssPath = getClass().getResource("/resources/EncryptoUI.css").toExternalForm();
            scene.getStylesheets().add(cssPath);
        } catch (Exception e) {
            System.err.println("Warning: Could not load CSS file. Using default styles.");
        }

        primaryStage.setScene(scene);
        primaryStage.setMinWidth(800);
        primaryStage.setMinHeight(600);

        applyTheme();
        primaryStage.show();

        // Fade in animation
        FadeTransition fadeIn = new FadeTransition(Duration.millis(500), root);
        fadeIn.setFromValue(0.0);
        fadeIn.setToValue(1.0);
        fadeIn.play();
    }

    /**
     * Creates the header with title and theme toggle
     */
    private HBox createHeader() {
        HBox header = new HBox(20);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(20));
        header.setId("header");

        Label title = new Label("ENCRYPTO");
        title.setFont(Font.font("Arial", FontWeight.BOLD, 28));
        title.setId("title");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        // Theme toggle
        ToggleButton themeToggle = new ToggleButton("🌙 Dark");
        themeToggle.setSelected(true);
        themeToggle.getStyleClass().add("theme-toggle");
        themeToggle.setOnAction(e -> {
            isDarkTheme = themeToggle.isSelected();
            themeToggle.setText(isDarkTheme ? "🌙 Dark" : "☀ Light");
            applyTheme();
        });

        header.getChildren().addAll(title, spacer, themeToggle);
        return header;
    }

    /**
     * Creates the main tab pane with three modes
     */
    private TabPane createTabPane() {
        TabPane tabPane = new TabPane();
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        // Encrypt Tab
        Tab encryptTab = new Tab("🔒 Encrypt");
        encryptTab.setContent(createOperationPane("ENCRYPT"));

        // Decrypt Tab
        Tab decryptTab = new Tab("🔓 Decrypt");
        decryptTab.setContent(createOperationPane("DECRYPT"));

        // Executable Tab
        Tab executableTab = new Tab("📦 Self-Extracting");
        executableTab.setContent(createOperationPane("EXECUTABLE"));

        tabPane.getTabs().addAll(encryptTab, decryptTab, executableTab);

        // Update current mode on tab change
        tabPane.getSelectionModel().selectedItemProperty().addListener((obs, oldTab, newTab) -> {
            if (newTab == encryptTab) currentMode = "ENCRYPT";
            else if (newTab == decryptTab) currentMode = "DECRYPT";
            else if (newTab == executableTab) currentMode = "EXECUTABLE";
        });

        return tabPane;
    }

    /**
     * Creates operation pane for each mode
     */
    private VBox createOperationPane(String mode) {
        VBox pane = new VBox(20);
        pane.setPadding(new Insets(30));
        pane.setAlignment(Pos.TOP_CENTER);

        // Title
        Label modeTitle = new Label(getModeTitle(mode));
        modeTitle.setFont(Font.font("Arial", FontWeight.BOLD, 20));
        modeTitle.getStyleClass().add("section-title");

        // Input file/folder
        VBox inputBox = createFileInputBox(mode);

        // Output location
        VBox outputBox = createOutputBox(mode);

        // Key configuration
        VBox keyBox = createKeyBox(mode);

        // Execute button
        Button execBtn = new Button(getExecuteButtonText(mode));
        execBtn.setPrefWidth(200);
        execBtn.setPrefHeight(50);
        execBtn.getStyleClass().add("execute-button");
        execBtn.setOnAction(e -> executeOperation(mode));

        if (mode.equals("ENCRYPT")) {
            executeButton = execBtn;
        }

        pane.getChildren().addAll(modeTitle, inputBox, outputBox, keyBox, execBtn);

        return pane;
    }

    /**
     * Creates file input box with drag-and-drop support
     */
    private VBox createFileInputBox(String mode) {
        VBox box = new VBox(10);

        Label label = new Label(mode.equals("DECRYPT") ? "Encrypted File:" : "Input File/Folder:");
        label.setFont(Font.font("Arial", FontWeight.SEMI_BOLD, 14));

        HBox inputRow = new HBox(10);
        inputRow.setAlignment(Pos.CENTER_LEFT);

        TextField pathField = new TextField();
        pathField.setPromptText("Drag & drop or click Browse...");
        pathField.setPrefWidth(500);
        pathField.getStyleClass().add("path-field");

        if (inputPathField == null) inputPathField = pathField;

        Button browseBtn = new Button("Browse");
        browseBtn.getStyleClass().add("browse-button");
        browseBtn.setOnAction(e -> browseInput(mode, pathField));

        inputRow.getChildren().addAll(pathField, browseBtn);

        // Drag and drop
        inputRow.setOnDragOver(event -> {
            if (event.getGestureSource() != inputRow && event.getDragboard().hasFiles()) {
                event.acceptTransferModes(TransferMode.COPY);
            }
            event.consume();
        });

        inputRow.setOnDragDropped(event -> {
            Dragboard db = event.getDragboard();
            if (db.hasFiles()) {
                File file = db.getFiles().get(0);
                pathField.setText(file.getAbsolutePath());
                event.setDropCompleted(true);
            }
            event.consume();
        });

        box.getChildren().addAll(label, inputRow);
        return box;
    }

    /**
     * Creates output location box
     */
    private VBox createOutputBox(String mode) {
        VBox box = new VBox(10);

        Label label = new Label("Output Directory:");
        label.setFont(Font.font("Arial", FontWeight.SEMI_BOLD, 14));

        HBox outputRow = new HBox(10);
        outputRow.setAlignment(Pos.CENTER_LEFT);

        TextField pathField = new TextField();
        pathField.setPromptText("Select output directory...");
        pathField.setPrefWidth(500);
        pathField.getStyleClass().add("path-field");

        if (outputPathField == null) outputPathField = pathField;

        Button browseBtn = new Button("Browse");
        browseBtn.getStyleClass().add("browse-button");
        browseBtn.setOnAction(e -> browseOutput(pathField));

        outputRow.getChildren().addAll(pathField, browseBtn);

        box.getChildren().addAll(label, outputRow);
        return box;
    }

    /**
     * Creates key configuration box
     */
    private VBox createKeyBox(String mode) {
        VBox box = new VBox(15);

        Label label = new Label(mode.equals("DECRYPT") ? "Decryption Key:" : "Encryption Key:");
        label.setFont(Font.font("Arial", FontWeight.SEMI_BOLD, 14));

        // Key mode selection
        HBox modeBox = new HBox(20);
        modeBox.setAlignment(Pos.CENTER_LEFT);

        ToggleGroup keyModeGroup = new ToggleGroup();

        RadioButton manual = new RadioButton("Manual Key");
        manual.setToggleGroup(keyModeGroup);
        manual.setSelected(true);

        RadioButton auto = new RadioButton("Auto-Generate");
        auto.setToggleGroup(keyModeGroup);

        if (mode.equals("DECRYPT")) {
            auto.setDisable(true);
            auto.setVisible(false);
        }

        if (manualKeyRadio == null) manualKeyRadio = manual;
        if (autoKeyRadio == null) autoKeyRadio = auto;

        modeBox.getChildren().addAll(manual, auto);

        // Key input field
        TextField keyInputField = new TextField();
        keyInputField.setPromptText("Enter password/emoji/mixed key (min 8 characters)");
        keyInputField.setPrefWidth(500);
        keyInputField.getStyleClass().add("key-field");

        if (keyField == null) keyField = keyInputField;

        keyModeGroup.selectedToggleProperty().addListener((obs, old, newVal) -> {
            keyInputField.setDisable(newVal == auto);
        });

        box.getChildren().addAll(label, modeBox, keyInputField);
        return box;
    }

    /**
     * Creates status area with log and progress
     */
    private VBox createStatusArea() {
        VBox statusArea = new VBox(10);
        statusArea.setPadding(new Insets(20));
        statusArea.setId("status-area");

        Label logLabel = new Label("Status Log:");
        logLabel.setFont(Font.font("Arial", FontWeight.BOLD, 12));

        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefHeight(150);
        logArea.setWrapText(true);
        logArea.getStyleClass().add("log-area");

        progressBar = new ProgressBar(0);
        progressBar.setPrefWidth(Double.MAX_VALUE);
        progressBar.setVisible(false);

        statusLabel = new Label("Ready");
        statusLabel.getStyleClass().add("status-label");

        statusArea.getChildren().addAll(logLabel, logArea, progressBar, statusLabel);
        return statusArea;
    }

    /**
     * Executes the operation based on mode
     */
    private void executeOperation(String mode) {
        String inputPath = inputPathField.getText().trim();
        String outputPath = outputPathField.getText().trim();
        String key = keyField.getText().trim();

        // Validation
        if (inputPath.isEmpty()) {
            showError("Input Required", "Please select an input file or folder.");
            return;
        }

        if (outputPath.isEmpty()) {
            showError("Output Required", "Please select an output directory.");
            return;
        }

        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            showError("Invalid Input", "The selected input does not exist.");
            return;
        }

        File outputDir = new File(outputPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        // Key validation
        boolean isManual = manualKeyRadio.isSelected();
        if (isManual && key.length() < 8) {
            showError("Invalid Key", "Key must be at least 8 characters long.");
            return;
        }

        // Execute in background
        Task<Void> task = createTask(mode, inputFile, outputDir, key, isManual);

        progressBar.setVisible(true);
        progressBar.progressProperty().bind(task.progressProperty());

        task.setOnSucceeded(e -> {
            progressBar.setVisible(false);
            statusLabel.setText("✓ Operation completed successfully!");
            statusLabel.setTextFill(Color.GREEN);
        });

        task.setOnFailed(e -> {
            progressBar.setVisible(false);
            Throwable error = task.getException();
            log("ERROR: " + error.getMessage());
            statusLabel.setText("✗ Operation failed");
            statusLabel.setTextFill(Color.RED);
            showError("Operation Failed", error.getMessage());
        });

        new Thread(task).start();
    }

    /**
     * Creates background task for operation
     */
    private Task<Void> createTask(String mode, File inputFile, File outputDir,
                                  String key, boolean isManual) {
        return new Task<Void>() {
            @Override
            protected Void call() throws Exception {
                updateProgress(0, 100);

                if (mode.equals("ENCRYPT")) {
                    performEncryption(inputFile, outputDir, key, isManual);
                } else if (mode.equals("DECRYPT")) {
                    performDecryption(inputFile, outputDir, key);
                } else if (mode.equals("EXECUTABLE")) {
                    performExecutableCreation(inputFile, outputDir, key, isManual);
                }

                updateProgress(100, 100);
                return null;
            }
        };
    }

    /**
     * Performs encryption
     */
    private void performEncryption(File inputFile, File outputDir, String key, boolean isManual)
            throws Exception {
        log("Starting encryption...");

        // Generate or use key
        String finalKey = isManual ? key : generateRandomKey();
        byte[] salt = KeyManager.generateRandomSalt();

        SecretKey secretKey = PBKDF2Util.generateAESKey(finalKey.toCharArray(), salt);

        log("Preparing content...");
        File tempPacked = File.createTempFile("encrypto_", ".tmp");

        if (inputFile.isDirectory()) {
            packFolder(inputFile, tempPacked);
        } else {
            packSingleFile(inputFile, tempPacked);
        }

        log("Encrypting...");
        File tempEncrypted = File.createTempFile("encrypto_enc_", ".tmp");
        Encryptor.encryptFile(tempPacked, tempEncrypted, secretKey);

        // Create final output
        String fileName = "enc_" + generateRandomId() + ".encrypted";
        File outputFile = new File(outputDir, fileName);

        prependSalt(tempEncrypted, outputFile, salt);

        tempPacked.delete();
        tempEncrypted.delete();

        log("✓ Encryption completed!");
        log("Output: " + outputFile.getAbsolutePath());

        if (!isManual) {
            log("\n*** SAVE THIS KEY ***");
            log("Key: " + finalKey);
            log("*** SAVE THIS KEY ***\n");

            Platform.runLater(() -> {
                showInfo("Auto-Generated Key",
                        "Your encryption key:\n\n" + finalKey +
                                "\n\nSave this key! Required for decryption.");
            });
        }
    }

    /**
     * Performs decryption
     */
    private void performDecryption(File encryptedFile, File outputDir, String key)
            throws Exception {
        log("Starting decryption...");

        // Extract salt
        byte[] salt = new byte[16];
        try (InputStream in = Files.newInputStream(encryptedFile.toPath())) {
            in.read(salt);
        }

        SecretKey secretKey = PBKDF2Util.generateAESKey(key.toCharArray(), salt);

        // Create temp file without salt
        File tempEncrypted = File.createTempFile("encrypto_dec_", ".tmp");
        extractWithoutSalt(encryptedFile, tempEncrypted, 16);

        log("Decrypting...");
        File tempDecrypted = File.createTempFile("encrypto_plain_", ".tmp");
        Decryptor.decryptFile(tempEncrypted, tempDecrypted, secretKey);

        // Detect type and extract
        String contentType = detectContentType(tempDecrypted);

        if ("###FOLDER###".equals(contentType)) {
            log("Unpacking folder...");
            unpackFolder(tempDecrypted, outputDir);
        } else {
            log("Extracting file...");
            unpackSingleFile(tempDecrypted, outputDir);
        }

        tempEncrypted.delete();
        tempDecrypted.delete();

        log("✓ Decryption completed!");
        log("Output: " + outputDir.getAbsolutePath());
    }

    /**
     * Performs self-extracting JAR creation
     */
    private void performExecutableCreation(File inputFile, File outputDir, String key, boolean isManual)
            throws Exception {
        log("Creating self-extracting JAR...");

        // This would normally call StubGenerator methods
        // For now, simplified version
        log("Feature in development - Use CLI for now");
        throw new Exception("Self-extracting JAR creation - use CLI version");
    }

    // Helper methods (simplified versions of Commands.java methods)

    private void packSingleFile(File file, File output) throws IOException {
        try (DataOutputStream out = new DataOutputStream(new FileOutputStream(output))) {
            out.writeUTF("###FILE###");
            out.writeUTF(file.getName());
            out.writeLong(file.lastModified());
            byte[] data = Files.readAllBytes(file.toPath());
            out.writeInt(data.length);
            out.write(data);
        }
    }

    private void packFolder(File folder, File output) throws IOException {
        try (DataOutputStream out = new DataOutputStream(new FileOutputStream(output))) {
            out.writeUTF("###FOLDER###");
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

    private void collectFiles(File root, File current, List<FileEntry> entries) {
        File[] files = current.listFiles();
        if (files == null) return;
        for (File file : files) {
            String relativePath = root.toPath().relativize(file.toPath()).toString();
            if (file.isDirectory()) {
                entries.add(new FileEntry(file, relativePath, true));
                collectFiles(root, file, entries);
            } else {
                entries.add(new FileEntry(file, relativePath, false));
            }
        }
    }

    private void prependSalt(File source, File target, byte[] salt) throws IOException {
        try (FileOutputStream out = new FileOutputStream(target)) {
            out.write(salt);
            Files.copy(source.toPath(), out);
        }
    }

    private void extractWithoutSalt(File source, File target, int saltLen) throws IOException {
        try (InputStream in = Files.newInputStream(source.toPath());
             FileOutputStream out = new FileOutputStream(target)) {
            in.skip(saltLen);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }
    }

    private String detectContentType(File file) throws IOException {
        try (DataInputStream in = new DataInputStream(new FileInputStream(file))) {
            return in.readUTF();
        }
    }

    private void unpackSingleFile(File packed, File outputDir) throws IOException {
        try (DataInputStream in = new DataInputStream(new FileInputStream(packed))) {
            in.readUTF(); // marker
            String name = in.readUTF();
            long modified = in.readLong();
            int len = in.readInt();
            byte[] data = new byte[len];
            in.readFully(data);
            File output = new File(outputDir, name);
            Files.write(output.toPath(), data);
            output.setLastModified(modified);
            log("Extracted: " + name);
        }
    }

    private void unpackFolder(File packed, File outputDir) throws IOException {
        try (DataInputStream in = new DataInputStream(new FileInputStream(packed))) {
            in.readUTF(); // marker
            String rootName = in.readUTF();
            File root = new File(outputDir, rootName);
            root.mkdirs();
            int count = in.readInt();
            for (int i = 0; i < count; i++) {
                String path = in.readUTF();
                boolean isDir = in.readBoolean();
                File target = new File(root, path);
                if (isDir) {
                    target.mkdirs();
                } else {
                    long modified = in.readLong();
                    target.getParentFile().mkdirs();
                    int len = in.readInt();
                    byte[] data = new byte[len];
                    in.readFully(data);
                    Files.write(target.toPath(), data);
                    target.setLastModified(modified);
                }
            }
            log("Extracted folder: " + rootName);
        }
    }

    private String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        StringBuilder key = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        for (int i = 0; i < 24; i++) {
            key.append(chars.charAt(random.nextInt(chars.length())));
        }
        return key.toString();
    }

    private String generateRandomId() {
        SecureRandom random = new SecureRandom();
        StringBuilder id = new StringBuilder();
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 8; i++) {
            id.append(chars.charAt(random.nextInt(chars.length())));
        }
        return id.toString();
    }

    private void browseInput(String mode, TextField field) {
        if (mode.equals("DECRYPT")) {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Select Encrypted File");
            chooser.getExtensionFilters().add(
                    new FileChooser.ExtensionFilter("Encrypted Files", "*.encrypted")
            );
            File file = chooser.showOpenDialog(primaryStage);
            if (file != null) field.setText(file.getAbsolutePath());
        } else {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select File");
            File file = fileChooser.showOpenDialog(primaryStage);
            if (file != null) {
                field.setText(file.getAbsolutePath());
                return;
            }

            DirectoryChooser dirChooser = new DirectoryChooser();
            dirChooser.setTitle("Select Folder");
            File dir = dirChooser.showDialog(primaryStage);
            if (dir != null) field.setText(dir.getAbsolutePath());
        }
    }

    private void browseOutput(TextField field) {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Select Output Directory");
        File dir = chooser.showDialog(primaryStage);
        if (dir != null) field.setText(dir.getAbsolutePath());
    }

    private void log(String message) {
        Platform.runLater(() -> {
            logArea.appendText(message + "\n");
        });
    }

    private void showError(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    private void showInfo(String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    private void applyTheme() {
        Scene scene = primaryStage.getScene();
        if (scene != null) {
            if (isDarkTheme) {
                scene.getRoot().getStyleClass().remove("light-theme");
                scene.getRoot().getStyleClass().add("dark-theme");
            } else {
                scene.getRoot().getStyleClass().remove("dark-theme");
                scene.getRoot().getStyleClass().add("light-theme");
            }
        }
    }

    private String getModeTitle(String mode) {
        switch (mode) {
            case "ENCRYPT": return "Encrypt File or Folder";
            case "DECRYPT": return "Decrypt Encrypted File";
            case "EXECUTABLE": return "Create Self-Extracting Archive";
            default: return "Operation";
        }
    }

    private String getExecuteButtonText(String mode) {
        switch (mode) {
            case "ENCRYPT": return "🔒 Encrypt Now";
            case "DECRYPT": return "🔓 Decrypt Now";
            case "EXECUTABLE": return "📦 Create Archive";
            default: return "Execute";
        }
    }

    static class FileEntry {
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