package packager;

import keys.KeyManager;
import keys.PBKDF2Util;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.jar.*;

/**
 * StubGenerator creates self-extracting JAR files.
 * The JAR embeds encrypted data and extraction logic in a single runnable file.
 */
public class StubGenerator {

    private static final String SIGNATURE = "###ENCRYPTO_SELF_EXTRACT###";
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final String FOLDER_MARKER = "###FOLDER###";
    private static final String FILE_MARKER = "###FILE###";

    public static void createExecutable(Scanner scanner) {
        System.out.println("\n=== CREATE SELF-EXTRACTING FILE ===\n");

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

            // Get output directory
            System.out.print("Enter output directory path: ");
            String outputDirPath = scanner.nextLine().trim();
            outputDirPath = removeQuotes(outputDirPath);

            File outputDir = new File(outputDirPath);
            if (!outputDir.exists()) outputDir.mkdirs();
            if (!outputDir.isDirectory()) {
                System.out.println("ERROR: Output path is not a directory.");
                return;
            }

            // Choose key input method
            System.out.println("\nChoose key input method:");
            System.out.println("  1. Enter key manually (password/emoji/mixed)");
            System.out.println("  2. Auto-generate random key");
            System.out.print("Enter choice (1 or 2): ");
            String keyChoice = scanner.nextLine().trim();

            SecretKey key;
            byte[] salt = new byte[SALT_LENGTH];
            new SecureRandom().nextBytes(salt);
            String generatedKey = null;

            if (keyChoice.equals("1")) {
                System.out.print("\nEnter your encryption key (min 8 characters): ");
                String password = scanner.nextLine();
                if (password.length() < 8) {
                    System.out.println("ERROR: Key must be at least 8 characters long.");
                    return;
                }
                char[] passwordChars = password.toCharArray();
                key = PBKDF2Util.generateAESKey(passwordChars, salt);
                KeyManager.clearPassword(passwordChars);
            } else if (keyChoice.equals("2")) {
                generatedKey = generateRandomKey();
                System.out.println("\nGenerated encryption key: " + generatedKey);
                System.out.println("IMPORTANT: Save this key! Needed for extraction.");
                char[] keyChars = generatedKey.toCharArray();
                key = PBKDF2Util.generateAESKey(keyChars, salt);
                KeyManager.clearPassword(keyChars);
            } else {
                System.out.println("ERROR: Invalid choice.");
                return;
            }

            // Pack content
            System.out.println("\nPreparing content...");
            File tempPackedFile = File.createTempFile("encrypto_pack_", ".tmp");

            if (inputFile.isDirectory()) {
                packFolder(inputFile, tempPackedFile);
            } else {
                packSingleFile(inputFile, tempPackedFile);
            }

            // Encrypt
            System.out.println("Encrypting...");
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            byte[] packedData = Files.readAllBytes(tempPackedFile.toPath());
            byte[] encryptedData = encryptData(packedData, key, iv);

            if (encryptedData == null) {
                System.out.println("ERROR: Encryption failed.");
                tempPackedFile.delete();
                return;
            }

            // Create JAR
            System.out.println("Building self-extracting archive...");
            String jarName = "SecureFile_" + generateRandomId() + ".jar";
            File outputFile = new File(outputDir, jarName);

            createSelfExtractingJar(outputFile, salt, iv, encryptedData);
            tempPackedFile.delete();

            System.out.println("\nSUCCESS: Self-extracting archive created!");
            System.out.println("Output: " + outputFile.getAbsolutePath());
            System.out.println("\nTo extract: Double-click the JAR file");

            if (generatedKey != null) {
                System.out.println("\n*** SAVE THIS KEY ***");
                System.out.println("Key: " + generatedKey);
                System.out.println("*** SAVE THIS KEY ***");
            } else {
                System.out.println("\nRemember your key! Required for extraction.");
            }

        } catch (Exception e) {
            System.out.println("ERROR: Failed to create executable - " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Creates self-extracting JAR with compiled class and encrypted data.
     */
    private static void createSelfExtractingJar(File outputFile, byte[] salt,
                                                byte[] iv, byte[] encryptedData) throws IOException {

        // First compile the extractor class
        File tempDir = Files.createTempDirectory("encrypto_build_").toFile();
        File sourceFile = new File(tempDir, "SelfExtract.java");

        // Write source code
        String sourceCode = generateExtractorSource();
        Files.write(sourceFile.toPath(), sourceCode.getBytes("UTF-8"));

        // Compile it with Java 8 compatibility
        try {
            ProcessBuilder pb = new ProcessBuilder("javac", "-source", "8", "-target", "8", sourceFile.getAbsolutePath());
            pb.directory(tempDir);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Read compilation output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int result = process.waitFor();
            if (result != 0) {
                System.out.println("Compilation output:\n" + output);
            }
        } catch (Exception e) {
            throw new IOException("Could not compile extractor. Ensure javac is in PATH: " + e.getMessage());
        }

        // Create JAR with manifest
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(java.util.jar.Attributes.Name.MAIN_CLASS, "SelfExtract");

        try (JarOutputStream jarOut = new JarOutputStream(new FileOutputStream(outputFile), manifest)) {

            // Add ALL compiled class files (including inner classes)
            File[] classFiles = tempDir.listFiles(new FilenameFilter() {
                public boolean accept(File dir, String name) {
                    return name.endsWith(".class");
                }
            });

            if (classFiles == null || classFiles.length == 0) {
                throw new IOException("Failed to compile extractor. No class files generated.");
            }

            for (File classFile : classFiles) {
                JarEntry classEntry = new JarEntry(classFile.getName());
                jarOut.putNextEntry(classEntry);
                Files.copy(classFile.toPath(), jarOut);
                jarOut.closeEntry();
            }

            // Add encrypted data
            JarEntry dataEntry = new JarEntry("encrypted.dat");
            jarOut.putNextEntry(dataEntry);
            jarOut.write(SIGNATURE.getBytes("UTF-8"));
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
     * Generates the self-extracting source code (Java 8 compatible).
     * FIXED: Uses matching PBKDF2 iteration count (210000)
     */
    private static String generateExtractorSource() {
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

    private static byte[] encryptData(byte[] data, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    private static void packSingleFile(File file, File outputFile) throws IOException {
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)));
        out.writeUTF(FILE_MARKER);
        out.writeUTF(file.getName());
        out.writeLong(file.lastModified());
        byte[] data = Files.readAllBytes(file.toPath());
        out.writeInt(data.length);
        out.write(data);
        out.close();
    }

    private static void packFolder(File folder, File outputFile) throws IOException {
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)));
        out.writeUTF(FOLDER_MARKER);
        out.writeUTF(folder.getName());
        List<FileEntry> entries = new ArrayList<FileEntry>();
        collectFiles(folder, folder, entries);
        out.writeInt(entries.size());
        for (int i = 0; i < entries.size(); i++) {
            FileEntry entry = entries.get(i);
            out.writeUTF(entry.relativePath);
            out.writeBoolean(entry.isDirectory);
            if (!entry.isDirectory) {
                out.writeLong(entry.file.lastModified());
                byte[] data = Files.readAllBytes(entry.file.toPath());
                out.writeInt(data.length);
                out.write(data);
            }
        }
        out.close();
    }

    private static void collectFiles(File rootFolder, File currentFolder, List<FileEntry> entries) throws IOException {
        File[] files = currentFolder.listFiles();
        if (files == null) return;
        for (int i = 0; i < files.length; i++) {
            File file = files[i];
            String relativePath = rootFolder.toPath().relativize(file.toPath()).toString();
            if (file.isDirectory()) {
                entries.add(new FileEntry(file, relativePath, true));
                collectFiles(rootFolder, file, entries);
            } else {
                entries.add(new FileEntry(file, relativePath, false));
            }
        }
    }

    private static String generateRandomKey() {
        SecureRandom random = new SecureRandom();
        StringBuilder key = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        for (int i = 0; i < 24; i++) {
            key.append(chars.charAt(random.nextInt(chars.length())));
        }
        return key.toString();
    }

    private static String generateRandomId() {
        SecureRandom random = new SecureRandom();
        StringBuilder id = new StringBuilder();
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 8; i++) {
            id.append(chars.charAt(random.nextInt(chars.length())));
        }
        return id.toString();
    }

    private static String removeQuotes(String path) {
        if (path == null || path.length() < 2) return path;
        if ((path.startsWith("\"") && path.endsWith("\"")) || (path.startsWith("'") && path.endsWith("'"))) {
            return path.substring(1, path.length() - 1);
        }
        return path;
    }

    private static void deleteDirectory(File dir) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (int i = 0; i < files.length; i++) {
                if (files[i].isDirectory()) {
                    deleteDirectory(files[i]);
                } else {
                    files[i].delete();
                }
            }
        }
        dir.delete();
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
}