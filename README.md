# Encrypto - File & Folder Encryption System

A robust Java-based file encryption system that provides AES-256-GCM encryption for files and folders with support for password-based keys, emoji keys, and self-extracting encrypted archives.

## Features

- **AES-256-GCM Encryption**: Military-grade encryption with built-in integrity verification
- **File & Folder Support**: Encrypt individual files or entire directory structures
- **Flexible Key Input**: Support for passwords, emoji sequences, and mixed-character keys
- **Auto Key Generation**: Automatically generate strong random encryption keys
- **Self-Extracting Archives**: Create standalone JAR files that decrypt themselves
- **Metadata Preservation**: Maintains original file timestamps and directory structure
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Dual Interface**: Both command-line (CLI) and graphical (JavaFX GUI) interfaces

## Technical Specifications

- **Encryption Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 210,000 iterations
- **Salt Length**: 128 bits (16 bytes)
- **IV Length**: 96 bits (12 bytes)
- **Authentication Tag**: 128 bits
- **Minimum Password Length**: 8 characters

## Requirements

- Java 8 or higher
- Maven 3.x (for building)
- `javac` in PATH (for self-extracting archive creation)

## Installation

### Clone the Repository
```bash
git clone <repository-url>
cd Encrypto
```

### Build with Maven
```bash
mvn clean install
```

### Compile Manually
```bash
javac -d bin src/core/*.java src/keys/*.java src/cli/*.java src/packager/*.java
```

## Usage

### Command Line Interface (CLI)

#### Run from IDE
Right-click `MainCLI.java` → Run 'MainCLI.main()'

#### Run from Terminal
```bash
cd path/to/Encrypto
java -cp bin cli.MainCLI
```

#### Main Menu Options
1. **Encrypt file/folder** - Encrypt files or directories
2. **Decrypt file/folder** - Decrypt encrypted files
3. **Create self-extracting encrypted file** - Generate standalone JAR archives
4. **Exit** - Close the application

### Graphical User Interface (GUI)

```bash
java -cp bin ui.MainUI
```

The GUI provides three tabs:
- **Encrypt**: Drag & drop files/folders for encryption
- **Decrypt**: Decrypt encrypted files
- **Self-Extractor**: Create self-extracting JAR files

## Encryption Workflow

### Encrypting a File
```
1. Select input file/folder
2. Choose output directory
3. Enter encryption key (or auto-generate)
4. Encrypted file saved with .encrypted extension
```

### Decrypting a File
```
1. Select encrypted .encrypted file
2. Choose output directory
3. Enter decryption key
4. Original file/folder restored with metadata
```

### Creating Self-Extracting Archive
```
1. Select input file/folder
2. Choose output directory
3. Enter encryption key (or auto-generate)
4. JAR file created that can decrypt itself
5. Double-click JAR → Enter key → Files extracted
```

## Project Structure

```
Encrypto/
├── src/
│   ├── cli/              # Command-line interface
│   │   ├── MainCLI.java
│   │   └── Commands.java
│   ├── core/             # Core encryption/decryption logic
│   │   ├── Encryptor.java
│   │   ├── Decryptor.java
│   │   └── FileUtils.java
│   ├── keys/             # Key management utilities
│   │   ├── KeyManager.java
│   │   ├── PBKDF2Util.java
│   │   └── EmojiKeyUtil.java
│   ├── packager/         # Self-extracting JAR generator
│   │   └── StubGenerator.java
│   └── ui/               # JavaFX GUI (optional)
│       └── MainUI.java
├── target/               # Maven build output
├── pom.xml              # Maven configuration
└── README.md
```

## Security Features

- **PBKDF2 Key Derivation**: 210,000 iterations to prevent brute-force attacks
- **Unique Salts**: Each encryption uses a cryptographically random salt
- **GCM Mode**: Provides both encryption and authentication
- **Secure Memory Handling**: Passwords cleared from memory after use
- **No Key Storage**: Keys are never stored, only derived from passwords

## File Format

### Encrypted File Structure
```
[16-byte Salt][12-byte IV][Encrypted Data + 16-byte Auth Tag]
```

### Packed Folder Structure
```
[Marker][Folder Name][Entry Count][Entries...]
Each Entry: [Path][IsDirectory][Timestamp][Size][Data]
```

## Examples

### Encrypt a File
```
Enter file/folder path: C:\Documents\report.pdf
Enter output directory: C:\Encrypted
Choose key mode: 1 (Manual)
Enter key: MySecurePassword123
→ Output: C:\Encrypted\enc_abc123xyz789.encrypted
```

### Decrypt a File
```
Enter path to encrypted file: C:\Encrypted\enc_abc123xyz789.encrypted
Enter output directory: C:\Decrypted
Enter key: MySecurePassword123
→ Output: C:\Decrypted\report.pdf (restored)
```

### Using Emoji Keys
```
Enter key: 🔒🐱🌟🚀💎🎨🔥🎭
(Minimum 2 emojis required)
```

## Error Handling

- **Wrong Key**: Authentication tag mismatch detected
- **Corrupted File**: Integrity verification fails
- **Invalid Format**: File structure validation errors
- **Missing Files**: Clear error messages with file paths

## Performance Considerations

- Uses streaming I/O for memory-efficient large file handling
- 8KB buffer size for optimal disk I/O
- Progress indicators for long operations (GUI)
- Background threads prevent UI freezing (GUI)

## Limitations

- Self-extracting JARs require `javac` in system PATH
- Maximum file path length: 260 characters (Windows)
- Emoji key support varies by platform keyboard
- SSD secure deletion effectiveness is limited by wear-leveling

## Contributing

Contributions are welcome! Areas for improvement:
- Additional encryption algorithms
- Cloud storage integration
- Compression before encryption
- Multi-threading for large folders

## License

This project is free for educational and non-commercial use.

## Version

**Current Version**: 1.0.0

## Author

© 2025 Encrypto Project

## Troubleshooting

### "javac not found" Error
Ensure JDK is installed and `javac` is in your system PATH.

### "Wrong key or corrupted file"
- Verify the key is exactly as entered during encryption
- Check if file was modified after encryption
- Ensure complete file transfer (no truncation)

### "Out of Memory" Error
For very large files, increase JVM heap size:
```bash
java -Xmx2G -cp bin cli.MainCLI
```

## Acknowledgments

Built using Java's standard cryptography libraries (`javax.crypto`, `java.security`).
