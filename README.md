<img width="824" height="421" alt="Gemini_Generated_Image_qssgfsv341qv341qv341q" src="https://github.com/user-attachments/assets/890fcc5d-969b-47c9-b0eb-ad68899a9396" />

# 🛡️ Encrypto — File & Folder Encryption System  

**Encrypto** is a powerful Java-based encryption system designed to secure files and folders using **AES-256-GCM** encryption.  
It supports both **manual and auto-generated keys**, **emoji/mixed passwords**, and even **self-extracting encrypted JAR files** that can decrypt themselves with the correct key.

---

## ⚙️ Features  

- 🔒 **AES-256-GCM Encryption:** Secure encryption with integrity verification.  
- 🗂️ **Folder Encryption:** Encrypts entire directories while preserving structure and metadata.  
- 🧩 **Emoji / Mixed Keys:** Supports any characters — text, emojis, symbols.  
- 🔑 **Auto Key Generation:** Generates a strong random encryption key automatically.  
- 🧱 **Packed File Structure:** Encrypted output includes filenames, timestamps, and hierarchy data.  
- 🧰 **Self-Extracting JARs:** Create standalone `.jar` files that ask for the key and decrypt themselves.  
- 🚮 **Secure Delete Utility:** Built-in method for secure file shredding (used internally).  
- 🧠 **Cross-Platform:** Works seamlessly on Windows, Linux, and macOS.  
- 💬 **CLI Interface:** Modular command-line control with clean workflow.  
- 🪟 **UI Coming Soon:** JavaFX-based GUI in upcoming releases.  

---

## 🧩 Technical Details  

- **Language:** Java  
- **Build System:** Maven  
- **Encryption Algorithm:** AES-256-GCM  
- **Key Derivation:** PBKDF2WithHmacSHA256 (210,000 iterations, 128-bit salt)  
- **Libraries Used:** Only Java’s standard crypto (`javax.crypto`, `java.security`)  
- **Output Types:**  
  - `.encrypted` — Standard encrypted files/folders  
  - `.jar` — Self-extracting encrypted executables  

---

## 🚀 How to Install  

1. Clone or download this repository.  
2. Open the project in **IntelliJ IDEA** (recommended).  
3. Mark `src` as **Sources Root**.  
4. Ensure your JDK is **Java 8 or above**.  
5. Build using Maven or compile manually:  
   ```bash
   javac -d bin src/core/*.java src/keys/*.java src/cli/*.java src/packager/*.java
   ```

---

## 🧭 How to Use (CLI)

### Run from IntelliJ IDEA:
- Right-click `MainCLI.java` → **Run 'MainCLI.main()'**

### Run from CMD/Terminal:
```bash
cd "C:\path\to\Encrypto"
java -cp bin cli.MainCLI
```

---

### 🧱 Main Menu:
```
1. Encrypt file/folder
2. Decrypt file/folder
3. Create self-extracting encrypted file
4. Exit
```

#### Example (File Encryption)
```
Enter file/folder path: C:\test\data.txt
Enter output directory: C:\test\encrypted_output
Choose key mode: (1) Manual (2) Auto
Enter/Receive key → Encrypted file saved as .encrypted
```

#### Example (Decryption)
```
Enter path to .encrypted file
Enter output directory
Enter key → Decrypted file restored with original name & metadata
```

#### Example (Self-Extracting File)
```
Enter file/folder path
Enter output directory
Choose key mode → .jar file created
Run that .jar → Enter key → Auto-decrypts → Self-deletes
```

---

## 🧱 Project Structure

```
/Encrypto
 ├── src/
 │   ├── core/           → Encryptor, Decryptor, FileUtils
 │   ├── keys/           → KeyManager, PBKDF2Util, EmojiKeyUtil
 │   ├── cli/            → Commands, MainCLI
 │   └── packager/       → StubGenerator
 ├── bin/                → Compiled classes
 ├── target/             → Maven build output
 └── README.md
```

---

## 🔮 Upcoming Updates  

- 🪟 **JavaFX UI** — Interactive visual interface  
- 🧱 **Compression + Metadata Encryption Enhancements**  

---

## 📄 License  

This project is free for educational and non-commercial use.  
Feel free to fork, improve, and experiment with it responsibly.  

**© 2025 Encrypto Project**
