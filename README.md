# SecureFileVault: AES-256 Encryption and Decryption Tool

SecureFileVault is a powerful and user-friendly file encryption and decryption tool built with PowerShell and Windows Forms. It provides a robust solution for protecting sensitive files using AES-256 encryption, one of the strongest encryption standards available.

![20250106_070252](https://github.com/user-attachments/assets/ca030dcb-f4b9-4d72-bdda-78da2372610e)


## Features

- **Strong Encryption**: Utilizes AES-256 encryption for maximum security.
- **File Integrity**: Implements HMAC-SHA512 for file authenticity and integrity verification.
- **Secure Key Derivation**: Uses PBKDF2 with a high iteration count for enhanced security against brute-force attacks.
- **User-Friendly GUI**: Easy-to-use graphical interface for both encryption and decryption operations.
- **Password Strength Enforcement**: Ensures users create strong passwords meeting specific criteria.
- **File Overwrite Protection**: Automatically creates uniquely named decrypted files to prevent accidental overwriting.

## Why Use SecureFileVault?

1. **Protect Sensitive Information**: Ideal for securing confidential documents, financial records, personal data, and any files you want to keep private.

2. **Easy to Use**: No complex configurations or technical knowledge required. The intuitive GUI makes encryption and decryption straightforward.

3. **Strong Security**: AES-256 encryption, coupled with secure key derivation and integrity checks, provides robust protection against unauthorized access and tampering.

4. **Local Control**: Your files are encrypted and decrypted locally on your machine, ensuring your data never leaves your control.

5. **No Internet Required**: Works completely offline, reducing the risk of network-based attacks.

6. **Cross-Platform Compatibility**: Encrypted files can be safely transferred between different computers and operating systems.

7. **Open Source**: The code is open for review, ensuring transparency and allowing for community-driven improvements and security audits.

## Getting Started

1. Clone this repository or download the script.
2. Ensure you have PowerShell installed on your Windows machine.
3. Run the script to launch the SecureFileVault application.
4. Use the 'Encryption' tab to secure your files and the 'Decryption' tab to recover them.

## Requirements

- Windows operating system
- PowerShell 5.1 or later

## Usage

1. **Encrypting a File**:
   - Select the file you want to encrypt.
   - Enter a strong password (must be at least 16 characters with a mix of uppercase, lowercase, numbers, and symbols).
   - Click 'Encrypt File'.

2. **Decrypting a File**:
   - Select the encrypted file (.encrypted extension).
   - Enter the password used for encryption.
   - Click 'Decrypt File'.

## Security Note

The security of your encrypted files depends on the strength of your password. Always use strong, unique passwords and store them securely. SecureFileVault does not store or recover your passwords.

## Contributing

Contributions to improve SecureFileVault are welcome. Please feel free to submit pull requests or open issues to suggest improvements or report bugs.

