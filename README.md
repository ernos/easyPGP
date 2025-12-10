# EasyPGP - Simple Android PGP Encryption App

A user-friendly Android application for PGP (Pretty Good Privacy) encryption and decryption. Generate your own PGP keys, import others' public keys, and securely encrypt/decrypt messages with an intuitive interface.

***WARNING*** This is one of my first android applications ever, just a simple show and tell. This was even before I learned about the Compose multiverse so it uses the old style XML layouts. I'm keeping this up there just if people can use it to learn something from it, but dont expect me to update it. It is what is is.

## Features

### 🔐 **PGP Key Management**
- **Generate PGP Keys**: Create your own 2048-bit RSA key pair with password protection
- **Export Public Key**: Share your public key with others via clipboard
- **Import Public Keys**: Add friends' and contacts' public keys with custom names
- **Key Storage**: Securely store encrypted private keys and manage imported public keys

### 🔒 **Encryption & Decryption**
- **Text Encryption**: Encrypt messages for yourself or imported contacts
- **Text Decryption**: Decrypt messages sent to you using your private key
- **Recipient Selection**: Choose encryption target from dropdown list of imported keys
- **Clean Output**: View encrypted/decrypted text without unnecessary prefixes

### 🚀 **User Experience**
- **Password Dialogs**: Secure password prompts for key generation and decryption
- **Auto-Copy**: Automatically copies results to clipboard after operations
- **Tap-to-Copy**: Tap output area to manually copy content
- **Keyboard Management**: Automatically hides keyboard during operations
- **Error Handling**: Clear, helpful error messages for troubleshooting

## Screenshots

*Screenshots would go here showing the main interface, settings screen, and key management*

## Installation

### Requirements
- Android 7.0 (API level 24) or higher
- 50MB free storage space

### Installation Steps
1. Download the APK from the releases section
2. Enable "Install from unknown sources" in Android settings
3. Install the APK file
4. Launch EasyPGP and start encrypting!

## Quick Start Guide

### 1. Generate Your Keys
1. Open the app and tap **Settings**
2. Tap **Generate PGP Keys**
3. Enter a strong password when prompted
4. Wait for key generation to complete

### 2. Share Your Public Key
1. In Settings, tap **Export My Public Key**
2. Your public key is copied to clipboard
3. Share it with friends via email, messaging apps, etc.

### 3. Import Friends' Keys
1. In Settings, scroll to "Import Public Keys"
2. Enter a name for the contact (e.g., "John Doe")
3. Paste their public key in the text area
4. Tap **Import Public Key**

### 4. Encrypt Messages
1. Return to the main screen
2. Select recipient from the dropdown
3. Type your message
4. Tap **Encrypt**
5. Share the encrypted output

### 5. Decrypt Messages
1. Paste encrypted message in the input area
2. Tap **Decrypt**
3. Enter your password when prompted
4. View the decrypted message

## Security Features

- **RSA 2048-bit Keys**: Industry-standard key length for strong security
- **AES-256 Encryption**: Advanced encryption for message content
- **SHA-1 Checksums**: Key integrity verification
- **No Password Storage**: Passwords never saved, entered only when needed
- **Memory Security**: Private keys cleared from memory after use

## Technical Details

### Encryption Standards
- **Algorithm**: RSA with 2048-bit keys
- **Symmetric Cipher**: AES-256
- **Compression**: ZIP compression before encryption
- **Armor Format**: ASCII-armored PGP messages

### Dependencies
- **BouncyCastle**: Cryptographic library for PGP operations
- **Kotlin Coroutines**: Async operations for smooth UI
- **Android RecyclerView**: Key management interface
- **Gson**: JSON serialization for key storage

### Key Storage
- Private keys stored encrypted with user password
- Public keys stored in app preferences as JSON
- No sensitive data stored in plain text
- Keys persist between app sessions

## Troubleshooting

### Common Issues

**"Key generation failed: only SHA1 keys supported for checksums"**
- This is normal - the app uses SHA-1 for key checksums (industry standard)
- Key generation should complete successfully

**"Decryption block error - wrong key or corrupted data"**
- Message wasn't encrypted for your key
- Try with the correct encrypted message
- Verify the message wasn't corrupted during copy/paste

**"Incorrect password - checksum mismatch"**
- Wrong password entered for your private key
- Re-enter the password you used during key generation

**"Message was not encrypted for your key - cannot decrypt"**
- The message was encrypted for someone else's public key
- You can only decrypt messages encrypted specifically for you

### Getting Help
- Check error messages for specific guidance
- Ensure PGP messages start with "-----BEGIN PGP MESSAGE-----"
- Verify public keys start with "-----BEGIN PGP PUBLIC KEY BLOCK-----"

## Privacy & Security

### What We Store
- Your encrypted private key (password-protected)
- Imported public keys with names
- App preferences and settings

### What We Don't Store
- Your passwords (entered fresh each time)
- Decrypted message content
- Private keys in plain text
- Any personal information

### Best Practices
- Use strong, unique passwords for your keys
- Keep your private key password secure
- Regularly backup your public key
- Verify public keys with contacts through secure channels

## Development

### Building from Source
```bash
git clone <repository-url>
cd EasyPGP
./gradlew assembleDebug
```

### Dependencies
- Android SDK 24+
- Kotlin 1.9+
- BouncyCastle PGP libraries
- AndroidX libraries

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Changelog

### Version 1.0
- Initial release
- PGP key generation and management
- Text encryption and decryption
- Public key import/export
- Password-protected operations
- Auto-copy functionality

## Support

For bug reports, feature requests, or questions:
- Open an issue on GitHub
- Provide detailed error messages
- Include Android version and device info

---

**EasyPGP** - Making PGP encryption accessible for everyone 🔐
