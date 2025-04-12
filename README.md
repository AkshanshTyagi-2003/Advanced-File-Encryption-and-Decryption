# Advanced-File-Encryption-and-Decryption
A command-line based file encryption and decryption tool written in C++, utilizing AES-256-CBC encryption via OpenSSL. The project ensures data confidentiality, file integrity, and password-level protection, making it ideal for users and developers needing a secure file storage mechanism.
## Features
### AES-256-CBC Encryption
Implements strong symmetric encryption for file confidentiality.
### SHA-256 Password Hashing with Salt
Protects user passwords from brute-force and rainbow table attacks.
### Secure Key & IV Generation
Uses OpenSSL EVP routines to derive cryptographic key and IV from user password securely.
### File Integrity Checks
Uses SHA-256 hashing to verify file consistency and detect tampering.
### Modular Architecture
Clean separation of logic into components for hashing, encryption, decryption, and file handling.

## Technologies Used
- **C++ (C++11 and above)**
- **OpenSSL (libcrypto)**
- **Standard Template Library (STL)**
- **Terminal / Command-Line Interface**

## File Structure
secure-file-vault/ ├── main.cpp ├── encryption.cpp ├── decryption.cpp ├── hash_utils.cpp ├── crypto_utils.cpp ├── file_utils.cpp ├── Makefile └── README.md

## Security Design

- **AES-256-CBC** mode for encryption (widely trusted symmetric algorithm).
- **SHA-256 hashing with salt** for password storage and validation.
- Ensures **confidentiality**, **integrity**, and **modularity**.
- No hardcoded keys; all passwords are derived securely.

## Future Enhancements

- GUI frontend with **Qt** for cross-platform usability.
- Hybrid encryption using **RSA + AES**.
- Integration with **cloud storage** (e.g., Google Drive).
- **Audit logging** and access tracking.

---

## License

This project is licensed under the **MIT License**.  
Feel free to fork, contribute, and modify as per your needs.

---

## Contributing

Pull requests are welcome!  
For major changes, please open an issue first to discuss what you would like to change or improve.

---

## Author

**Akshansh Tyagi**  
🔗 [LinkedIn](https://www.linkedin.com/in/akshansh-tyagi-961691330)  
📧 akshansh2003@gmail.com
