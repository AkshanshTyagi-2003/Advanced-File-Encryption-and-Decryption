#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <algorithm>
#include <iomanip>
#include <string>
#include <random>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>



using namespace std;

class SecurityUtils {
public:
    // Generate a random salt
    static string generateSalt() {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dist(33, 126); // Printable ASCII
        string salt;
        for (int i = 0; i < 16; ++i) {
            salt += static_cast<char>(dist(gen));
        }
        return salt;
    }

    // Hash password with salt
    static string hashPassword(const string& password, const string& salt) {
        string saltedPassword = salt + password;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(saltedPassword.c_str()), saltedPassword.length(), hash);

        stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    // Check password strength
    static bool isStrongPassword(const string& password) {
        return password.length() >= 8 &&
               any_of(password.begin(), password.end(), ::isdigit) &&
               any_of(password.begin(), password.end(), ::isupper) &&
               any_of(password.begin(), password.end(), ::islower) &&
               any_of(password.begin(), password.end(), ::ispunct);
    }

    // Generate AES key and IV
    static void generateAESKey(unsigned char* key, unsigned char* iv) {
        RAND_bytes(key, 32); // 256-bit key
        RAND_bytes(iv, 16); // 128-bit IV
    }

    // AES encryption
    static vector<unsigned char> aesEncrypt(const vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        vector<unsigned char> encrypted(data.size() + AES_BLOCK_SIZE);
        int len, ciphertext_len;

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
        EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len);
        ciphertext_len += len;

        encrypted.resize(ciphertext_len);
        EVP_CIPHER_CTX_free(ctx);
        return encrypted;
    }

    // AES decryption
    static vector<unsigned char> aesDecrypt(const vector<unsigned char>& encrypted, const unsigned char* key, const unsigned char* iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        vector<unsigned char> decrypted(encrypted.size());
        int len, plaintext_len;

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
        EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted.data(), encrypted.size());
        plaintext_len = len;
        EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
        plaintext_len += len;

        decrypted.resize(plaintext_len);
        EVP_CIPHER_CTX_free(ctx);
        return decrypted;
    }

    // File hashing
    static string calculateFileHash(const string& filename) {
        ifstream file(filename, ios::binary);
        vector<unsigned char> content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(content.data(), content.size(), hash);

        stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        return ss.str();
    }
};
class DataAccess {
private:
    string filename;
    string password;

public:
    DataAccess(const string& filename, const string& password) : filename(filename), password(password) {}

    void accessData() {
        if (!validatePassword()) {
            cerr << "Incorrect password. Access denied." << endl;
            return;
        }

        try {
            // Read key and IV from a secure storage file
            unsigned char key[32], iv[16];
            if (!readKeyAndIV(key, iv)) {
                cerr << "Failed to retrieve key and IV. Ensure the file is properly secured." << endl;
                return;
            }

            // Open encrypted file
            ifstream encryptedFile(filename, ios::binary);
            if (!encryptedFile.is_open()) {
                cerr << "Encrypted file not found: " << filename << endl;
                return;
            }

            // Read encrypted content
            vector<unsigned char> encrypted((istreambuf_iterator<char>(encryptedFile)), istreambuf_iterator<char>());
            encryptedFile.close();

            // Decrypt data
            vector<unsigned char> decrypted = SecurityUtils::aesDecrypt(encrypted, key, iv);

            // Save decrypted content to a new file
            string decryptedFileName = "decrypted_" + filename;
            ofstream decryptedFile(decryptedFileName, ios::binary);
            decryptedFile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
            decryptedFile.close();

            cout << "File decrypted and saved as " << decryptedFileName << endl;
        } catch (const exception& e) {
            cerr << "Error during data access: " << e.what() << endl;
        }
    }

private:
    bool validatePassword() const {
        string salt, savedHash;
        ifstream passwordFile("password.txt");
        if (!passwordFile.is_open() || !getline(passwordFile, salt) || !getline(passwordFile, savedHash)) {
            cerr << "Password file is missing or corrupted. Aborting." << endl;
            return false;
        }
        passwordFile.close();

        string enteredHash = SecurityUtils::hashPassword(password, salt);
        return enteredHash == savedHash;
    }

    bool readKeyAndIV(unsigned char* key, unsigned char* iv) const {
        ifstream keyFile("key_iv.txt", ios::binary);
        if (!keyFile.is_open()) {
            return false;
        }
        keyFile.read(reinterpret_cast<char*>(key), 32);
        keyFile.read(reinterpret_cast<char*>(iv), 16);
        keyFile.close();
        return true;
    }
};

    
class FileSecurity {
private:
    string filename;
    string password;

public:
    FileSecurity(const string& filename, const string& password) : filename(filename), password(password) {}

    void secureOperation() {
    if (!validatePassword()) {
        cerr << "Incorrect password. Operation aborted." << endl;
        return;
    }

    try {
        ifstream originalData(filename, ios::binary);
        if (!originalData.is_open()) {
            cerr << "File with name " << filename << " not found." << endl;
            return;
        }

        vector<unsigned char> content((istreambuf_iterator<char>(originalData)), istreambuf_iterator<char>());
        originalData.close();

        unsigned char key[32], iv[16];
        SecurityUtils::generateAESKey(key, iv);

        vector<unsigned char> encrypted = SecurityUtils::aesEncrypt(content, key, iv);

        string securedFileName = "protected_" + filename;
        ofstream securedFile(securedFileName, ios::binary);
        securedFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        securedFile.close();

        // Save key and IV securely
        ofstream keyFile("key_iv.txt", ios::binary);
        keyFile.write(reinterpret_cast<const char*>(key), 32);
        keyFile.write(reinterpret_cast<const char*>(iv), 16);
        keyFile.close();

        cout << "File secured and saved as " << securedFileName << endl;

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
    }
}

    void changePassword(const string& newPassword) {
        if (!SecurityUtils::isStrongPassword(newPassword)) {
            cerr << "Weak password. Ensure it has at least 8 characters, including digits, upper and lower case letters, and special symbols." << endl;
            return;
        }

        string salt = SecurityUtils::generateSalt();
        string hashedPassword = SecurityUtils::hashPassword(newPassword, salt);

        ofstream passwordFile("password.txt");
        passwordFile << salt << endl << hashedPassword;
        passwordFile.close();

        cout << "Password changed successfully." << endl;
    }

private:
    bool validatePassword() const {
        string salt, savedHash;
        ifstream passwordFile("password.txt");
        if (passwordFile.is_open()) {
            getline(passwordFile, salt);
            getline(passwordFile, savedHash);
            passwordFile.close();
        } else {
            cerr << "Password file not found. Aborting." << endl;
            return false;
        }

        string enteredHash = SecurityUtils::hashPassword(password, salt);
        return enteredHash == savedHash;
    }
};

// Similar updates for DataAccess class...

int main() {
    string spaceCount(30, ' ');

    cout << spaceCount << "File Security And Data Access Tool" << spaceCount << endl;

    string password;

    while (true) {
        // Display menu options
        cout << "\nMenu Options:" << endl;
        cout << "1. Secure Data" << endl;
        cout << "2. Access Data" << endl;
        cout << "3. Change Password" << endl;
        cout << "4. Set Password" << endl;
        cout << "5. Verify File Integrity" << endl;
        cout << "6. Exit" << endl;

        cout << "\nEnter your choice (1-6): ";
        int choice;
        cin >> choice;

        // Validate user input
        if (cin.fail() || choice < 1 || choice > 6) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cerr << "Invalid input. Please enter a valid option (1-6)." << endl;
            continue;
        }

        if (choice == 1) {
            // Secure Data
            cout << "\nData Security Process" << endl;
            cout << "Enter the full file path for data security: ";
            string file;
            cin >> file;

            cout << "Enter password: ";
            cin >> password;

            FileSecurity fs(file, password);
            fs.secureOperation();

        } else if (choice == 2) {
            // Access Data
            cout << "\nData Access Process" << endl;
            cout << "Enter the full file path for data access: ";
            string file;
            cin >> file;

            cout << "Enter password: ";
            cin >> password;

            DataAccess da(file, password);
            da.accessData();

        } else if (choice == 3) {
            // Change Password
            cout << "\nPassword Change Process" << endl;
            cout << "Enter your current password: ";
            cin >> password;

            cout << "Enter a new password: ";
            string newPassword;
            cin >> newPassword;

            FileSecurity fs("", password);
            fs.changePassword(newPassword);

        } else if (choice == 4) {
            // Set Password
            cout << "\nPassword Setup Process" << endl;
            cout << "Enter a new password: ";
            cin >> password;

            if (!SecurityUtils::isStrongPassword(password)) {
                cerr << "Weak password. Please ensure the password has at least 8 characters, including digits, upper and lower case letters, and special symbols." << endl;
                continue;
            }

            string salt = SecurityUtils::generateSalt();
            string hashedPassword = SecurityUtils::hashPassword(password, salt);

            ofstream passwordFile("password.txt");
            passwordFile << salt << endl << hashedPassword;
            passwordFile.close();

            cout << "Password set successfully." << endl;

        } else if (choice == 5) {
            // Verify File Integrity
            cout << "\nFile Integrity Verification Process" << endl;
            cout << "Enter the file path: ";
            string file;
            cin >> file;

            string hash = SecurityUtils::calculateFileHash(file);
            cout << "The hash of the file is: " << hash << endl;

            cout << "Do you have a previously saved hash to compare? (y/n): ";
            char compareChoice;
            cin >> compareChoice;

            if (tolower(compareChoice) == 'y') {
                cout << "Enter the previously saved hash: ";
                string savedHash;
                cin >> savedHash;

                if (hash == savedHash) {
                    cout << "File integrity verified. The file has not been tampered with." << endl;
                } else {
                    cerr << "File integrity check failed. The file may have been altered." << endl;
                }
            }
        } else if (choice == 6) {
            // Exit
            cout << "Exiting the program. Goodbye!" << endl;
            break;
        }
    }

    return 0;
}
