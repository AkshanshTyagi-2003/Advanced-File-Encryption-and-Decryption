#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <algorithm>
#include <string>

using namespace std;

class FileSecurity {
private:
    string filename;
    string password; 
public:
    FileSecurity(const string& filename, const string& password) : filename(filename), password(password) {}

    void secureOperation() {
        // Check if the password is correct
        if (!validatePassword()) {
            cerr << "Incorrect password. Operation aborted." << endl;
            return;
        }

        try {
            ifstream originalData(filename, ios::binary);
            if (!originalData.is_open()) {
                cerr << "File with name " << filename << " is not found." << endl;
                exit(0);
            }

            vector<char> content((istreambuf_iterator<char>(originalData)), istreambuf_iterator<char>());
            originalData.close();

            int key = 192;
            string securedFileName = "protected_" + filename;
            ofstream securedFile(securedFileName, ios::binary);

            cout << "Security Process is in progress...!" << endl;

            transform(content.begin(), content.end(), content.begin(), [key](char val) { return val ^ key; });

            copy(content.begin(), content.end(), ostreambuf_iterator<char>(securedFile));
            securedFile.close();
        } catch (const exception& e) {
            cerr << "Something went wrong with " << filename << ": " << e.what() << endl;
        }
    }

    // Added function to change the password
    void changePassword(const string& newPassword) {
        // Save the new password to a file
        ofstream passwordFile("password.txt");
        passwordFile << newPassword;
        passwordFile.close();

        cout << "Password changed successfully." << endl;
    }

private:
    bool validatePassword() const {
        // Read the saved password from a file
        string savedPassword;
        ifstream passwordFile("password.txt");
        if (passwordFile.is_open()) {
            getline(passwordFile, savedPassword);
            passwordFile.close();
        } else {
            cerr << "Password file not found. Aborting." << endl;
            exit(0);
        }

        // Compare the entered password with the saved password
        return password == savedPassword;
    }
};

class DataAccess {
private:
    string filename;
    string password; // Added password member variable

public:
    DataAccess(const string& filename, const string& password) : filename(filename), password(password) {}

    void accessData() {
        // Check if the password is correct
        if (!validatePassword()) {
            cerr << "Incorrect password. Operation aborted." << endl;
            return;
        }

        try {
            ifstream securedFile(filename, ios::binary);
            if (!securedFile.is_open()) {
                cerr << "File with name " << filename << " is not found." << endl;
                exit(0);
            }

            string decryptedFileName;
            cout << "Enter the filename for the Decryption file with extension: ";
            cin >> decryptedFileName;

            ofstream decryptedFile(decryptedFileName, ios::binary);

            vector<char> cipherText((istreambuf_iterator<char>(securedFile)), istreambuf_iterator<char>());
            securedFile.close();

            int key = 192;

            cout << "Data Access Process is in progress...!" << endl;

            transform(cipherText.begin(), cipherText.end(), cipherText.begin(), [key](char val) { return val ^ key; });

            copy(cipherText.begin(), cipherText.end(), ostreambuf_iterator<char>(decryptedFile));
            decryptedFile.close();
        } catch (const exception& e) {
            cerr << "Some problem with Cipher data, unable to handle: " << e.what() << endl;
        }
    }

private:
    bool validatePassword() const {
        // Read the saved password from a file
        string savedPassword;
        ifstream passwordFile("password.txt");
        if (passwordFile.is_open()) {
            getline(passwordFile, savedPassword);
            passwordFile.close();
        } else {
            cerr << "Password file not found. Aborting." << endl;
            exit(0);
        }

        // Compare the entered password with the saved password
        return password == savedPassword;
    }
};

int main() {
    string spaceCount(30, ' ');

    cout << spaceCount << " File Security And Data Access Tool. " << spaceCount << endl;

    string password; // Added password variable

    while (true) {
        cout << "1. Secure Data" << endl;
        cout << "2. Access Data" << endl;
        cout << "3. Change Password" << endl; // Added option to change password
        cout << "4. Set Password" << endl;
        cout << "5. Exit" << endl;

        cout << "~C++: ";
        int choice;
        cin >> choice;

        if (choice == 1) {
            cout << "Security Process" << endl;
            cout << "Enter the full file path for Data Security: ";
            string file;
            cin >> file;

            cout << "Enter password: ";
            cin >> password;

            FileSecurity fs(file, password);
            fs.secureOperation();

            cout << "Do you want to do it again (y/n): ";
            char againChoice;
            cin >> againChoice;

            if (tolower(againChoice) == 'y') {
                continue;
            } else {
                break;
            }
        } else if (choice == 2) {
            cout << "Data Access Process" << endl;
            cout << "Enter the full file path for Data Access: ";
            string file;
            cin >> file;

            cout << "Enter password: ";
            cin >> password;

            DataAccess da(file, password);
            da.accessData();

            cout << file << " Data Access is done Successfully...!" << endl;

            cout << "Do you want to do it again (y/n): ";
            char againChoice;
            cin >> againChoice;

            if (tolower(againChoice) == 'y') {
                continue;
            } else {
                break;
            }
        } else if (choice == 3) {
            // Change Password
            cout << "Enter new password: ";
            string newPassword;
            cin >> newPassword;

            FileSecurity fs("", password);
            fs.changePassword(newPassword);
        } else if (choice == 4) {
            // Set Password
            cout << "Enter new password: ";
            cin >> password;

            // Save the new password to a file
            ofstream passwordFile("password.txt");
            passwordFile << password;
            passwordFile.close();

            cout << "Password set successfully." << endl;
        } else if (choice == 5) {
            exit(0);
        } else {
            cout << "Your choice of selection is not available. Sorry to see you again." << endl;
        }
    }

    return 0;
}