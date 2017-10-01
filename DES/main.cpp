#include <bitset>
#include "des.h"
#include <iostream>
#include <string>
#include <fstream>

using std::bitset;
using std::ifstream;
using std::ofstream;
using std::ios;
using std::cerr;
using std::cout;
using std::endl;
using std::string;

bool encrypt_file(const string& plain_path, const string& cipher_path, const bitset<64>& key);
bool decrypt_file(const string& cipher_path, const string& decipher_path, const bitset<64>& key);

int main() {
    string k("1111111111111111111111111111111111111111111111111111111111111111");
    bitset<64> key(k);

    if (encrypt_file("Test-Files/plain.txt", "Test-Files/cipher.txt", key)) {
        cout << "Encrypt success!" << endl;
    } else {
        cout << "Encrypt failed!" << endl;
        return 0;
    }

    if (decrypt_file("Test-Files/cipher.txt", "Test-Files/decipher.txt", key)) {
        cout << "Decrypt success!" << endl;
    } else {
        cout << "Decrypt failed!" << endl;
    }

    return 0;
}

bool encrypt_file(const string& plain_path,
                  const string& cipher_path, const bitset<64>& key) {
    ifstream fin;
    ofstream fout;

    //读取 plain.txt 的信息，加密到 cipher.txt
    fin.open(plain_path, ios::binary);
    fout.open(cipher_path, ios::binary);

    if (!fin || !fout) {
        cerr << "Files open failed!" << endl;
        return false;
    }

    bitset<64> info;
    while (fin.read((char*)&info, sizeof(info))) {
        std::bitset<64> cipher  = encrypt(info, key);  
        fout.write((char*)&cipher, sizeof(cipher));  
        info.reset();
    }

    fin.close();
    fout.close();
    return true;
}

bool decrypt_file(const string& cipher_path, 
                  const string& decipher_path, const bitset<64>& key) {
    ifstream fin;
    ofstream fout;
    //读取 cipher.txt 的信息，解密到 decipher.txt
    fin.open(cipher_path, ios::binary);
    fout.open(decipher_path, ios::binary);
    if (!fin || !fout) {
        cerr << "Files open failed!" << endl;
        return false;
    }

    bitset<64> info;
    while (fin.read((char*)&info, sizeof(info))) {
        std::bitset<64> decipher  = decrypt(info, key);  
        fout.write((char*)&decipher, sizeof(decipher));  
        info.reset();
    }
    fin.close();
    fout.close();
    return true;
}