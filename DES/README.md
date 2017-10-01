# Data-Encryption-Standard (DES)

**API**

```cpp
//加密文件
bool encrypt_file(const string& plain_path, const string& cipher_path, const bitset<64>& key);

//解密文件
bool decrypt_file(const string& cipher_path, const string& decipher_path, const bitset<64>& key);
```

---

**Test-Files**

* plain.txt：原始明文 
* cipher.txt：加密后的密文
* decipher.txt：解密后的明文

---

**Blog**

[DES 加密算法](https://qyb225.github.io/information-security/des)