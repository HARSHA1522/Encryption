#ifndef DES_H
#define DES_H

#include <bitset>
#include <array>

//加密
std::bitset<64> encrypt(const std::bitset<64>& plaintext, const std::bitset<64>& key);

//解密
std::bitset<64> decrypt(const std::bitset<64>& ciphertext, const std::bitset<64>& key);

//1. IP 置换 64bits -> 64bits
std::bitset<64> ip_permutation(const std::bitset<64>& input);

//2. IP 逆置换 64bits -> 64bits
std::bitset<64> ip_inv_permutation(const std::bitset<64>& input);

//3. F 函数: 16轮迭代 64bits -> 64bits
std::bitset<64> F(const std::bitset<64>& input, const std::bitset<64>& key, bool decipher = false);

//3.1 子密钥生成函数 64bits -> 48bits[16]
std::array<std::bitset<48>, 16> get_sub_key(const std::bitset<64>& key);

//3.1.1 PC-1 置换 64bits -> 56bits
std::bitset<56> pc1_permutation(const std::bitset<64>& key);

//3.1.2 PC-2 置换 56bits -> 48bits
std::bitset<48> pc2_permutation(const std::bitset<56>& input);

//3.2 Feistle 函数
std::bitset<32> feistle(const std::bitset<32>& pre_R,const std::bitset<48>& sub_key);

//3.2.1 E 扩展 32bits -> 48bits
std::bitset<48> e_permutation(const std::bitset<32>& input);

//3.2.2 S-Box 48bits -> 32bits
std::bitset<32> s_box_transfer(const std::bitset<48>& input);

//3.2.3 P 置换 32bits -> 32bits
std::bitset<32> p_permutation(const std::bitset<32>& input);

#endif