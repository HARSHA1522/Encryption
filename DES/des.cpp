#include <array>
#include <bitset>
#include "des.h"

std::bitset<64> encrypt(const std::bitset<64>& plaintext, const std::bitset<64>& key) {
    std::bitset<64> ip_out = ip_permutation(plaintext);
    std::bitset<64> f_out = F(ip_out, key);
    std::bitset<64> ip_inv_out = ip_inv_permutation(f_out);

    return ip_inv_out;
}

std::bitset<64> decrypt(const std::bitset<64>& ciphertext, const std::bitset<64>& key) {
    std::bitset<64> ip_out = ip_permutation(ciphertext);
    std::bitset<64> f_decipher_out = F(ip_out, key, true);
    std::bitset<64> ip_inv_out = ip_inv_permutation(f_decipher_out);

    return ip_inv_out;
}

std::bitset<64> ip_permutation(const std::bitset<64>& input) {
    const int ip[64] = { 
        58, 50, 42, 34, 26, 18, 10, 2, 
        60, 52, 44, 36, 28, 20, 12, 4, 
        62, 54, 46, 38, 30, 22, 14, 6, 
        64, 56, 48, 40, 32, 24, 16, 8, 
        57, 49, 41, 33, 25, 17, 9, 1, 
        59, 51, 43, 35, 27, 19, 11, 3, 
        61, 53, 45, 37, 29, 21, 13, 5, 
        63, 55, 47, 39, 31, 23, 15, 7 
    };
    std::bitset<64> output;
    for (int i = 0; i < 64; ++i) {
        int pos = ip[i] - 1;
        output[i] = input[pos];
    }
    return output;
}

std::bitset<64> ip_inv_permutation(const std::bitset<64>& input) {
    const int ip_inv[64] = { 
        40, 8, 48, 16, 56, 24, 64, 32, 
        39, 7, 47, 15, 55, 23, 63, 31, 
        38, 6, 46, 14, 54, 22, 62, 30, 
        37, 5, 45, 13, 53, 21, 61, 29, 
        36, 4, 44, 12, 52, 20, 60, 28, 
        35, 3, 43, 11, 51, 19, 59, 27, 
        34, 2, 42, 10, 50, 18, 58, 26, 
        33, 1, 41, 9, 49, 17, 57, 25 
    };
    std::bitset<64> output;
    for (int i = 0; i < 64; ++i) {
        int pos = ip_inv[i] - 1;
        output[i] = input[pos];
    }
    return output;
}

std::bitset<64> F(const std::bitset<64>& input, const std::bitset<64>& key, bool decipher) {
    std::bitset<32> pre_L, pre_R;
    std::bitset<32> current_L, current_R;
    for (int i = 0; i < 32; ++i) {
        pre_L[i] = input[i];
    }
    for (int i = 0; i < 32; ++i) {
        pre_R[i] = input[i + 32];
    }
    std::array<std::bitset<48>, 16> sub_key = get_sub_key(key);

    //16 次 Feistle 迭代
    if (decipher) {
        for (int i = 15; i > -1; --i) {
            current_L = pre_R;
            current_R = pre_L ^ feistle(pre_R, sub_key[i]);

            pre_L = current_L;
            pre_R = current_R;
        }
    } else {
        for (int i = 0; i < 16; ++i) {
            current_L = pre_R;
            current_R = pre_L ^ feistle(pre_R, sub_key[i]);

            pre_L = current_L;
            pre_R = current_R;
        }
    }

    std::bitset<64> output;
    for (int i = 0; i < 32; ++i) {
        output[i] = current_R[i];
    }
    for (int i = 32; i < 64; ++i) {
        output[i] = current_L[i - 32];
    }
    return output;
}

std::array<std::bitset<48>, 16> get_sub_key(const std::bitset<64>& key) {
    std::bitset<56> pc1_out = pc1_permutation(key);
    std::bitset<28> pre_C, pre_D;
    std::bitset<28> current_C, current_D;

    for (int i = 0; i < 28; ++i) {
        pre_C[i] = pc1_out[i];
    }
    for (int i = 0; i < 28; ++i) {
        pre_D[i] = pc1_out[i + 28];
    }

    std::array<std::bitset<48>, 16> sub_key_set;
    const int shift[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 28; ++j) {
            int shift_pos = (j + shift[i]) % 28;
            current_C[j] = pre_C[shift_pos];
            current_D[j] = pre_D[shift_pos];
        }
        pre_C = current_C;
        pre_D = current_D;

        std::bitset<56> current_merge;
        for (int j = 0; j < 28; ++j) {
            current_merge[j] = current_C[j];
        }
        for (int j = 28; j < 56; ++j) {
            current_merge[j] = current_D[j - 28];
        }
        sub_key_set[i] = pc2_permutation(current_merge);
    }
    return sub_key_set;
}

std::bitset<56> pc1_permutation(const std::bitset<64>& key) {
    const int pc_1[56] = { 
        57, 49, 41, 33, 25, 17, 9, 
        1, 58, 50, 42, 34, 26, 18, 
        10, 2, 59, 51, 43, 35, 27, 
        19, 11, 3, 60, 52, 44, 36, 
        63, 55, 47, 39, 31, 23, 15, 
        7, 62, 54, 46, 38, 30, 22, 
        14, 6, 61, 53, 45, 37, 29, 
        21, 13, 5, 28, 20, 12, 4 
    };
    std::bitset<56> output;
    for (int i = 0; i < 56; ++i) {
        int pos = pc_1[i] - 1;
        output[i] = key[pos];
    }
    return output;
}

std::bitset<48> pc2_permutation(const std::bitset<56>& input) {
    const int pc_2[48] = { 
        14, 17, 11, 24, 1, 5, 
        3, 28, 15, 6, 21, 10, 
        23, 19, 12, 4, 26, 8, 
        16, 7, 27, 20, 13, 2, 
        41, 52, 31, 37, 47, 55, 
        30, 40, 51, 45, 33, 48, 
        44, 49, 39, 56, 34, 53, 
        46, 42, 50, 36, 29, 32 
    };
    std::bitset<48> output;
    for (int i = 0; i < 48; ++i) {
        int pos = pc_2[i] - 1;
        output[i] = input[pos];
    }
    return output;
}

std::bitset<32> feistle(const std::bitset<32>& pre_R, const std::bitset<48>& sub_key) {
    std::bitset<48> e_permutation_R = e_permutation(pre_R);
    std::bitset<48> s_box_in = e_permutation_R ^ sub_key;
    std::bitset<32> s_box_out = s_box_transfer(s_box_in);
    std::bitset<32> p_out = p_permutation(s_box_out);
    return p_out;
}

std::bitset<48> e_permutation(const std::bitset<32>& input) {
    const int e[48] = { 
        32, 1, 2, 3, 4, 5, 
        4, 5, 6, 7, 8, 9, 
        8, 9, 10, 11, 12, 13, 
        12, 13, 14, 15, 16, 17, 
        16, 17, 18, 19, 20, 21, 
        20, 21, 22, 23, 24, 25, 
        24, 25, 26, 27, 28, 29, 
        28, 29, 30, 31, 32, 1
    }; 
    std::bitset<48> output;
    for (int i = 0; i < 48; ++i) {
        int pos = e[i] - 1;
        output[i] = input[pos];
    }
    return output;
}

std::bitset<32> s_box_transfer(const std::bitset<48>& input) {
    const int s_box[8][4][16] = {{  
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7}, 
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, 
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0}, 
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    }, 
    {    
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, 
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, 
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, 
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}    
    }, 
    {    
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, 
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, 
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, 
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}    
    }, 
    {    
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, 
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, 
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, 
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}    
    }, 
    {    
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, 
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, 
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, 
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}    
    }, 
    {    
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, 
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, 
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, 
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}    
    }, 
    {    
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, 
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, 
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, 
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}    
    }, 
    {    
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, 
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, 
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, 
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}    
    }};

    std::array<std::bitset<6>, 8> piece_in;
    std::array<std::bitset<4>, 8> piece_out;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 6; ++j) {
            int pos = i * 6 + j;
            piece_in[i][j] = input[pos];
        }
    }

    for (int i = 0; i < 8; ++i) {
        int row = 2 * piece_in[i][0] + piece_in[i][5];
        int col = 8 * piece_in[i][1] + 4 * piece_in[i][2] + 2 * piece_in[i][3] + piece_in[i][4];
        piece_out[i] =  std::bitset<4>(s_box[i][row][col]);
    }

    std::bitset<32> output;
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            int pos = i * 6 + j;
            output[pos] = piece_out[i][j];
        }
    }
    return output;
}

std::bitset<32> p_permutation(const std::bitset<32>& input) {
    const int p[32] = { 
        16, 7, 20, 21, 
        29, 12, 28, 17, 
        1, 15, 23, 26, 
        5, 18, 31, 10, 
        2, 8, 24, 14, 
        32, 27, 3, 9, 
        19, 13, 30, 6, 
        22, 11, 4, 25
    };
    std::bitset<32> output;
    for (int i = 0; i < 32; ++i) {
        int pos = p[i] - 1;
        output[i] = input[pos];
    }
    return output;
}