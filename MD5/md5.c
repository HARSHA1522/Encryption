#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "md5.h"

//API: length of hash_str at least 33 ('\0' in the end)
void md5(char *msg, char* hash_str) {
    int num_blocks = 0;
    int length = strlen(msg);
    //Padding original message
    byte* padding_msg = padding(msg, length, &num_blocks);
    
    word cv[4];
    md5_model(padding_msg, cv, num_blocks);

    //Get hash_code in cv, copy to byte array in order to transform to little-endian
    byte hash_msg[16];
    memcpy(hash_msg, cv, 16);

    //to str
    hash_code_str(hash_str, hash_msg);
}

//Step1. Padding message
byte *padding(const byte *message, int length, int *num_blocks) {
    int n = length / 64;
    if (n * 64 + 56 <= length) {
        ++n;
    }
    //Byte length need to padding
    int padding_byte_length = n * 64 + 56;
    //Byte length after adding 64-bits init-length
    int total_byte_length = (n + 1) * 64;
    *num_blocks = n + 1;

    //Save after-padding msg (free in function: md5_model) 
    byte *padding_msg = (byte *)malloc(total_byte_length);
    memset(padding_msg, 0, total_byte_length);
    memcpy(padding_msg, message, length);

    //Padding 100000... 
    padding_msg[length] = 128;
    
    //Add init-length after padding (Little-Endian)
    unsigned long long msg_bit_length = length * 8;
    memcpy(padding_msg + padding_byte_length, &msg_bit_length, 8);

    return padding_msg;
}

//Step2. Hash every blocks, after this fn, hash code is saved in cv[]
void md5_model(byte *padding_message, word *cv, int num_blocks) {
    word buffer[4] = { 0x67452301, 0xEFCDAB89,
                       0x98BADCFE, 0x10325476 };
    memcpy(cv, buffer, 16);

    //Save every blocks of message.
    word *m = (word *)malloc(64);

    //Hash every blocks
    for (int i = 0; i < num_blocks; ++i) {
        byte *begin_ptr = padding_message + (64 * i);
        memcpy(m, begin_ptr, 64);

        //md5-compress function
        H_md5(cv, m);
    }
    free(m);
    free(padding_message);
}

//2.1 Main loop
void H_md5(word *cv, word *m) {    
    /*
    * cv: 16bytes, 4 words
    * m : 64bytes, 16 words: padding-message
    */
    word a = cv[0], b = cv[1], c = cv[2], d = cv[3];
    const int s[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    for (int i = 0; i < 64; ++i) {
        word g_value;
        int k;
        if (i < 16) {
            g_value = F(b, c, d);
            k = i;
        } else if (i < 32) {
            g_value = G(b, c, d);
            k = (5 * i + 1) % 16;
        } else if (i < 48) {
            g_value = H(b, c, d);
            k = (3 * i + 5) % 16;
        } else {
            g_value = I(b, c, d);
            k = (7 * i) % 16;
        }
        word t = (word)(4294967296 * fabs(sin(i + 1)));
        a = b + left_rotate_shift(a + g_value + m[k] + t, s[i]);

        //rotate right shift a, b, c, d
        word temp = a;
        a = d;
        d = c;
        c = b;
        b = temp;
    }

    cv[0] += a;
    cv[1] += b;
    cv[2] += c;
    cv[3] += d;
}

//bit-function
word F(word b, word c, word d) {
    return (b & c) | ((~b) & d);
}

word G(word b, word c, word d) {
    return (b & d) | (c & (~d));
}

word H(word b, word c, word d) {
    return b ^ c ^ d;
}

word I(word b, word c, word d) {
    return c ^ (b | (~d));
}

word left_rotate_shift(word w, int s) {
    return (w << s) | (w >> (32 - s));
}

//Utils
void byte_to_hex(byte digit, char buffer[2]) {
    int i = 1;
    while (digit != 0) {
        char current = digit % 16;
        buffer[i--] = ((current > 9) ? (current - 10 + 'a') : (current + '0'));
        digit /= 16;
    }
    if (i == 0) {
        buffer[i] = '0';
    }
}

void hash_code_str(char *hash_str, byte hash_msg[16]) {
    char buffer[2];
    for (int i = 0; i < 16; ++i) {
        byte_to_hex(hash_msg[i], buffer);
        hash_str[2 * i] = buffer[0];
        hash_str[2 * i + 1] = buffer[1];
    }
    hash_str[32] = '\0';
}