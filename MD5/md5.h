#ifndef MD5_H
#define MD5_H

typedef unsigned char byte;
typedef unsigned int word;

// Padding
void md5(char *msg, char* hash_str);
byte *padding(const byte *message, int length, int *num_blocks);
void md5_model(byte *padding_message, word *cv, int num_blocks);
void H_md5(word *cv, word *m);

void hash_code_str(char *hash_str, byte hash_msg[16]);

word F(word b, word c, word d);
word G(word b, word c, word d);
word H(word b, word c, word d);
word I(word b, word c, word d);

word left_rotate_shift(word w, int s);
void byte_to_hex(byte digit, char buffer[2]);

#endif