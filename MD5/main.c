#include <stdio.h>
#include "md5.h"

int main() {
    char msg1[] = "Hello, world!",
         msg2[] = "abc",
         msg3[] = "Thank you";
    char hash_code[33];

    md5(msg1, hash_code);
    
    printf("Message:  %s\n", msg1);
    printf("Md5Code:  %s\n", hash_code);

    md5(msg2, hash_code);
    
    printf("Message:  %s\n", msg2);
    printf("Md5Code:  %s\n", hash_code);

    md5(msg3, hash_code);
    
    printf("Message:  %s\n", msg3);
    printf("Md5Code:  %s\n", hash_code);
    
    return 0;
}