#include <hypercrypt.h>
#include <stdlib.h>
#include <stdio.h>

int main(){
    char str[] = "Hello guys! I'm HyperWin, and this is successfully encrypted and decrypted text.";
    uint32_t key[4] = {rand(), rand(), rand(), rand()};
    char* cipher = 0;
    char* test = calloc(96, sizeof(char));
    encrypt(str, sizeof(str), &key, &cipher, REQUIREDCIPHERALLOC);
    decrypt(cipher, sizeof(str), key, test);
    puts(test);
}