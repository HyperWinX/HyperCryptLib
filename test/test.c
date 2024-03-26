#include <hypercrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void print_hex(const char *s)
{
    while(*s)
        printf("%02x", (unsigned int) *s++);
    printf("\n\n\n");
}

int main(){
    char str[] = "Hello guys! I'm HyperWin, and this is successfully encrypted and decrypted text.";
    uint32_t key[4] = {rand(), rand(), rand(), rand()};
    char* cipher = 0;
    char* test = calloc(96, sizeof(char));
    memset(test, 0, 96);
    encrypt(str, sizeof(str), (char*)&key, &cipher, REQUIREDCIPHERALLOC);
    decrypt(cipher, sizeof(str), key, test);
    puts(test);
    puts("\n\n");
    print_hex(cipher);
    print_hex(test);
    print_hex(str);
}