#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hypercrypt.h>

static char* _round_keys[10];

static const char _sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

errcode_t _allocate_and_move(void* buf, const uint64_t size, void** newptr){
    uint64_t mem_to_alloc = 0;

    /* Calculate memory required for algorithm. Should be easily divided into matrices 4x4 */
    if (!(size % 16)) mem_to_alloc = size;
    else mem_to_alloc = size + (16 - (size % 16));

    /* Allocate and check for valid pointer */
    void* ptr = calloc(1, sizeof(char));
    if (!ptr) return ALLOCFAILURE;

    /* Now copy all data to new buffer, and make newptr point to buffer */
    memcpy(ptr, buf, size);
    *newptr = ptr;

    return NOERR;
}

errcode_t _allocate_cipher(void** buf, const uint64_t size){
    void* ptr = calloc(size, sizeof(char));
    if (!ptr) return ALLOCFAILURE;
    else {*buf = ptr; return NOERR;}
}

uint64_t _rotate_left64(const uint64_t n, const int d){
    return (n << d) | (n >> ((sizeof(uint64_t) * 8) - d));
}

uint64_t _rotate_right64(const uint64_t n, const int d){
    return (n >> d) | (n << ((sizeof(uint64_t) * 8) - d));
}

uint64_t _rotate_left16(const uint16_t n, const int d){
    return (n << d) | (n >> ((sizeof(uint16_t) * 8) - d));
}

uint64_t _rotate_right16(const uint16_t n, const int d){
    return (n >> d) | (n << ((sizeof(uint16_t) * 8) - d));
}

void _process_block_encrypt(char* restrict block, char* restrict key){
    /* Stage 1: XOR block with key */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    /* Stage 2: Rotate block halves */
    *(uint64_t*)(block) = _rotate_left64(*(uint64_t*)(block), ROTATENUM64);
    *(uint64_t*)(block + 8) = _rotate_left64(*(uint64_t*)(block + 8), ROTATENUM64);

    /* Stage 3: Add key bytes to block bytes */
    for (int i = 0; i < BLOCKSIZE; ++i)
        block[i] += key[i];

    /* Stage 4: Rotate again */
    *(uint64_t*)(block) = _rotate_left64(*(uint64_t*)(block), ROTATENUM64);
    *(uint64_t*)(block + 8) = _rotate_left64(*(uint64_t*)(block + 8), ROTATENUM64);

    /* Stage 5: XOR again */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    /* Stage 6: Invert all bits */
    *(uint64_t*)(block) = ~(*(uint64_t*)(block));
    *(uint64_t*)(block + 8) = ~(*(uint64_t*)(block + 8));

    /* Stage 7: Subtract key bytes from block bytes */
    for (int i = 0; i < BLOCKSIZE; ++i)
        block[i] -= key[i];

    /* Stage 8: XOR again */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    /* Stage 9: Swap block halves */
    uint64_t tmp = *(uint64_t*)(block);
    *(uint64_t*)(block) = *(uint64_t*)(block + 8);
    *(uint64_t*)(block + 8) = tmp;

    /* Stage 10: Rotate 16-bit subblocks */
    for (int i = 0; i < 8; ++i)
        *(uint16_t*)(block + (i * 2)) = _rotate_left16(*(uint16_t*)(block + (i * 2)), ROTATENUM16);

    /* Stage NULL: Loop to protect algo from timing attacks */
;   for (int i = 0; i < rand() % 50; i++);
}

void _process_block_decrypt(char* restrict block, char* restrict key){
    /* Stage 1: Rotate 16-bit subblocks */
    for (int i = 0; i < 8; ++i)
        *(uint16_t*)(block + (i * 2)) = _rotate_right16(*(uint16_t*)(block + (i * 2)), ROTATENUM16);

    /* Stage 2: Swap block halves */
    uint64_t tmp = *(uint64_t*)(block);
    *(uint64_t*)(block) = *(uint64_t*)(block + 8);
    *(uint64_t*)(block + 8) = tmp;

    /* Stage 3: XOR block with key */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    /* Stage 4: Add key bytes to block bytes */
    for (int i = 0; i < BLOCKSIZE; ++i)
        block[i] += key[i];

    /* Stage 5: Invert bits */
    *(uint64_t*)(block) = ~(*(uint64_t*)(block));
    *(uint64_t*)(block + 8) = ~(*(uint64_t*)(block + 8));

    /* Stage 6: XOR again */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    /* Stage 7: Rotate block halves */
    *(uint64_t*)(block) = _rotate_right64(*(uint64_t*)(block), ROTATENUM64);
    *(uint64_t*)(block + 8) = _rotate_right64(*(uint64_t*)(block + 8), ROTATENUM64);

    /* Stage 8: Subtract key bytes from block bytes */
    for (int i = 0; i < BLOCKSIZE; ++i)
        block[i] -= key[i];

    /* Stage 9: Rotate again */
    *(uint64_t*)(block) = _rotate_right64(*(uint64_t*)(block), ROTATENUM64);
    *(uint64_t*)(block + 8) = _rotate_right64(*(uint64_t*)(block + 8), ROTATENUM64);

    /* Stage 10: XOR again */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    /* Stage NULL: Loop to protect algo from timing attacks */
    int num = 0;
    for (int i = 0; i < rand() % 50; i++) num++;
}

void _generate_round_key(char* restrict newkey, char* restrict mainkey){
    for (int i = 0; i < BLOCKSIZE; ++i)
        newkey[i] = _sbox[mainkey[i]];
}

__attribute__((visibility("default"))) errcode_t encrypt(void* restrict userbuf,
                                                         const uint64_t size,
                                                         char* restrict key,
                                                         void** restrict target,
                                                         int flags){
    char* buf                                   = userbuf;
    char* cipher                                = 0;
    uint64_t actual_size                        = size + (16 - (size % 16));
    uint32_t iterations_to_process              = actual_size >> 4;
    char round_keys[10][16];

    /* Parse flags */
    if (flags & REQUIREDCIPHERALLOC) _allocate_cipher(target, actual_size);
    cipher = *target;

    /* Clear cipher buffer, and copy buf to there */
    memset(cipher, 0, actual_size);
    memcpy(cipher, buf, size);

    /* Round keys generation */
    _generate_round_key(round_keys[0], key);
    for (int i = 1; i < 10; ++i){
        _generate_round_key(round_keys[i], round_keys[i - 1]);
        _round_keys[i] = round_keys[i];
    }

    /* Main cycle */
    for (int i = 0; i < STEPCOUNT; ++i){
        for (uint32_t j = 0; j < iterations_to_process; ++j)
            /* Calculate offset and process block */
            _process_block_encrypt(cipher + (BLOCKSIZE * j), _round_keys[i]);
    }

    return NOERR;
}

__attribute__((visibility("default"))) errcode_t decrypt(void* restrict userbuf,
                                                         uint64_t size,
                                                         void* restrict key,
                                                         void* restrict target){
    unsigned char* buf                  = userbuf;
    uint32_t iterations_to_process      = size >> 4;
    char round_keys[10][16];

    /* Copy cipher data */
    memcpy(target, userbuf, size);

    /* Round keys generation */
    _generate_round_key(round_keys[0], key);
    for (int i = 1; i < 10; ++i){
        _generate_round_key(round_keys[i], round_keys[i - 1]);
        _round_keys[i] = round_keys[i];
    }

    /* Main cycle */
    for (int i = 0; i < STEPCOUNT; ++i){
        for (uint32_t j = 0; j < iterations_to_process; ++j)
            /* Calculate offset and process block */
            _process_block_decrypt(target + (BLOCKSIZE * j), _round_keys[i]);
    }

    return NOERR;
}