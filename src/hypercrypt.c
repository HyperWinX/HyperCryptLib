#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hypercrypt.h>

errcode_t _allocate_and_move(void* buf, uint64_t size, void** newptr){
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

errcode_t _allocate_cipher(void** buf, uint64_t size){
    void* ptr = calloc(size, sizeof(char));
    if (!ptr) return ALLOCFAILURE;
    else {*buf = ptr; return NOERR;}
}

uint64_t _rotate_left(uint64_t n, int d){
    return (n << d) | (n >> ((sizeof(uint64_t) * 8) - d));
}

uint64_t _rotate_right(uint64_t n, int d){
    return (n >> d) | (n << ((sizeof(uint64_t) * 8) - d));
}

void _process_block_encrypt(unsigned char* block, unsigned char* key){
    /* Stage 1: XOR block with key */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    /* Stage 2: Rotate block halves */
    *(uint64_t*)(block) = _rotate_left(*(uint64_t*)(block), ROTATENUM);
    *(uint64_t*)(block + 8) = _rotate_left(*(uint64_t*)(block + 8), ROTATENUM);

    /* Stage 3: Add key bytes to block bytes */
    for (int i = 0; i < BLOCKSIZE; ++i)
        block[i] += key[i];

    /* Stage 4: Rotate again */
    *(uint64_t*)(block) = _rotate_left(*(uint64_t*)(block), ROTATENUM);
    *(uint64_t*)(block + 8) = _rotate_left(*(uint64_t*)(block + 8), ROTATENUM);

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
}

void _process_block_decrypt(unsigned char* block, unsigned char* key){
    /* Stage 1: XOR block with key */
    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    for (int i = 0; i < BLOCKSIZE; ++i)
        block[i] += key[i];

    *(uint64_t*)(block) = ~(*(uint64_t*)(block));
    *(uint64_t*)(block + 8) = ~(*(uint64_t*)(block + 8));

    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);

    *(uint64_t*)(block) = _rotate_right(*(uint64_t*)(block), ROTATENUM);
    *(uint64_t*)(block + 8) = _rotate_right(*(uint64_t*)(block + 8), ROTATENUM);

    for (int i = 0; i < BLOCKSIZE; ++i)
        block[i] -= key[i];

    *(uint64_t*)(block) = _rotate_right(*(uint64_t*)(block), ROTATENUM);
    *(uint64_t*)(block + 8) = _rotate_right(*(uint64_t*)(block + 8), ROTATENUM);

    *(uint64_t*)(block) ^= *(uint64_t*)(key);
    *(uint64_t*)(block + 8) ^= *(uint64_t*)(key + 8);
}

errcode_t encrypt(void* userbuf, uint64_t size, void* key, void** target, int flags){
    unsigned char* buf                           = userbuf;
    unsigned char* cipher                        = 0;
    uint64_t actual_size                = size + (16 - (size % 16));
    uint32_t iterations_to_process      = actual_size / 16;

    /* Parse flags */
    if (flags & REQUIREDCIPHERALLOC) _allocate_cipher(target, actual_size);
    cipher = *target;

    /* Clear cipher buffer, and copy buf to there */
    memset(cipher, 0, actual_size);
    memcpy(cipher, buf, size);

    /* Main cycle */
    for (int i = 0; i < STEPCOUNT; ++i){
        for (uint32_t j = 0; j < iterations_to_process; ++j)
            /* Calculate offset and process block */
            _process_block_encrypt(cipher + (BLOCKSIZE * j), key);
    }

    return NOERR;
}

errcode_t decrypt(void* userbuf, uint64_t size, void* key, void* target){
    unsigned char* buf                  = userbuf;
    uint32_t iterations_to_process      = size / 16;

    memcpy(target, userbuf, size);

    /* Main cycle */
    for (int i = 0; i < STEPCOUNT; ++i){
        for (uint32_t j = 0; j < iterations_to_process; ++j)
            /* Calculate offset and process block */
            _process_block_decrypt(target + (BLOCKSIZE * j), key);
    }

    return NOERR;
}