#include <stdint.h>

/* Structs definitions */
typedef enum _errcode_t{
    REALLOCFAILURE,
    ALLOCFAILURE,
    MEMCPYFAILURE,
    NOERR
} errcode_t;

typedef enum _flags_t{
    REQUIREDCIPHERALLOC=0b00000001
} flags_t;

/* Macros to remove magic numbers */
#define STEPCOUNT 10
#define BLOCKSIZE 16
#define ROTATENUM 35

/* Functions definitions */
errcode_t encrypt(void* buf, uint64_t size, void* key, void** cipher, int flags);
errcode_t decrypt(void* buf, uint64_t size, void* key, void* target);