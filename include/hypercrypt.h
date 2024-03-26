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
#define STEPCOUNT   10
#define BLOCKSIZE   16
#define ROTATENUM64 35
#define ROTATENUM16 8

/* Functions definitions */
errcode_t encrypt(void* restrict userbuf,
                  const uint64_t size,
                  char* restrict key,
                  void** restrict target,
                  int flags);
errcode_t decrypt(void* restrict userbuf,
                  uint64_t size,
                  void* restrict key,
                  void* restrict target);