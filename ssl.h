#include <stddef.h>
#include <assert.h>

typedef struct ssl3_ctx_st {
    char pad[0x98];
    char server_random[0x20];
    char client_random[0x20];
} ssl3_ctx_st;

typedef struct SSL_SESSION {
    char pad[0x14];
    char master_key[0x30];
} SSL_SESSION;

typedef struct SSL {
    char pad[0x54];
    ssl3_ctx_st* s3;
    char pad1[0x78];
    SSL_SESSION* session;
} SSL;

void __asserts() {
    _Static_assert(offsetof(SSL, s3) == 0x54);
    _Static_assert(offsetof(SSL, session) == 0xd0);
    _Static_assert(offsetof(ssl3_ctx_st, client_random) == 0xb8);
    _Static_assert(offsetof(SSL_SESSION, master_key) == 0x14);
}
