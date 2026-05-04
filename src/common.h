#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define NAME "libssl-keylog"

#define log(fmt, ...) sceClibPrintf("[" NAME "] " fmt "\n", ##__VA_ARGS__)

typedef struct offset_t {
    uintptr_t offset;
    uint8_t needle[4];
} offset_t;

int find_offset(offset_t* offsets, size_t offsets_size, uintptr_t text_base, uintptr_t* offset);

void tohex(char* dst, char* data, size_t len);

void* memset(void* dst, int ch, size_t len);
