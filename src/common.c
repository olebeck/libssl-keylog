#include "common.h"
#include <psp2/kernel/clib.h>


int find_offset(offset_t* offsets, size_t offsets_size, uintptr_t text_base, uintptr_t* offset) {
    size_t count = offsets_size / sizeof(offset_t);
    for(size_t i = 0; i < count; i++) {
        offset_t* off = &offsets[i];
        uint8_t* ptr = (uint8_t*)(text_base + off->offset);
        bool found = true;
        for(size_t j = 0; j < sizeof(off->needle); j++) {
            if(ptr[j] != off->needle[j]) {
                found = false;
                break;
            }
        }
        if(found) {
            *offset = off->offset;
            return 0;
        }
    }
    return -1;
}

char* tohex(char* dst, char* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[i * 2 + 0] = hex[(data[i] >> 4) & 0xf];
        dst[i * 2 + 1] = hex[(data[i] >> 0) & 0xf];
    }
    return dst + len*2;
}

void* memset(void* dst, int ch, size_t len) {
    return sceClibMemset(dst, ch, len);
}
