#include "cfg.h"

#include <psp2/io/fcntl.h>
#include <psp2/kernel/clib.h>
#include <psp2/types.h>

#define CFG_BUF_SIZE 1024
#define CFG_MAX_KEYS 32

static int is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\r';
}

static char* trim(char* s) {
    while(is_whitespace(*s)) s++;
    char* end = s + sceClibStrnlen(s, 0x100);
    while(end > s && is_whitespace(end[-1])) *--end = '\0';
    return s;
}

static int read_file(const char* path, char* buf, size_t cap) {
    SceUID fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if(fd < 0) return fd;

    int size = sceIoRead(fd, buf, cap - 1);
    if(size < 0) {
        sceIoClose(fd);
        return size;
    }
    if(size == (int)(cap - 1)) {
        char extra;
        int more = sceIoRead(fd, &extra, 1);
        if(more != 0) {
            sceIoClose(fd);
        }
    }
    sceIoClose(fd);
    buf[size] = '\0';
    return size;
}

int cfg_load(const char* path, const cfg_key* keys, size_t key_count, void* userarg) {
    if(key_count > CFG_MAX_KEYS) return -1;

    char buf[CFG_BUF_SIZE];
    int size = read_file(path, buf, sizeof(buf));
    if(size < 0) return size;

    unsigned int seen = 0;
    char* line = buf;

    // Skip UTF-8 BOM
    if(size >= 3 &&
       (unsigned char)line[0] == 0xEF &&
       (unsigned char)line[1] == 0xBB &&
       (unsigned char)line[2] == 0xBF)
        line += 3;

    while(*line) {
        char* next = line;
        while(*next && *next != '\n') next++;
        if(*next) *next++ = '\0';

        // Strip comment
        for(char* c = line; *c; c++) {
            if(*c == '#') { *c = '\0'; break; }
        }

        char* key = trim(line);
        if(*key) {
            char* colon = key;
            while(*colon && *colon != ':') colon++;
            if(*colon != ':') return -1;

            *colon = '\0';
            key = trim(key);
            char* value = trim(colon + 1);
            size_t key_len = sceClibStrnlen(key, 0x100);

            for(size_t i = 0; i < key_count; i++) {
                if(key_len == sceClibStrnlen(keys[i].name, 0x100) &&
                   sceClibMemcmp(key, keys[i].name, key_len) == 0) {
                    if(keys[i].parse(userarg, value) < 0) return -1;
                    seen |= 1u << i;
                    break;
                }
            }
        }
        line = next;
    }

    for(size_t i = 0; i < key_count; i++) {
        if(keys[i].required && !(seen & (1u << i))) return -1;
    }
    return 0;
}
