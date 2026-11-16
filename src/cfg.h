#ifndef CFG_H
#define CFG_H

#include <stddef.h>


typedef int (*cfg_value_parser)(void* userarg, char* value);

typedef struct {
    const char* name;
    cfg_value_parser parse;
    int required;
} cfg_key;

int cfg_load(const char* path, const cfg_key* keys, size_t key_count, void* userarg);

#endif
