#pragma once
#include <taihen.h>

void patch_init();
void patch_release();

typedef void (*PatchFunc)(int pid, const char* path);
int add_patch_func(PatchFunc func);

typedef int (*PatchGet)(const char **patch, int *offset, int *patch_size, unsigned int module_nid);
void apply_patch(int pid, int modid, int module_nid, PatchGet get_func, const char* name);
