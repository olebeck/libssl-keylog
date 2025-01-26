#include "tai.h"
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/debug.h>

#define TAI_SUCCESS 0
#define TAI_ERROR_SYSTEM 0x90010000
#define TAI_ERROR_MEMORY 0x90010001
#define TAI_ERROR_NOT_FOUND 0x90010002
#define TAI_ERROR_INVALID_ARGS 0x90010003
#define TAI_ERROR_INVALID_KERNEL_ADDR 0x90010004
#define TAI_ERROR_PATCH_EXISTS 0x90010005
#define TAI_ERROR_HOOK_ERROR 0x90010006
#define TAI_ERROR_NOT_IMPLEMENTED 0x90010007
#define TAI_ERROR_USER_MEMORY 0x90010008
#define TAI_ERROR_NOT_ALLOWED 0x90010009
#define TAI_ERROR_STUB_NOT_RESOLVED 0x9001000A
#define TAI_ERROR_INVALID_MODULE 0x9001000B
#define TAI_ERROR_MODULE_OVERFLOW 0x9001000C
#define TAI_ERROR_BLOCKING 0x9001000D

#define DEFAULT_FW_VERSION 0x3600000

#define MOD_LIST_SIZE (256)


int (*_ksceKernelGetModuleCB)(SceUID modid, void** info);
int ksceKernelGetModuleCB(SceUID modid, void** info) {
    return _ksceKernelGetModuleCB(modid, info);
}

int (*_ksceKernelGetModuleList)(SceUID pid, int flags1, int flags2, SceUID *modids, SceSize *num);
int ksceKernelGetModuleList(SceUID pid, int flags1, int flags2, SceUID *modids, SceSize *num) {
    return _ksceKernelGetModuleList(pid, flags1, flags2, modids, num);
}

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);

void tai_resolve_nid(char* module, uint32_t lib_360, uint32_t func_360, uint32_t lib_365, uint32_t func_365, void* func) {
    int ret;
    ret = module_get_export_func(KERNEL_PID, module, lib_360, func_360, func);
    if(ret < 0) {
        ret = module_get_export_func(KERNEL_PID, module, lib_365, func_365, func);
    }
    if(ret < 0) {
        ksceKernelPrintf("tai_resolve_nid %s %08x", module, ret);
    }
}

void tai_init() {
    tai_resolve_nid("SceKernelModulemgr", 0xC445FA63, 0xFE303863, 0x92C9FFC2, 0x37512E29, &_ksceKernelGetModuleCB);
    tai_resolve_nid("SceKernelModulemgr", 0xC445FA63, 0x97CF7B4E, 0x92C9FFC2, 0xB72C75A4, &_ksceKernelGetModuleList);
}


int sce_to_tai_module_info(SceUID pid, void *sceinfo, tai_module_info_t *taiinfo) {
    char *info;

    if (taiinfo->size < sizeof(tai_module_info_t)) {
        ksceKernelPrintf("Structure size too small: %d", taiinfo->size);
        return TAI_ERROR_SYSTEM;
    }

    info = (char *)sceinfo;
    if (pid == KERNEL_PID) {
        taiinfo->modid = *(SceUID *)(info + 0xC);
    } else {
        taiinfo->modid = *(SceUID *)(info + 0x10);
    }
    snprintf(taiinfo->name, 27, "%s", *(const char **)(info + 0x1C));
    taiinfo->name[26] = '\0';
    taiinfo->module_nid = *(uint32_t *)(info + 0x30);
    taiinfo->exports_start = *(uintptr_t *)(info + 0x20);
    taiinfo->exports_end = *(uintptr_t *)(info + 0x24);
    taiinfo->imports_start = *(uintptr_t *)(info + 0x28);
    taiinfo->imports_end = *(uintptr_t *)(info + 0x2C);
    return TAI_SUCCESS;
}

int get_tai_info(int pid, char* name, tai_module_info_t *info) {
    void* sceinfo;

    SceUID modlist[MOD_LIST_SIZE];
    size_t count = MOD_LIST_SIZE;

    int ret = ksceKernelGetModuleList(pid, 0x7FFFFFFF, 1, modlist, &count);
    if(ret < 0) {
        ksceKernelPrintf("ksceKernelGetModuleList: %08x\n", ret);
        return ret;
    }

    for(int i = 0; i < count; i++) {
        SceUID modid = modlist[i];
        ret = ksceKernelGetModuleCB(modid, &sceinfo);
        if(ret < 0) {
            ksceKernelPrintf("ksceKernelGetModuleCB: %08x\n", ret);
            return ret;
        }
        if ((ret = sce_to_tai_module_info(KERNEL_PID, sceinfo, info)) < 0) {
            return ret;
        }
        if(strncmp(info->name, name, 27) == 0) {
            return TAI_SUCCESS;
        }
    }
}
