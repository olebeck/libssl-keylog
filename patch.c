#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>

#include "patch.h"
#include "tai.h"

void apply_patch(int pid, int modid, int module_nid, PatchGet get_func, const char* name) {
    const char* patch;
    ptrdiff_t offset;
    int patch_size;
    int err = get_func(&patch, &offset, &patch_size, module_nid);
    if(err < 0) {
        ksceKernelPrintf("%s not found for %08x module nid\n", name, module_nid);
        return;
    }

    int hnd = taiInjectDataForKernel(pid, modid, 0, offset, patch, patch_size);
    if(hnd < 0) {
        ksceKernelPrintf("apply_patch %s: %08x\n", name, hnd);
        return;
    }
    ksceKernelPrintf("applied patch %s\n", name);
}

static int load_for_pid_id = 0;
static tai_hook_ref_t load_for_pid_ref;

#define MAX_PATCH_FUNCS 10
static PatchFunc patch_funcs[MAX_PATCH_FUNCS] = {0};

int add_patch_func(PatchFunc func) {
    for (int i = 0; i < MAX_PATCH_FUNCS; i++) {
        if (patch_funcs[i] == NULL) {
            patch_funcs[i] = func;
            return 0;
        }
    }
    return -1;
}

// load module for pid (0 to get), running in kernel context, path is in kernel
static SceUID load_for_pid_patched(int pid, const char *path, uint32_t flags, int *ptr_to_four) {
    int res = TAI_CONTINUE(SceUID, load_for_pid_ref, pid, path, flags, ptr_to_four);

    PatchFunc* patch_func = patch_funcs;
    while(*patch_func != NULL) {
        (*patch_func)(pid, path);
        patch_func++;
    }

	return res;
}

void patch_init() {
    tai_init();
    int module_mgr_modid = ksceKernelSearchModuleByName("SceKernelModulemgr");
    if (module_mgr_modid < 0) {
        ksceKernelPrintf("failed to find SceKernelModulemgr\n");
        return;
    }

    load_for_pid_id = taiHookFunctionOffsetForKernel(KERNEL_PID, &load_for_pid_ref, module_mgr_modid, 0, 0x21ec, 1, load_for_pid_patched);
    if (load_for_pid_id < 0) {
        ksceKernelPrintf("taiHookFunctionOffsetForKernel failed\n");
        return;
    }
}

void patch_release() {
    if(load_for_pid_id > 0) {
        taiHookReleaseForKernel(load_for_pid_id, load_for_pid_ref);
    }
}
