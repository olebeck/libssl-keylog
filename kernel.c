#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/io/fcntl.h>
#include <psp2/sysmodule.h>

#include "tai.h"
#include "inject.h"



static tai_hook_ref_t open_ref;
static SceUID open_id = -1;

static SceUID keylogFD = -1;


void print_hex(char* buf, char* out, int size) {
    for (int z = 0; z < size; z++) {
        unsigned char hi = (buf[z] >> 4) & 0xf; 
        unsigned char lo = buf[z] & 0xf;        
        *out++ = hi + (hi < 10 ? '0' : 'a' - 10);
        *out++ = lo + (lo < 10 ? '0' : 'a' - 10);
    }
    *out++ = 0;
}

typedef int (*PatchGet)(const char **patch, int *offset, int *patch_size, unsigned int module_nid);

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
        ksceKernelPrintf("%s: %08x\n", name, hnd);
        return;
    }
}


// this receives the client_random and master_key from the patch
SceUID hook_user_open(const char *path, int flags, SceMode mode, void *args) {
    if(path < 0x100) {
        int lib = (int)path;
        int func = flags;
        int reason = (int)mode;
        ksceKernelPrintf("SSL ERROR: %d %d %d\n", lib, func, reason);
        return 0;
    }

  if(flags > 0x81000000) { // flags is an address when called from the patch
    char client_random[0x20];
    char master_key[0x30];
    ksceKernelMemcpyFromUser(client_random, path + 0xb8, sizeof(client_random));
    ksceKernelMemcpyFromUser(master_key, (char*)flags + 0x14, sizeof(master_key));

    char buf[256];
    char client_random_hex[0x20*2+1];
    char master_key_hex[0x30*2+1];
    print_hex(client_random, client_random_hex, 0x20);
    print_hex(master_key, master_key_hex, 0x30);
    int len = snprintf(buf, 256, "CLIENT_RANDOM %s %s\n", client_random_hex, master_key_hex);

    ksceKernelPrintf(buf);
    if(keylogFD > 0) {
        ksceIoWrite(keylogFD, buf, len);
    }
  } else {
    return TAI_CONTINUE(SceUID, open_ref, path, flags, mode, args);
  }
}


static int hk = 0;
static tai_hook_ref_t lfp_hook;
// load module for pid (0 to get), running in kernel context, path is in kernel
static SceUID load_for_pid_patched(int pid, const char *path, uint32_t flags, int *ptr_to_four) {
    char* is_libssl = strstr(path, "libssl.suprx");

    int res = TAI_CONTINUE(SceUID, lfp_hook, pid, path, flags, ptr_to_four);

    if(is_libssl != NULL) {
        tai_module_info_t info;
        info.size = sizeof(tai_module_info_t);
        int ret2 = get_tai_info(pid, "SceLibSsl", &info);
        if(ret2 < 0) {
            ksceKernelPrintf("get_tai_info: %08x\n", ret2);
            return res;
        }

        ksceKernelPrintf("%s %08x %08x\n", info.name, info.module_nid, info.modid);
        apply_patch(pid, info.modid, info.module_nid, get_SSLKeylogPatch, "ssl keylog patch");
        apply_patch(pid, info.modid, info.module_nid, get_SSLPrintErrorsPatch, "ssl print errors");
        apply_patch(pid, info.modid, info.module_nid, get_SSLNoVerifyPatch, "ssl no verify");
    }

	return res;
}


void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
    int modid = ksceKernelSearchModuleByName("SceKernelModulemgr");
    if (modid > 0)
        hk = taiHookFunctionOffsetForKernel(KERNEL_PID, &lfp_hook, modid, 0, 0x21ec, 1, load_for_pid_patched);
    if (modid < 0 || hk < 0)
        return SCE_KERNEL_START_FAILED;

    // hook to get a way to talk to the kernel module from the patch
    open_id = taiHookFunctionExportForKernel(KERNEL_PID,      // Kernel process
        &open_ref,       // Output a reference
        "SceIofilemgr",  // Name of module being hooked
        TAI_ANY_LIBRARY, // If there's multiple libs exporting this
        0xCC67B6FD,      // NID specifying `sceIoOpen`
        hook_user_open
    );

    keylogFD = ksceIoOpen("ux0:data/tls-keylog.txt", SCE_O_CREAT|SCE_O_APPEND|SCE_O_WRONLY, 6);
}


int module_stop(SceSize args, void *argp) {
    if(hk > 0) {
		taiHookReleaseForKernel(hk, lfp_hook);
    }
    if(open_ref > 0) {
        taiHookReleaseForKernel(open_id, open_ref);
    }
    if(keylogFD > 0) {
        ksceIoClose(keylogFD);
    }
}
