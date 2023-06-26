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

static tai_hook_ref_t sceSysmoduleLoadModule_hook_ref;
static SceUID sceSysmoduleLoadModule_hook_id = -1;
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

void tls1_keylog_hook(int pid, int modid, int module_nid) {
    /*
        tls1_setup_key_block = 0x12950

        12a6c 1d 9a           ldr        r2,[sp,#__stack_chk]
        12a6e da f8 00 10     ldr.w      r1,[r10,#0x0]
        12a72 91 42           cmp        r1,r2
        12a74 02 d1           bne        LAB_81012a7c
    */

    const char* patch;
    ptrdiff_t offset;
    int patch_size;
    int err = get_tls_patch(&patch, &offset, &patch_size, module_nid);
    if(err < 0) {
        ksceKernelPrintf("Failed to find patch for %08x\n", module_nid);
        return;
    }

    int hnd = taiInjectDataForKernel(pid, modid, 0, offset, patch, patch_size);
    if(hnd < 0) {
        ksceKernelPrintf("tls1_keylog_patch: %08x\n", hnd);
        return;
    }
}


// this receives the client_random and master_key from the patch
SceUID hook_user_open(const char *path, int flags, SceMode mode, void *args) {
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


SceUID sceSysmoduleLoadModule_hook(SceSysmoduleModuleId id) {
    SceUID ret = TAI_CONTINUE(SceUID, sceSysmoduleLoadModule_hook_ref, id);
    if(id == SCE_SYSMODULE_HTTPS) {
        SceUID pid = ksceKernelGetProcessId();
        tai_module_info_t info;
        info.size = sizeof(tai_module_info_t);
        int ret2 = get_tai_info(pid, "SceLibSsl", &info);
        if(ret2 < 0) {
            ksceKernelPrintf("get_tai_info: %08x\n", ret2);
            return ret;
        }

        ksceKernelPrintf("%s %08x %08x\n", info.name, info.module_nid, info.modid);

        tls1_keylog_hook(pid, info.modid, info.module_nid);
    }
    return ret;
}


void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
    sceSysmoduleLoadModule_hook_id = taiHookFunctionExportForKernel(KERNEL_PID,
        &sceSysmoduleLoadModule_hook_ref,
        "SceSysmodule", 0x03FCF19D, 0x79A0160A,
        sceSysmoduleLoadModule_hook
    );

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
    if(sceSysmoduleLoadModule_hook_id > 0) {
        taiHookReleaseForKernel(sceSysmoduleLoadModule_hook_id, sceSysmoduleLoadModule_hook_ref);
    }
    if(open_ref > 0) {
        taiHookReleaseForKernel(open_id, open_ref);
    }
    if(keylogFD > 0) {
        ksceIoClose(keylogFD);
    }
}
