#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/io/fcntl.h>
#include <psp2/sysmodule.h>

static tai_hook_ref_t open_ref;
static SceUID open_id = -1;

static tai_hook_ref_t sceSysmoduleLoadModule_hook_ref;
static SceUID sceSysmoduleLoadModule_hook_id = -1;

int strcmp(const char *a,const char *b){
  if (! (*a | *b)) return 0;
  return (*a!=*b) ? *a-*b : strcmp(++a,++b);
}

void print_hex(char* buf, char* out, int size) {
    for (int z = 0; z < size; z++) {
        unsigned char hi = (buf[z] >> 4) & 0xf; 
        unsigned char lo = buf[z] & 0xf;        
        *out++ = hi + (hi < 10 ? '0' : 'a' - 10);
        *out++ = lo + (lo < 10 ? '0' : 'a' - 10);
    }
    *out++ = 0;
}

void tls1_keylog_hook(int pid, int modid) {
    /*
        tls1_setup_key_block = 0x12950

        12a6c 1d 9a           ldr        r2,[sp,#__stack_chk]
        12a6e da f8 00 10     ldr.w      r1,[r10,#0x0]
        12a72 91 42           cmp        r1,r2
        12a74 02 d1           bne        LAB_81012a7c
    */

    const char patch[] = {
        0xd4, 0xf8, 0xd0, 0x10, // ldr.w r1, [r4, #0xd0] // s->session
        0x60, 0x6d, // ldr r0, [r4, #0x54] // s->s3
        0x37, 0xf0, 0x78, 0xed // blx #0x37af4 // SceIoOpen
    };

    taiInjectDataForKernel(pid, modid, 0, 0x12a6c, patch, sizeof(patch));
}


// this receives the client_random and master_key from the patch
SceUID hook_user_open(const char *path, int flags, SceMode mode, void *args) {
  if(flags > 0x81000000) { // flags is an address when called from the patch
    char client_random[0x20];
    char master_key[0x30];
    ksceKernelMemcpyFromUser(client_random, path + 0xb8, sizeof(client_random));
    ksceKernelMemcpyFromUser(master_key, (char*)flags + 0x14, sizeof(master_key));

    char client_random_hex[0x20*2+1];
    char master_key_hex[0x30*2+1];
    print_hex(client_random, client_random_hex, 0x20);
    print_hex(master_key, master_key_hex, 0x30);
    ksceKernelPrintf("CLIENT_RANDOM %s %s\n", client_random_hex, master_key_hex);
  } else {
    return TAI_CONTINUE(SceUID, open_ref, path, flags, mode, args);
  }
}


SceUID sceSysmoduleLoadModule_hook(SceSysmoduleModuleId id) {
    SceUID ret = TAI_CONTINUE(SceUID, sceSysmoduleLoadModule_hook_ref, id);
    if(id == SCE_SYSMODULE_HTTPS) {
        SceUID pid = ksceKernelGetProcessId();

        int modidssize = 50;
        SceUID modids[50];
        int ret2 = ksceKernelGetModuleList(pid, 0x7FFFFFFF, 1, modids, &modidssize);
        for(int i = 0; i < modidssize; i++) {
            SceUID modid = modids[i];
            SceKernelModuleInfo info;
            info.size = sizeof(SceKernelModuleInfo);
            ret2 = ksceKernelGetModuleInfo(pid, modid, &info);
            if(ret2 < 0) {
                ksceKernelPrintf("ksceKernelGetModuleInfo: %08x\n", ret2);
                continue;
            }

            if(strncmp(info.module_name, "SceLibSsl", 26) == 0) {
                tls1_keylog_hook(pid, modid);
            }
        }
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
}


int module_stop(SceSize args, void *argp) {
    if(sceSysmoduleLoadModule_hook_id > 0) {
        taiHookReleaseForKernel(sceSysmoduleLoadModule_hook_id, sceSysmoduleLoadModule_hook_ref);
    }
    if(open_ref > 0) {
        taiHookReleaseForKernel(open_id, open_ref);
    }
}
