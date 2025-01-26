#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysclib.h>
#include <taihen.h>


static tai_hook_ref_t sceAppMgrReleaseBgmPort_hook_ref;
static SceUID sceAppMgrReleaseBgmPort_hook_id = -1;

typedef struct xmpp_address {
    char domain[0x40];
    unsigned short port;
    char server_name[0x40];
} xmpp_address; 

static xmpp_address replacement_xmpp = {0};


int sceAppMgrReleaseBgmPort_hook_continue() {
    return TAI_CONTINUE(int, sceAppMgrReleaseBgmPort_hook_ref);
}

__attribute__((naked)) void sceAppMgrReleaseBgmPort_hook() {
    asm(
        "cmp r7, #0x81000000\n"
        "bcs do_cpy\n"
        "b sceAppMgrReleaseBgmPort_hook_continue\n"
        "do_cpy:\n"
        "mov r0,r7\n"
        "ldr r1, =replacement_xmpp\n"
        "mov r2, #0x82\n"
        "b ksceKernelCopyToUser\n"
    );
}

void xmpp_rewrite_init(const char* domain, unsigned short port) {
    memset(&replacement_xmpp, 0, sizeof(replacement_xmpp));
    strncpy(replacement_xmpp.domain, domain, sizeof(replacement_xmpp.domain));
    strncpy(replacement_xmpp.server_name, domain, sizeof(replacement_xmpp.server_name));
    replacement_xmpp.port = port;

    sceAppMgrReleaseBgmPort_hook_id = taiHookFunctionExportForKernel(KERNEL_PID,
        &sceAppMgrReleaseBgmPort_hook_ref,
        "SceAppMgr", TAI_ANY_LIBRARY, 0xF3717E37,
        sceAppMgrReleaseBgmPort_hook
    );
    if(sceAppMgrReleaseBgmPort_hook_id < 0) {
        ksceKernelPrintf("sceAppMgrReleaseBgmPort_hook_id: %08x\n", sceAppMgrReleaseBgmPort_hook_id);
    }
};

void xmpp_rewrite_release() {
    if(sceAppMgrReleaseBgmPort_hook_id > 0) {
        taiHookReleaseForKernel(sceAppMgrReleaseBgmPort_hook_id, sceAppMgrReleaseBgmPort_hook_ref);
    }
}