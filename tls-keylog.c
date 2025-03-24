#include <taihen.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/net/net.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "inject.h"
#include "patch.h"
#include "tai.h"

static tai_hook_ref_t open_ref;
static SceUID open_id = -1;

static SceUID keylog_file = -1;

#if NET_LOG
static SceUID keylog_socket = -1;
static bool with_net_log = false;

#define MULTICAST_IP   0x010000ef  // 239.0.0.1 in hex
#define MULTICAST_PORT 12345

#define HTONS(port) ((uint16_t)((((port) >> 8) & 0xFF) | (((port) & 0xFF) << 8))) 

static const SceNetSockaddrIn MULTICAST_ADDR = {
    .sin_len    = sizeof(SceNetSockaddrIn),
    .sin_family = SCE_NET_AF_INET,
    .sin_port   = HTONS(MULTICAST_PORT),
    .sin_addr   = { .s_addr = MULTICAST_IP }
};
#endif

void do_ssl_keylog(const char* ssl_ctx, const char* ssl_ctx_2);

// this receives the client_random and master_key from the patch
SceUID hook_user_open(const char *path, int flags, SceMode mode, void *args) {
    if((uint32_t)path < 0x100) {
        int lib = (int)path;
        int func = flags;
        int reason = (int)mode;
        ksceKernelPrintf("SSL ERROR: %d %d %d\n", lib, func, reason);
        return 0;
    }

    if(flags > 0x81000000) { // flags is an address when called from the patch
        do_ssl_keylog(path, (const char*)flags);
        return (SceUID)path;
    } else {
        return TAI_CONTINUE(SceUID, open_ref, path, flags, mode, args);
    }
}

#if NET_LOG
void send_netlog(void* data, size_t len, int retry) {
    if(retry > 3) {
        return;
    }
    if(keylog_socket < 0) { // create socket
        keylog_socket = ksceNetSocket("keylog-multicast", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
    }

    int ret = ksceNetSendto(keylog_socket, data, len, 0, (SceNetSockaddr*)&MULTICAST_ADDR, sizeof(MULTICAST_ADDR));
    if(ret < 0) {
        ksceKernelPrintf("failed to send keylog %d\n", ret);
        ksceNetClose(keylog_socket);
        keylog_socket = -1;
        send_netlog(data, len, retry+1);
    }
}
#endif

void do_ssl_keylog(const char* ssl_ctx, const char* ssl_ctx_2) {
    char client_random[0x20];
    char master_key[0x30];
    ksceKernelMemcpyFromUser(client_random, ssl_ctx + 0xb8, sizeof(client_random));
    ksceKernelMemcpyFromUser(master_key, ssl_ctx_2 + 0x14, sizeof(master_key));

    char out_buf[256];
    char client_random_hex[0x20*2+1];
    char master_key_hex[0x30*2+1];
    print_hex(client_random, client_random_hex, 0x20);
    print_hex(master_key, master_key_hex, 0x30);
    int len = snprintf(out_buf, sizeof(out_buf), "CLIENT_RANDOM %s %s\n", client_random_hex, master_key_hex);
    out_buf[len] = 0;

    ksceKernelPrintf(out_buf);
    if(keylog_file > 0) {
        ksceIoWrite(keylog_file, out_buf, len);
    }
    
    #if NET_LOG
    if(with_net_log) {
        // send twice to make it less likely to be lost
        send_netlog(out_buf, len+1, 0);
        send_netlog(out_buf, len+1, 0);
    }
    #endif
}


void tls_keylog_patch_func(int pid, const char* path) {
    if(strstr(path, "libssl.suprx") == NULL) {
        return;
    }

    tai_module_info_t ssl_info;
    ssl_info.size = sizeof(tai_module_info_t);
    int ret = get_tai_info(pid, "SceLibSsl", &ssl_info);
    if(ret < 0) {
        ksceKernelPrintf("get_tai_info SceLibSsl: %08x\n", ret);
        return;
    }

    ksceKernelPrintf("%s %08x %08x\n", ssl_info.name, ssl_info.module_nid, ssl_info.modid);
    apply_patch(pid, ssl_info.modid, ssl_info.module_nid, get_SSLKeylogPatch, "ssl keylog patch");
    apply_patch(pid, ssl_info.modid, ssl_info.module_nid, get_SSLPrintErrorsPatch, "ssl print errors");
}


void tls_keylog_init(bool with_net) {
    #if NET_LOG
    with_net_log = with_net;
    #endif
    // hook to get a way to talk to the kernel module from the patch
    open_id = taiHookFunctionExportForKernel(KERNEL_PID, &open_ref, "SceIofilemgr", TAI_ANY_LIBRARY, 0xCC67B6FD, hook_user_open);
    keylog_file = ksceIoOpen("ux0:data/tls-keylog.txt", SCE_O_CREAT|SCE_O_APPEND|SCE_O_WRONLY, 6);
    add_patch_func(tls_keylog_patch_func);
};

void tls_keylog_release() {
    if(open_id > 0) {
        taiHookReleaseForKernel(open_id, open_ref);
    }
    if(keylog_file > 0) {
        ksceIoClose(keylog_file);
    }
};
