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

static bool with_net_log = false;
static SceUID net_log_socket = -1;
static bool net_log_need_connect = true;
static SceNetSockaddrIn keylog_target_addr;
static uint64_t account_id;

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
    int len = snprintf(out_buf, 256, "CLIENT_RANDOM %s %s\n", client_random_hex, master_key_hex);

    ksceKernelPrintf(out_buf);
    if(keylog_file > 0) {
        ksceIoWrite(keylog_file, out_buf, len);
    }

    if(with_net_log) {
        if(net_log_need_connect) {
            if(net_log_socket > 0) {
                ksceNetSocketClose(net_log_socket);
                net_log_socket = -1;
            }
            net_log_socket = ksceNetSocket("keylog_net_sender", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
            if(net_log_socket < 0) {
                ksceKernelPrintf("failed to create socket 0x%08x\n", net_log_socket);
            }
            ksceKernelPrintf("ssl_keylog_net: connecting\n");
            int ret = ksceNetConnect(net_log_socket, (SceNetSockaddr*)&keylog_target_addr, sizeof(keylog_target_addr));
            if(ret < 0) {
                ksceKernelPrintf("failed to connect to keylog server 0x%08x\n", ret);
            } else {
                uint64_t header[2];
                header[0] = 0x676c79656b736c74; // tlskeylg
                header[1] = account_id;
                ret = ksceNetSend(net_log_socket, &header, sizeof(header), 0);
                if(ret < 0) {
                    ksceKernelPrintf("failed to send keylog header 0x%08x\n", ret);
                } else {
                    net_log_need_connect = false;
                }
            }
        }
        if(!net_log_need_connect) {
            int ret = ksceNetSend(net_log_socket, out_buf, len, 0);
            if(ret < 0) {
                ksceKernelPrintf("failed to write to keylog server 0x%08x\n", ret);
                net_log_need_connect = true;
            }
        }
    }
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


void tls_keylog_init(SceNetSockaddrIn* keylog_addr, uint64_t _account_id) {
    if(keylog_addr != NULL) {
        keylog_target_addr = *keylog_addr;
        with_net_log = true;
    }
    account_id = _account_id;

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
