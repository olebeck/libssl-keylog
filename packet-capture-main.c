#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>

#include "util.h"
#include "patch.h"
#include "tls-keylog.h"
#include "tcp-proxy.h"
extern unsigned long long account_key;

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
    patch_init();

    DEFINE_SCE_NET_SOCKADDR_IN(keylog_addr, 192,168,178,173, 1235);
    tls_keylog_init(&keylog_addr, account_key);

    DEFINE_SCE_NET_SOCKADDR_IN(proxy_addr, 192,168,178,173, 1234);
    proxy_init(&proxy_addr, account_key);

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
    patch_release();
    tls_keylog_release();
    proxy_release();
}
