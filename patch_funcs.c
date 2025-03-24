#include <taihen.h>
#include <string.h>

#include "inject.h"

static void tls_no_verify_patch_func(int pid, const char* path) {
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

    apply_patch(pid, ssl_info.modid, ssl_info.module_nid, get_SSLNoVerifyPatch, "ssl no verify");
}


static void np_matching2_port_patch(int pid, const char* path) {
    if(strstr(path, "np_matching2.suprx") == NULL) {
        return;
    }
    tai_module_info_t info;
    info.size = sizeof(tai_module_info_t);
    int ret = get_tai_info(pid, "SceNpMatching2", &info);
    if(ret < 0) {
        ksceKernelPrintf("get_tai_info SceNpMatching2: %08x\n", ret);
        return;
    }
    apply_patch(pid, info.modid, info.module_nid, get_Matching2TlsPortPatch, "NpMatching2TlsPortPatch");
}
