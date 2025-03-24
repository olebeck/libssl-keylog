#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/io/stat.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/net/net.h>
#include <stdbool.h>

#include "util.h"
#include "inject.h"
#include "patch.h"
#include "tai.h"

#include "http-rewrite.h"
#include "xmpp-rewrite.h"

#include "config.h"

#include "patch_funcs.c"

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args) {
    patch_init();
    add_patch_func(tls_no_verify_patch_func);
    add_patch_func(np_matching2_port_patch);

    http_rewrite_init(replacements, ARRAY_LEN(replacements));
    xmpp_rewrite_init(xmpp_replacement, 5223);

    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
    patch_release();
    http_rewrite_release();
    xmpp_rewrite_release();
}


