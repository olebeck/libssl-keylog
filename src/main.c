#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/io/fcntl.h>
#include <stdbool.h>
#include <assert.h>

#include <stai/stai.h>

#include "common.h"


static const uint32_t SceSsl_library_nid = 0xCAF5F2E9;

static offset_t ssl_tls1_setup_key_block_offsets[] = {
    { .offset = 0x12950, .needle = {0x2d, 0xe9, 0xf0, 0x47} }, // pre tls 1.2
    { .offset = 0x1453e, .needle = {0x2d, 0xe9, 0xf0, 0x47} }, // with tls 1.2
};

typedef struct ssl3_ctx_st {
    uint8_t padding1[0x98];
    char server_random[32];
    char client_random[32];
    // etc
} ssl3_ctx_st;

static_assert(offsetof(ssl3_ctx_st, client_random) == 0xb8);

typedef struct SSL_SESSION {
    int ssl_version;
    int key_arg_length;
    char key_arg[8];
    int master_key_length;
    char master_key[48];
    int session_id_length;
    char session_id[32];
    // etc
} SSL_SESSION;

static_assert(offsetof(SSL_SESSION, master_key) == 0x14);

typedef struct SSL {
    uint8_t padding1[0x54];
    ssl3_ctx_st* s3;
    uint8_t padding2[0x78];
    SSL_SESSION* session;
    // etc
} SSL;

static_assert(offsetof(SSL, s3) == 0x54);
static_assert(offsetof(SSL, session) == 0xd0);

static void write_keylog(char* buf, size_t size) {
    static SceUID keylog_fd = -1;
    if(keylog_fd < 0) {
        keylog_fd = sceIoOpen("ux0:data/keylog.txt", SCE_O_CREAT | SCE_O_APPEND | SCE_O_WRONLY, 0666);
    }
    if(keylog_fd < 0) {
        sceClibPrintf("[libssl-keylog]: open keylog: %08x\n", keylog_fd);
        return;
    }
    int ret = sceIoWrite(keylog_fd, buf, size);
    if(ret < 0) {
        sceIoClose(keylog_fd);
        keylog_fd = -1;
    }
}

STAI_HOOK(int, tls1_setup_key_block, SSL* s) {
    int ret = STAI_HOOK_CONTINUE(tls1_setup_key_block, s);

    const char prefix[] = "CLIENT_RANDOM ";
    char buf[sizeof(prefix)-1 + 32*2 + 1 + 48*2 + 1 + 1];
    sceClibMemset(buf, 0, sizeof(buf));
    char* p = buf;
    sceClibMemcpy(p, prefix, sizeof(prefix));
    p += sizeof(prefix)-1;

    tohex(p, s->s3->client_random, 32);
    p += 32*2;
    *p++ = ' ';
    tohex(p, s->session->master_key, 48);
    p += 48*2;
    *p++ = '\n';
    *p = 0;
    sceClibPrintf(buf);
    write_keylog(buf, p - buf);
    return ret;
}

STAI_HOOK(int, SceSsl_module_start, SceSize argc, void* argv) {
    stai_module_info SceSsl_module_info = {
        .size = sizeof(stai_module_info)
    };
    int ret = staiFindModuleByLibraryNid(SceSsl_library_nid, &SceSsl_module_info);
    log("staiFindModuleByLibraryNid: %08x", ret);
    if(ret < 0) {
        goto cont;
    }

    uintptr_t tls1_setup_key_block_offset;
    if(find_offset(
        ssl_tls1_setup_key_block_offsets, sizeof(ssl_tls1_setup_key_block_offsets),
        SceSsl_module_info.text_base, &tls1_setup_key_block_offset
    ) < 0) {
        log("find_offset(ssl_tls1_setup_key_block) failed");
        goto cont;
    }

    ret = staiHookOffset(
        SceSsl_module_info.module_uid,
        tls1_setup_key_block_offset, 1,
        tls1_setup_key_block_hook, &tls1_setup_key_block_hook_ref
    );
    log("staiHookOffset: %08x", ret);
cont:
    return STAI_HOOK_CONTINUE(SceSsl_module_start, argc, argv);
}

int module_start(int argc, void* argv) {
    int ret = staiHookModuleStart(SceSsl_library_nid, SceSsl_module_start_hook, &SceSsl_module_start_hook_ref);
    if(ret < 0) {
        log("staiHookModuleStart(SceSsl): 0x%08X", ret);
        return SCE_KERNEL_START_FAILED;
    }
    return SCE_KERNEL_START_SUCCESS;
}
