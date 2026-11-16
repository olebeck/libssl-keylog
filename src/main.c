#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/sysmodule.h>
#include <psp2/io/fcntl.h>
#include <psp2/net/net.h>
#include <assert.h>

#include <stai/stai.h>

#include "common.h"
#include "cfg.h"

#define CFG_PATH "ur0:data/libssl-keylog.cfg"
#define KEYLOG_PATH "ux0:data/keylog.txt"

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

static SceUID keylog_fd = -1;
static SceUID net_fd = -1;

static SceNetSockaddrIn net_addr = {0};

typedef struct {
    SceNetSockaddrIn addr;
} config_state;

static int parse_config_ip(void* userarg, char* value) {
    config_state* state = (config_state*)userarg;
    if(sceNetInetPton(SCE_NET_AF_INET, value, &state->addr.sin_addr) != 1) return -1;
    return 0;
}

static int parse_config_port(void* userarg, char* value) {
    config_state* state = (config_state*)userarg;
    unsigned int port = 0;
    if(!*value) return -1;
    for(char* p = value; *p; p++) {
        if(*p < '0' || *p > '9') return -1;
        unsigned int digit = (unsigned int)(*p - '0');
        if(port > (65535U - digit) / 10U) return -1;
        port = port * 10U + digit;
    }
    if(port == 0) return -1;
    state->addr.sin_port = sceNetHtons((uint16_t)port);
    return 0;
}

static const cfg_key config_keys[] = {
    { "ip",   parse_config_ip,   1 },
    { "port", parse_config_port, 1 },
};

static int load_config(void) {
    config_state state = {0};
    int ret = cfg_load(CFG_PATH, config_keys, sizeof(config_keys) / sizeof(config_keys[0]), &state);
    if(ret < 0) return ret;
    state.addr.sin_family = SCE_NET_AF_INET;
    net_addr = state.addr;
    return 0;
}

static void write_keylog_file(char* buf, size_t size) {
    if(keylog_fd < 0) {
        keylog_fd = sceIoOpen(KEYLOG_PATH, SCE_O_CREAT | SCE_O_APPEND | SCE_O_WRONLY, 0666);
    }
    if(keylog_fd < 0) {
        log("open keylog: %08x", keylog_fd);
        return;
    }
    int ret = sceIoWrite(keylog_fd, buf, size);
    if(ret < 0) {
        sceIoClose(keylog_fd);
        keylog_fd = -1;
    }
}

static void write_keylog_net(char* buf, size_t size) {
    if(sceSysmoduleIsLoaded(SCE_SYSMODULE_NET) != 0) return;
    if(net_addr.sin_port == 0) return;
    int ret = 0;
    if(net_fd < 0) {
        net_fd = sceNetSocket("ssl_keylog", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
        ret = sceNetConnect(net_fd, (const SceNetSockaddr*)&net_addr, sizeof(net_addr));
        if(ret < 0) {
            sceNetSocketClose(net_fd);
            net_fd = -1;
        }
    }
    ret = sceNetSend(net_fd, buf, size, 0);
    if(ret < 0) {
        sceNetSocketClose(net_fd);
        net_fd = -1;
    }
}

static size_t format_client_random(const SSL* s, char* p) {
    const char* start = p;
    const char prefix[] = "CLIENT_RANDOM ";
    sceClibMemcpy(p, prefix, sizeof(prefix));
    p += sizeof(prefix)-1;
    p = tohex(p, s->s3->client_random, 32);
    *p++ = ' ';
    p = tohex(p, s->session->master_key, 48);
    *p++ = '\n';
    *p = 0;
    return (size_t)(p - start);
}

STAI_HOOK(int, tls1_setup_key_block, SSL* s) {
    int ssl_ret = STAI_HOOK_CONTINUE(tls1_setup_key_block, s);

    static int config_loaded = 0;
    if(!config_loaded) {
        config_loaded = 1;
        int ret = load_config();
        if(ret < 0) {
            log("failed to load config: 0x%08x", ret);
        }
    }

    char buf[0x100];
    size_t len = format_client_random(s, buf);
    sceClibPrintf(buf);
    write_keylog_file(buf, len);
    write_keylog_net(buf, len);
    return ssl_ret;
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
