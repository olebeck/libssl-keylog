#include <taihen.h>
#include <stdbool.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h> 

#include "tcp-proxy.h"

static SceNetSockaddrIn proxy_target_addr;

static SceUID connect_hook_id;
static tai_hook_ref_t connect_hook_ref;
unsigned long long account_id;

bool is_local_addr(SceNetInAddr addr) {
    unsigned long ip = ksceNetHtonl(addr.s_addr);

    // Check for localhost (127.0.0.0/8)
    if ((ip & 0xFF000000) == 0x7F000000) {
        return true;
    }

    // Check for private IP ranges
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) {
        return true;
    }
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000) {
        return true;
    }
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) {
        return true;
    }

    return false;
}

bool is_target_addr(SceNetInAddr addr) {
    return addr.s_addr == proxy_target_addr.sin_addr.s_addr;
}

#define PROXY_V2_SIGNATURE "\r\n\r\n\0\r\nQUIT\n"
#define PROXY_V2_VERSION 0x2
#define PROXY_V2_COMMAND_PROXY 0x0
#define PROXY_V2_AF_INET 0x1
#define PROXY_V2_PROTO_STREAM 0x1

typedef struct proxy_hdr_v2 {
    uint8_t sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
    uint8_t ver_cmd;  /* protocol version and command */
    uint8_t fam;      /* protocol family and address */
    uint16_t len;     /* number of following bytes part of the header */
} __attribute__((packed)) proxy_hdr_v2;

typedef struct proxy_ipv4_addr {        /* for TCP/UDP over IPv4, len = 12 */
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
} __attribute__((packed)) proxy_ipv4_addr;

typedef struct proxy_v2_tlv {
    uint8_t type;
    uint16_t length;
} __attribute__((packed)) proxy_v2_tlv;

typedef struct tlv_account_id {
    proxy_v2_tlv tlv;
    uint64_t value;
} __attribute__((packed)) tlv_account_id;

typedef struct proxy_v2_header {
    proxy_hdr_v2 hdr;
    proxy_ipv4_addr addr;
    tlv_account_id account_id;
} __attribute__((packed)) proxy_v2_header;

void create_proxy_v2_header(const SceNetSockaddrIn* src,
                            const SceNetSockaddrIn* dst,
                            uint64_t account_id,
                            proxy_v2_header *header) {
    memcpy(header->hdr.sig, PROXY_V2_SIGNATURE, sizeof(header->hdr.sig));
    header->hdr.ver_cmd = (PROXY_V2_VERSION << 4) | PROXY_V2_COMMAND_PROXY;
    header->hdr.fam = (PROXY_V2_AF_INET << 4) | PROXY_V2_PROTO_STREAM;
    header->hdr.len = ksceNetHtons(sizeof(proxy_ipv4_addr) + sizeof(tlv_account_id));
    header->addr.src_addr = src->sin_addr.s_addr;
    header->addr.src_port = src->sin_port;
    header->addr.dst_addr = dst->sin_addr.s_addr;
    header->addr.dst_port = dst->sin_port;
    header->account_id.tlv.length = ksceNetHtons(sizeof(uint64_t));
    header->account_id.tlv.type = 0xe1;
    header->account_id.value = account_id;
}

int ksceNetGetsockname(int s, const SceNetSockaddr* name, unsigned int namelen);

int sceNetSyscallConnect_hook(int s, const SceNetSockaddr* name, unsigned int namelen) {
    uint32_t state;
    ENTER_SYSCALL(state);

    SceNetSockaddrIn name_in;
    ksceKernelMemcpyFromUser((void*)&name_in, (void*)name, namelen);

    ksceKernelPrintf("sceNetSyscallConnect_hook\n");

    int ret = 0;
    if(is_local_addr(name_in.sin_addr) || is_target_addr(name_in.sin_addr)) {
        ret = ksceNetConnect(s, (SceNetSockaddr*)&name_in, namelen);
        goto RETURN;
    }

    // connect to proxy instead
    ret = ksceNetConnect(s, (SceNetSockaddr*)&proxy_target_addr, sizeof(proxy_target_addr));
    if(ret < 0) goto RETURN;

    // get localaddr
    SceNetSockaddrIn src;
    //ret = ksceNetGetsockname(s, (SceNetSockaddr*)&src, sizeof(src));
    //if(ret < 0) goto RETURN;

    // write proxy v2 header
    proxy_v2_header header;
    create_proxy_v2_header(&src, &name_in, account_id, &header);
    ret = ksceNetSend(s, &header, sizeof(header), 0);

RETURN:
    EXIT_SYSCALL(state);
    return ret;
}

void proxy_init(SceNetSockaddrIn* target, uint64_t _account_id) {
    proxy_target_addr = *target;
    account_id = _account_id;

    connect_hook_id = taiHookFunctionExportForKernel(
        KERNEL_PID,
        &connect_hook_ref,
        "SceNetPs",
        0x2CBED2C6, // SceNetForSyscalls
        0x14A4DE52, // sceNetSyscallConnect
        sceNetSyscallConnect_hook
    );
    if(connect_hook_id < 0) {
        ksceKernelPrintf("failed to hook sceNetConnect 0x%08x", connect_hook_id);
    }
}

void proxy_release() {
    if(connect_hook_id > 0) {
        taiHookReleaseForKernel(connect_hook_id, connect_hook_ref);
    }
}
