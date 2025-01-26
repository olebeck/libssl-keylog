static void print_hex(char* buf, char* out, int size) {
    for (int z = 0; z < size; z++) {
        unsigned char hi = (buf[z] >> 4) & 0xf; 
        unsigned char lo = buf[z] & 0xf;        
        *out++ = hi + (hi < 10 ? '0' : 'a' - 10);
        *out++ = lo + (lo < 10 ? '0' : 'a' - 10);
    }
    *out++ = 0;
}

#define DEFINE_SCE_NET_SOCKADDR_IN(name, ip1, ip2, ip3, ip4, port)  \
    SceNetSockaddrIn name = {                       \
        .sin_len = sizeof(SceNetSockaddrIn),        \
        .sin_family = SCE_NET_AF_INET,              \
        .sin_port = ksceNetHtons(port),             \
        .sin_addr = { .s_addr = ksceNetHtonl((ip1 << 24) | (ip2 << 16) | (ip3 << 8) | ip4) }, \
        .sin_vport = 0,                             \
        .sin_zero = {0}                             \
    }

#define ARRAY_LEN(x) (sizeof(x)/sizeof(*x))
