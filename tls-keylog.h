#pragma once
#include <psp2kern/net/net.h>

void tls_keylog_init(SceNetSockaddrIn* keylog_addr, uint64_t _account_id);
void tls_keylog_release();
