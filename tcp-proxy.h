#pragma once
#include <psp2kern/net/net.h>
#include <stdint.h>

void proxy_init(SceNetSockaddrIn* target, uint64_t account_id);
void proxy_release();
