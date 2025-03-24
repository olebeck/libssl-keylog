#pragma once
#include <psp2kern/net/net.h>

void tls_keylog_init(bool with_net);
void tls_keylog_release();
