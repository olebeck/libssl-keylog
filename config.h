#pragma once
#include "http-rewrite.h"

const replacement_t replacements[] = {
    {
        .original_domain = "playstation.net",
        .replacement_domain = "np.yuv.pink",
    },
    {
        .original_domain = "kzv.online.scee.com",
        .replacement_domain = "mirage.yuv.pink"
    }
};

const char* xmpp_replacement = "xmpp.np.yuv.pink";
