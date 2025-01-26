#pragma once
typedef struct replacement_t {
    char* original_domain;
    char* replacement_domain;
} replacement_t;

void http_rewrite_init(const replacement_t* replacements, int replacement_num);
void http_rewrite_release();
