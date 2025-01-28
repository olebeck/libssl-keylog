#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>
#include <taihen.h>

#include "http-rewrite.h"
#include "patch.h"
#include "inject.h"
#include "tai.h"


static tai_hook_ref_t sceAppMgrIsNonGameProgram_hook_ref;
static SceUID sceAppMgrIsNonGameProgram_hook_id = -1;

static const replacement_t* s_replacements;
static int s_replacements_num;

int replaceDomain(const char* input, char* out, int input_length, const char* part_to_replace, const char* replacement_domain) {
    const char* found = strstr(input, part_to_replace);
    if (found != NULL) {
        size_t part_len = strlen(part_to_replace);
        size_t replace_len = strlen(replacement_domain);
        size_t tail_len = strlen(found + part_len);
        size_t modified_len = strlen(input) - part_len + replace_len;
        
        if (out == NULL) {
            // just Return the length if out is 0
            return modified_len+1;
        }
        
        // Write the modified domain to out
        strncpy(out, input, found - input);
        strncpy(out + (found - input), replacement_domain, replace_len);
        strncpy(out + (found - input) + replace_len, found + part_len, tail_len + 1);
        out[modified_len] = '\0';
        ksceKernelPrintf("modified domain: %s\n", out);
        return modified_len+1;
    }

    return -1;
}

int sceAppMgrIsNonGameProgram_hook(char* out_user, char* serverName_user, int flag, int serverNameLength) {
    char serverName[0xff];
    char out[0xff];
    char* out_p = out;
    int ret = 0;

    if(flag == 0x00001234) {
        ksceKernelMemcpyFromUser(serverName, serverName_user, serverNameLength+1);
        if(out_user == NULL) {
            out_p = NULL;
        }

        for(int i = 0; i < s_replacements_num; i++) {
            const replacement_t r = s_replacements[i];
            ret = replaceDomain(serverName, out_p, serverNameLength, r.original_domain, r.replacement_domain);
            if(ret > 0) break;
        }

        if(ret > 0 && out_p != NULL) {
            ksceKernelMemcpyToUser(out_user, out_p, ret);
        }
        return ret;
    }

    return TAI_CONTINUE(int, sceAppMgrIsNonGameProgram_hook_ref);
}


void http_rewrite_patch_func(int pid, const char* path) {
    if(strstr(path, "libhttp.suprx") == NULL) {
        return;
    }

    if(pid == ksceKernelSysrootGetShellPid()) {
        tai_module_info_t shell_info;
        shell_info.size = sizeof(tai_module_info_t);
        int ret = get_tai_info(pid, "SceShell", &shell_info);
        if(ret < 0) {
            ksceKernelPrintf("get_tai_info SceShell: %08x\n", ret);
            return;
        }

        apply_patch(pid, shell_info.modid, shell_info.module_nid, get_ShellCACheckPatch, "ShellCACheckPatch");
        apply_patch(pid, shell_info.modid, shell_info.module_nid, get_ShellXMPPRedirect, "ShellXMPPRedirect");
    }

    tai_module_info_t http_info;
    http_info.size = sizeof(tai_module_info_t);
    int ret = get_tai_info(pid, "SceLibHttp", &http_info);
    if(ret < 0) {
        ksceKernelPrintf("get_tai_info SceShell: %08x\n", ret);
        return;
    }
    apply_patch(pid, http_info.modid, http_info.module_nid, get_PsnRedirectPatch, "PsnRedirectPatch");
}


void http_rewrite_init(const replacement_t* replacements, int replacement_num) {
    add_patch_func(http_rewrite_patch_func);

    s_replacements = replacements;
    s_replacements_num = replacement_num;

    sceAppMgrIsNonGameProgram_hook_id = taiHookFunctionExportForKernel(KERNEL_PID,
        &sceAppMgrIsNonGameProgram_hook_ref,
        "SceAppMgr", TAI_ANY_LIBRARY, 0x5F22E192,
        sceAppMgrIsNonGameProgram_hook
    );
    if(sceAppMgrIsNonGameProgram_hook_id < 0) {
        ksceKernelPrintf("sceAppMgrIsNonGameProgram_hook_id: %08x\n", sceAppMgrIsNonGameProgram_hook_id);
    }
}

void http_rewrite_release() {
    if(sceAppMgrIsNonGameProgram_hook_id > 0) {
        taiHookReleaseForKernel(sceAppMgrIsNonGameProgram_hook_id, sceAppMgrIsNonGameProgram_hook_ref);
    }
}
