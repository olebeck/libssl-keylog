from keystone import *
from capstone import *

from patcher import Patch, BASE, insn_b_to_addr, generate_all_patches

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True


class SSLKeylogPatch(Patch):
    _filename = "vs0/sys/external/libssl.suprx.elf"
    _extra_files = ["lssl.suprx.elf"]
    def patch_name(self) -> str:
        return f"ssl_keylog_0x{self.addr:08x}_0x{self.syms['SceIoOpen']:08x}"

    _imports = {
        "SceIoOpen": 0x6C60AC61
    }

    _code = (
        "ldr.w r1, [r4, #0xd0]\n" # s->session
        "ldr r0, [r4, #0x54]\n" # s->s3
        "blx SceIoOpen\n"
    )

    @staticmethod
    def find_patch_location(data: bytes) -> tuple[int, dict[str, int]]:
        key_expansion = BASE+data.find(b"key expansion")
        high = (key_expansion >> 16)
        low = key_expansion & 0xffff

        mov = data.find(ks.asm(f"movw r1, #0x{low:x}", 0, True)[0])
        end = data.find(b'\x1e\xb0\xbd\xe8\xf0\x87', mov)
        pos = end - 10

        return BASE + pos, {}


# prints errors in libssl
class SSLPrintErrorsPatch(Patch):
    _filename = "vs0/sys/external/libssl.suprx.elf"
    _extra_files = ["lssl.suprx.elf"]

    _imports = {
        "SceIoOpen": 0x6C60AC61
    }

    def patch_name(self) -> str:
        return f"ssl_print_errors_0x{self.addr:08x}_0x{self.syms['SceIoOpen']:08x}"

    _code = (
        "push {lr}\n"
        "blx SceIoOpen\n"
        "pop.w {pc}\n"
    )

    @staticmethod
    def find_patch_location(data: bytes) -> tuple[int, dict[str, int]]:
        pos = data.find(b'\x2d\xe9\xf0\x41\x14\x1c\x0e\x1c\x07\x1c')
        return BASE + pos, {}


# turns cert verify off, needed for psn redirect
class SSLNoVerifyPatch(Patch):
    _filename = "vs0/sys/external/libssl.suprx.elf"
    _extra_files = ["lssl.suprx.elf"]

    def patch_name(self) -> str:
        return f"ssl_no_verify"

    # r5 = 0 is before so its 0
    # set ssl->verify_mode = 0
    _code = (
        "str.w r5,[r9,#0xd4]\n"
    )

    @staticmethod
    def find_patch_location(data: bytes) -> tuple[int, dict[str, int]]:
        pos = data.find(b'\x4f\xf0\xff\x34\x17\xb9\xd9\xf8\x00\x01\x47\x6f')
        return BASE + pos, {}


class PsnRedirectPatch(Patch):
    _filename = "vs0/sys/external/libhttp.suprx.elf"
    _extra_files = ["lhttp.suprx.elf"]
    def patch_name(self):
        return f"psn_redirect_0x{self.addr:08x}_0x{self.syms['sceAppMgrIsNonGameProgram']:08x}"

    _imports = {
        "sceAppMgrIsNonGameProgram": 0x5F22E192,
        "sceClibStrnlen": 0xAC595E68
    }

    _code = (
        "ldr.w r4, [sp, #0xbc]\n" # load serverNameBuf from stack
        
        # get length
        "mov r0, r4\n"
        "movs r1, #0xff\n"
        "blx sceClibStrnlen\n"
        "mov r3, r0\n"
        
        # check if need to rewrite, how long
        "movw r0, #0x0\n" # out buf is 0 because only want length
        "mov r1, r4\n" # serverNameBuf
        "movw r2, #0x1234\n" # identifier to the hook
        "blx sceAppMgrIsNonGameProgram\n" # call the hook
        "cmp r0, #0\n" # check if its < 0
        "ble patch_end\n" # if its less than 0 no need to rewrite, skip the patch

        # allocate new buffer
        "mov r1, r0\n" # store the returned length in r1
        "ldr.w r0, [r11, #0xb0]\n" # load template->allocator.alloc
        "bl call_alloc\n" # allocate the returned length (r1) with the allocator in r0
        "str.w r0, [sp, #0xbc]\n" # store the new buffer address in the serverNameBuf stack location

        # write the modified domain name to the buffer
        "mov r1, r4\n" # serverNameBuf
        "movw r2, #0x1234\n" # identifier to the hook
        "blx sceAppMgrIsNonGameProgram\n" # call the hook (r0 = buffer, r1 = serverNameBuf, r2 = identifier)

        # free old buffer
        "ldr.w r0, [r11, 0xb4]\n" # load template->allocator.free
        "mov r1, r4\n" # load serverNameBuf to r1
        "bl call_dealloc\n" # deallocate the old server name

        "b patch_end\n" # skip the to the end of the patch
    )


    # finds the start of where to patch,
    # where the end of the if block
    # and the alloc, free functions to use on the servername are,
    # does this with simple byte offsets from the known string
    # this works fine as sony hasnt changed the module basically at all in recent versions  
    @staticmethod
    def find_patch_location(seg: bytes) -> tuple[int, dict[str, int]]:
        SceLibHttp_str_location = BASE+seg.find(b"SceLibHttp_%s")
        low = SceLibHttp_str_location & 0xffff

        # find patch_start
        mov = seg.find(ks.asm(f"movw r2, #0x{low:x}", 0, True)[0])
        patch_start = BASE + (mov-52)

        # find patch_end
        dis = list(cs.disasm(seg[mov-52:mov], mov-52, 3))
        # make sure the offset is correct
        assert dis[0].mnemonic == "blx"
        assert dis[1].mnemonic == "cmp"
        assert dis[2].mnemonic == "bne"
        patch_end = insn_b_to_addr(dis[2])

        # find call_alloc
        call_to_alloc = patch_end + 52
        dis2 = list(cs.disasm(seg[call_to_alloc:call_to_alloc+4], call_to_alloc, 1))
        assert dis2[0].mnemonic == "bl"
        call_alloc = insn_b_to_addr(dis2[0])

        # find call_dealloc
        call_to_dealloc = call_to_alloc + 74
        dis3 = list(cs.disasm(seg[call_to_dealloc:call_to_dealloc+4], call_to_dealloc, 1))
        assert dis3[0].mnemonic == "bl"
        call_dealloc = insn_b_to_addr(dis3[0])

        return patch_start, {
            "patch_end": BASE+patch_end,
            "call_alloc": BASE+call_alloc,
            "call_dealloc": BASE+call_dealloc
        }


# shell checks that the ca is SCEI DNAS 5, just return 0 it
class ShellCACheckPatch(Patch):
    _filename = "vs0/vsh/shell/shell.self.elf"
    def patch_name(self):
        return "shell_ca_check_patch"
    
    _code = (
        "mov r0, 0\n"
        "bx lr\n"
    )

    @staticmethod
    def find_patch_location(data: bytes) -> tuple[int, dict[str, int]]:
        off = data.find(b'\x01\xeb\x82\x00\x50\xf8\x04\x0c')-22
        dis = list(cs.disasm(data[off:off+6], off, 2))
        assert dis[0].mnemonic == "push.w"
        assert dis[1].mnemonic == "sub"
        return BASE+off, {}


class ShellXMPPRedirect(Patch):
    _filename = "vs0/vsh/shell/shell.self.elf"
    def patch_name(self):
        return f"shell_xmpp_redirect_patch_0x{self.addr:08x}_0x{self.syms['sceAppMgrReleaseBgmPort']:08x}"
    
    _imports = {
        "sceAppMgrReleaseBgmPort": 0xF3717E37,
    }

    _code = (
        "blx sceAppMgrReleaseBgmPort\n"
    )

    @staticmethod
    def find_patch_location(data: bytes) -> tuple[int, dict[str, int]]:
        off = data.find(b'\xc4\xf8\x2c\x90\xc4\xf8\x30\x90')
        if off < 0:
            raise Exception("not found")
        off -= 20
        dis = list(cs.disasm(data[off:off+32], off, 3))
        assert dis[0].mnemonic == "str.w"
        assert dis[1].mnemonic == "adds.w"
        assert dis[2].mnemonic == "str.w"
        return BASE+off, {}


# matching2 uses port 443 for non https, kinda annoying so just patch it to a different port (3480)
class Matching2TlsPortPatch(Patch):
    _filename = "vs0/sys/external/np_matching2.suprx.elf"
    def patch_name(self):
        return "np_matching2_tls_patch"
    
    _code = (
        "movw r1, #0xd98\n"
    )

    @staticmethod
    def find_patch_location(data: bytes) -> tuple[int, dict[str, int]]:
        start_needle = bytes(ks.asm("""
            push {r4,r5,r6,r7,r8,r9,r10,r11,lr}
            sub sp,#0x14
            strd r2, r1, [sp]
        """)[0])
        end_needle = bytes(ks.asm("""
            add sp,#0x14
            pop.w {r4,r5,r6,r7,r8,r9,r10,r11,pc}
        """)[0])

        start = data.find(start_needle)
        end = data[start:].find(end_needle) + start
        precise = bytes(ks.asm("movw r1,#443")[0])
        off = data[start:end].index(precise)
        return BASE+off+start, {}


def main():
    with open("inject.h", "w") as f_h, open("inject.c", "w") as f_c:
        source, header = generate_all_patches(
            SSLKeylogPatch, SSLPrintErrorsPatch, SSLNoVerifyPatch,
            PsnRedirectPatch, ShellCACheckPatch, ShellXMPPRedirect, Matching2TlsPortPatch
        )
        f_h.write(header)
        f_c.write(source)

main()
