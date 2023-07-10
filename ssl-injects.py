from keystone import *

from patcher import Patch, BASE, generate_all_patches

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)


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
    def find(data: bytes) -> tuple[int, dict[str, int]]:
        key_expansion = BASE+data.find(b"key expansion")
        high = (key_expansion >> 16)
        low = key_expansion & 0xffff

        mov = data.find(ks.asm(f"movw r1, #0x{low:x}", 0, True)[0])
        end = data.find(b'\x1e\xb0\xbd\xe8\xf0\x87', mov)
        pos = end - 10

        return BASE + pos, {}


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
    def find(data: bytes) -> tuple[int, dict[str, int]]:
        pos = data.find(b'\x2d\xe9\xf0\x41\x14\x1c\x0e\x1c\x07\x1c')
        return BASE + pos, {}



class SSLNoVerifyPatch(Patch):
    _filename = "vs0/sys/external/libssl.suprx.elf"
    _extra_files = ["lssl.suprx.elf"]

    def patch_name(self) -> str:
        return f"ssl_no_verify"

    _code = (
        "str.w r5,[r9,#0xd4]\n"
    )

    @staticmethod
    def find(data: bytes) -> tuple[int, dict[str, int]]:
        pos = data.find(b'\x4f\xf0\xff\x34\x17\xb9\xd9\xf8\x00\x01\x47\x6f')
        return BASE + pos, {}



def main():
    with open("inject.h", "w") as f:
        f.write(generate_all_patches(SSLKeylogPatch, SSLPrintErrorsPatch, SSLNoVerifyPatch))

main()
