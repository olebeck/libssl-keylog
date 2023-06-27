from keystone import *
from git import Repo, Commit
from io import BytesIO
from typing import BinaryIO
from elftools.elf.elffile import ELFFile
import os, struct


base = 0x81000000

def to_c_array(b: bytes):
    return "{"+", ".join([f"0x{a:02x}" for a in b])+"}"

class Patch:
    def __init__(self, addr: int, SceIoOpen: int, module_nid: int):
        self.addr = addr
        self.SceIoOpen = SceIoOpen
        self.module_nid = module_nid
        self.versions = []
        self.ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self.ks.sym_resolver = self.sym_resolver
    
    def patch_name(self):
        return f"patch_0x{self.addr:08x}_0x{self.SceIoOpen:08x}"

    def sym_resolver(self, name: bytes, value):
        name: str = name.decode("utf8")
        if name == "SceIoOpen":
            value[0] = self.SceIoOpen
            return True
        print("missing symbol", name)
        return False

    def make(self):
        return to_c_array(self.ks.asm(
            "ldr.w r1, [r4, #0xd0]\n" # s->session
            "ldr r0, [r4, #0x54]\n" # s->s3
            "blx SceIoOpen\n",
            self.addr, True
        )[0])

    def __hash__(self) -> int:
        return self.addr*self.SceIoOpen


ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

# finds  tls1_setup_key_block based on a string pointer
# then finds the end of the function by searching for the pop.w
# -10 from that is the space for the patch 
def find_patch_location(seg: bytes):
    key_expansion = base+seg.find(b"key expansion")
    high = (key_expansion >> 16)
    low = key_expansion & 0xffff

    mov = seg.find(ks.asm(f"movw r1, #0x{low:x}", 0, True)[0])
    end = seg.find(b'\x1e\xb0\xbd\xe8\xf0\x87', mov)
    pos = end - 10

    return base + pos


class Struct:
    def __init__(self, data: bytes):
        format, names = self._format()
        tup = struct.unpack(format, data)
        for name, value in zip(names, tup):
            setattr(self, name, value)

    @classmethod
    def _format(cls):
        format = ""
        names = []
        for key, _ in cls.__annotations__.items():
            fmt = getattr(cls, key)
            format += fmt
            names.append(key)
        return format, names
    
    @classmethod
    def size(cls):
        return struct.calcsize(cls._format()[0])

class SceModuleInfo(Struct):
    attributes: int = "b"
    version: int = "h"
    module_name: str = "27s"
    type: int = "b"
    gp_value: int = "I"
    exportsStart: int = "I"
    exportsEnd: int = "I"
    importsTop: int = "I"
    importsEnd: int = "I"
    module_nid: int = "I"
    tlsStart: int = "I"
    tlsFileSize: int = "I"
    tlsMemSize: int = "I"
    module_start: int = "I"
    module_stop: int = "I"
    exidx_top: int = "I"
    exidx_end: int = "I"
    extab_start: int = "I"
    extab_end: int = "I"

class SceModuleImports(Struct):
    size_: int = "h"
    version: int = "h"
    attribute: int = "h"
    num_functions: int = "h"
    num_vars: int = "h"
    library_nid: int = "I"
    library_name: int = "I"
    func_nid_table: int = "I"
    func_entry_table: int = "I"
    var_nid_table: int = "I"
    var_entry_table: int = "I"


def get_nids(seg_data: bytes, module_info: SceModuleInfo):
    importsData = seg_data[module_info.importsTop:module_info.importsEnd]
    nids = {}
    off = 0
    while off < len(importsData):
        size = int.from_bytes(importsData[off:off+2], "little")
        assert size == 0x24
        
        imports = SceModuleImports(importsData[off:off+size])
        off += size
        
        entry_table_location = imports.func_entry_table-base
        func_entry_table = seg_data[entry_table_location:entry_table_location+imports.num_functions*4]
        nid_table_location = imports.func_nid_table-base
        func_nid_table = seg_data[nid_table_location:nid_table_location+imports.num_functions*4]

        for i in range(imports.num_functions):
            nid = int.from_bytes(func_nid_table[i*4:(i+1)*4], "little")
            func = int.from_bytes(func_entry_table[i*4:(i+1)*4], "little")
            nids[nid] = func
    return nids


# automatically finds the patch location, where the SceIoOpen stub is
def find_patch(elf: ELFFile):
    entry: int = elf.header.e_entry
    segment_num = (entry >> 30) & 0x3
    info_offset = entry & 0x3fffffff
    seg = elf.get_segment(segment_num)
    seg_data: bytes = seg.data()
    
    module_info = SceModuleInfo(seg_data[info_offset:info_offset+SceModuleInfo.size()])
    nids = get_nids(seg_data, module_info)

    SceIoOpen = nids[0x6C60AC61]

    location = find_patch_location(seg_data)
    return Patch(location, SceIoOpen, module_info.module_nid)


# versions to look at
versions = [
    "360-CEX", "360-DEX", "360-QAF", "360-TOOL",
    "361-CEX", "361-DEX", "361-TOOL",
    "363-CEX", "363-DEX", "363-QAF",  "363-TOOL",
    "365-CEX", "365-DEX", "365-TOOL",
    "367-CEX", "367-DEX", "367-TOOL",
    "368-CEX", "368-DEX", "368-TOOL",
    "369-CEX",
    "370-CEX",
    "371-CEX", "371-TOOL",
    "372-CEX", "372-DEX", "372-QAF",
    "373-CEX", "373-TOOL",
    "374-CEX",   
]

def add_all_patches():
    # find patches in every version
    auto_patches: list[Patch] = []
    def add_patch(r: BinaryIO, version: str):
        elf = ELFFile(r)
        patch = find_patch(elf)
        patch.versions.append(version)
        auto_patches.append(patch)

    psvita_elfs = Repo("psvita-elfs")
    for version in versions:
        head = psvita_elfs.heads[version]
        commit: Commit = head.commit
        file_contents = psvita_elfs.git.show('{}:{}'.format(commit.hexsha, "vs0/sys/external/libssl.suprx.elf")).encode("utf8", "surrogateescape")
        add_patch(BytesIO(file_contents), version)
    psvita_elfs.close()

    libssl_itls = "lssl.suprx.elf"
    if os.path.exists(libssl_itls):
        with open(libssl_itls, "rb") as f:
            add_patch(f, "itls")
    return auto_patches


def filter_patches(auto_patches: list[Patch]):
    # patches by module_nid
    patches: dict[int, Patch] = {}
    for patch in auto_patches:
        existing = patches.get(patch.module_nid)
        if existing:
            assert patch.SceIoOpen == existing.SceIoOpen and patch.addr == existing.addr
            existing.versions.append(patch.versions[0])
        else:
            patches[patch.module_nid] = patch

    # patches that are not the same address and sceioopen 
    patches_unique: list[Patch] = []
    for patch in patches.values():
        exists = len([p for p in patches_unique if hash(p) == hash(patch)]) > 0
        if not exists:
            patches_unique.append(patch)

    # put all module_nids that this patch works for in the patch
    for patch in patches_unique:
        matches = [a for a in auto_patches if a.addr == patch.addr and a.SceIoOpen == patch.SceIoOpen]
        patch.module_nid = set([match.module_nid for match in matches])

    return patches_unique, patches


# write header with the patch data and switch to select it
def write_inject_h(patches_unique: list[Patch], patches: dict[int, Patch]):
    with open("inject.h", "w") as f:
        for patch in patches_unique:
            f.write(f"const char {patch.patch_name()}[] = {patch.make()};\n\n")

        f.write("\nint get_tls_patch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {\n")
        f.write("    switch(module_nid) {\n")

        for patch in patches_unique:
            for module_nid in patch.module_nid:
                p = patches[module_nid]
                f.write(f"\tcase 0x{module_nid:08x}: // {', '.join(p.versions)}\n")

            f.write(f"\t\t*patch = {patch.patch_name()};\n")
            f.write(f"\t\t*patch_size = sizeof({patch.patch_name()});\n")
            f.write(f"\t\t*offset = 0x{patch.addr-base:x};\n")
            f.write("\t\tbreak;\n")
        
        f.write("\tdefault:\n\t\treturn -1;\n")

        f.write("\t}\n\treturn 0;\n")
        f.write("}\n")


def main():
    auto_patches = add_all_patches()
    patches_unique, patches = filter_patches(auto_patches)
    write_inject_h(patches_unique, patches)


main()
