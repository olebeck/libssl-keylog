from keystone import *
from collections import namedtuple
from git import Repo, Commit
from io import BytesIO
from elftools.elf.elffile import ELFFile


psvita_elfs = Repo("psvita-elfs")

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
base = 0x81000000

def make_patch(addr: int, SceIoOpen: int):
    out = "{\n"
    jump = SceIoOpen - (addr + 6)

    for insn in [
        "ldr.w r1, [r4, #0xd0]", # s->session
        "ldr r0, [r4, #0x54]", # s->s3"
        f"blx #0x{jump:x}"
        ]:
        b = ks.asm(insn, 0, True)[0]
        line = ", ".join([f"0x{a:02x}" for a in b])
        out += f"\t{line}, // {insn}\n"
    
    out += "}"
    return out

class Patch:
    def __init__(self, addr: int, SceIoOpen: int, module_nid: int, versions: list = []):
        self.addr = addr
        self.SceIoOpen = SceIoOpen
        self.module_nid = module_nid
        self.versions = versions
    def __hash__(self) -> int:
        return self.addr*self.SceIoOpen


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


# automatically finds the patch location, where the SceIoOpen stub is
def find_patch(elf: ELFFile):
    entry: int = elf.header.e_entry
    segment_num = (entry >> 30) & 0x3
    info_offset = entry & 0x3fffffff
    seg = elf.get_segment(segment_num)
    seg_data: bytes = seg.data()

    info_data = seg_data[info_offset:info_offset+0xdc]
    module_nid = int.from_bytes(info_data[0x34:0x38], "little")
    funcCount = int.from_bytes(info_data[0xc2:0xc3], "little")
    pNidTable = int.from_bytes(info_data[0xd0:0xd4], "little")
    pEntryTable = int.from_bytes(info_data[0xd4:0xd8], "little")

    nid_table = seg_data[pNidTable-base:pNidTable-base + (funcCount*4)]
    entry_table = seg_data[pEntryTable-base:pEntryTable-base + (funcCount*4)]

    nids = {}
    for i in range(funcCount):
        nid = int.from_bytes(nid_table[i*4:(i+1)*4], "little")
        func = int.from_bytes(entry_table[i*4:(i+1)*4], "little")
        nids[nid] = func

    SceIoOpen = nids[0x6C60AC61]
    location = find_patch_location(seg_data)
    return Patch(location, SceIoOpen, module_nid)


# find patches in every version
auto_patches: list[Patch] = []
for version in versions:
    head = psvita_elfs.heads[version]
    commit: Commit = head.commit
    file_contents = psvita_elfs.git.show('{}:{}'.format(commit.hexsha, "vs0/sys/external/libssl.suprx.elf")).encode("utf8", "surrogateescape")
    elf = ELFFile(BytesIO(file_contents))
    
    patch = find_patch(elf)
    patch.versions.append(version)
    auto_patches.append(patch)


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

# get variable name for this patch
def patch_name(patch: Patch):
    return f"patch_0x{patch.addr:08x}_0x{patch.SceIoOpen:08x}"


# write header with the patch data and switch to select it
with open("inject.h", "w") as f:
    for patch in patches_unique:
        data = make_patch(patch.addr, patch.SceIoOpen)
        f.write(f"const char {patch_name(patch)}[] = {data};\n\n")

    f.write("""
int get_tls_patch(const char** patch, int* offset, int* patch_size, unsigned int module_nid) {
    switch(module_nid) {
""")

    for patch in patches_unique:
        for module_nid in patch.module_nid:
            p = patches[module_nid]
            f.write(f"\tcase 0x{module_nid:08x}: // {', '.join(p.versions)}\n")

        f.write(f"\t\t*patch = {patch_name(patch)};\n")
        f.write(f"\t\t*patch_size = sizeof({patch_name(patch)});\n")
        f.write(f"\t\t*offset = 0x{patch.addr-base:x};\n")
        f.write("\t\tbreak;\n")
    
    f.write("\tdefault:\n\t\treturn -1;\n")

    f.write("\t}\n\treturn 0;\n")
    f.write("}\n")
