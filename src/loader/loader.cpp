// SPDX-License-Identifier: Apache-2.0
#include "dede/loader/loader.hpp"

#include <cstring>
#include <fstream>

namespace dede {
namespace {

// Bounds-checked little-endian reads over a byte buffer; any out-of-range read
// marks the cursor bad so a malformed file yields an error, never a crash.
struct Reader {
    const std::vector<u8>& d;
    bool ok = true;
    bool has(u64 off, u64 n) const { return off + n <= d.size() && off + n >= off; }
    u8 u8_(u64 o) { if (!has(o, 1)) { ok = false; return 0; } return d[o]; }
    u16 u16_(u64 o) { if (!has(o, 2)) { ok = false; return 0; } u16 v; std::memcpy(&v, &d[o], 2); return v; }
    u32 u32_(u64 o) { if (!has(o, 4)) { ok = false; return 0; } u32 v; std::memcpy(&v, &d[o], 4); return v; }
    u64 u64_(u64 o) { if (!has(o, 8)) { ok = false; return 0; } u64 v; std::memcpy(&v, &d[o], 8); return v; }
    std::string cstr(u64 o) {
        std::string s;
        while (has(o, 1) && d[o]) s.push_back(static_cast<char>(d[o++]));
        return s;
    }
};

u8 elf_perms(u32 pf) {
    u8 p = 0;
    if (pf & 0x4) p |= perm::R;
    if (pf & 0x2) p |= perm::W;
    if (pf & 0x1) p |= perm::X;
    return p ? p : perm::R;
}

std::vector<u8> slice_padded(const std::vector<u8>& d, u64 off, u64 filesz, u64 memsz) {
    std::vector<u8> out(memsz, 0);
    for (u64 i = 0; i < filesz && off + i < d.size() && i < memsz; ++i) out[i] = d[off + i];
    return out;
}

}  // namespace

Result<LoadedImage> load_elf64(const std::vector<u8>& d) {
    Reader r{d};
    if (d.size() < 64 || d[0] != 0x7f || d[1] != 'E' || d[2] != 'L' || d[3] != 'F')
        return make_error("not an ELF file");
    if (d[4] != 2) return make_error("ELF: only 64-bit (ELFCLASS64) supported");
    if (d[5] != 1) return make_error("ELF: only little-endian supported");
    u16 machine = r.u16_(18);
    if (machine != 62) return make_error("ELF: only x86-64 (EM_X86_64) supported");

    LoadedImage img;
    img.format = "elf64";
    img.arch = Arch::X86_64;
    img.entry = r.u64_(24);
    u64 phoff = r.u64_(32), shoff = r.u64_(40);
    u16 phentsize = r.u16_(54), phnum = r.u16_(56);
    u16 shentsize = r.u16_(58), shnum = r.u16_(60), shstrndx = r.u16_(62);

    // Program headers -> loadable segments.
    for (u16 i = 0; i < phnum; ++i) {
        u64 ph = phoff + static_cast<u64>(i) * phentsize;
        if (r.u32_(ph) != 1) continue;  // PT_LOAD
        u32 flags = r.u32_(ph + 4);
        u64 off = r.u64_(ph + 8), vaddr = r.u64_(ph + 16);
        u64 filesz = r.u64_(ph + 32), memsz = r.u64_(ph + 40);
        if (memsz == 0 || memsz > (1ull << 32)) continue;  // sanity
        img.segments.push_back({vaddr, elf_perms(flags), slice_padded(d, off, filesz, memsz)});
    }
    if (img.segments.empty())
        return make_error("ELF: no loadable segments");

    // Section headers -> section list (names from the section-header string table).
    u64 shstr_off = 0;
    if (shnum && shstrndx < shnum) shstr_off = r.u64_(shoff + static_cast<u64>(shstrndx) * shentsize + 24);
    auto sh_name = [&](u64 sh) { return r.cstr(shstr_off + r.u32_(sh)); };
    u64 symtab_off = 0, symtab_sz = 0, symstr_off = 0;
    u64 dynsym_off = 0, dynsym_sz = 0, dynstr_off = 0;
    for (u16 i = 0; i < shnum; ++i) {
        u64 sh = shoff + static_cast<u64>(i) * shentsize;
        u64 flags = r.u64_(sh + 8), addr = r.u64_(sh + 16), size = r.u64_(sh + 32);
        std::string name = sh_name(sh);
        if (addr) {
            u8 p = perm::R | ((flags & 0x1) ? perm::W : 0) | ((flags & 0x4) ? perm::X : 0);
            img.sections.push_back({name, addr, size, p});
        }
        if (name == ".symtab") { symtab_off = r.u64_(sh + 24); symtab_sz = size;
            u32 link = r.u32_(sh + 40); symstr_off = r.u64_(shoff + static_cast<u64>(link) * shentsize + 24); }
        if (name == ".dynsym") { dynsym_off = r.u64_(sh + 24); dynsym_sz = size;
            u32 link = r.u32_(sh + 40); dynstr_off = r.u64_(shoff + static_cast<u64>(link) * shentsize + 24); }
    }

    auto parse_syms = [&](u64 off, u64 sz, u64 stroff, bool imports) {
        for (u64 o = 0; o + 24 <= sz; o += 24) {
            u64 e = off + o;
            u32 nameoff = r.u32_(e);
            u8 info = r.u8_(e + 4);
            u16 shndx = r.u16_(e + 6);
            u64 value = r.u64_(e + 8);
            std::string nm = r.cstr(stroff + nameoff);
            if (nm.empty()) continue;
            bool func = (info & 0xf) == 2;  // STT_FUNC
            if (imports) {
                if (shndx == 0) img.imports.push_back(nm);  // SHN_UNDEF
            } else if (value) {
                img.symbols.push_back({value, nm, func});
            }
        }
    };
    if (symtab_off) parse_syms(symtab_off, symtab_sz, symstr_off, false);
    if (dynsym_off) parse_syms(dynsym_off, dynsym_sz, dynstr_off, true);

    if (!r.ok) return make_error("ELF: truncated or malformed headers");
    return img;
}

Result<LoadedImage> load_pe64(const std::vector<u8>& d) {
    Reader r{d};
    if (d.size() < 0x40 || d[0] != 'M' || d[1] != 'Z') return make_error("not a PE/MZ file");
    u32 pe = r.u32_(0x3c);
    if (!r.has(pe, 24) || r.u32_(pe) != 0x00004550) return make_error("PE: bad NT signature");
    u16 machine = r.u16_(pe + 4);
    if (machine != 0x8664) return make_error("PE: only x86-64 (AMD64) supported");
    u16 nsec = r.u16_(pe + 6);
    u16 opt_sz = r.u16_(pe + 20);
    u64 opt = pe + 24;
    if (r.u16_(opt) != 0x20b) return make_error("PE: only PE32+ (64-bit) supported");
    u32 entry_rva = r.u32_(opt + 16);
    u64 image_base = r.u64_(opt + 24);

    LoadedImage img;
    img.format = "pe64";
    img.entry = image_base + entry_rva;

    u64 sec = opt + opt_sz;
    for (u16 i = 0; i < nsec; ++i) {
        u64 s = sec + static_cast<u64>(i) * 40;
        char nm[9] = {0};
        for (int j = 0; j < 8; ++j) nm[j] = static_cast<char>(r.u8_(s + j));
        u32 vsize = r.u32_(s + 8), vaddr = r.u32_(s + 12);
        u32 rawsize = r.u32_(s + 16), rawptr = r.u32_(s + 20);
        u32 chars = r.u32_(s + 36);
        u8 p = perm::R | ((chars & 0x80000000u) ? perm::W : 0) | ((chars & 0x20000000u) ? perm::X : 0);
        u64 va = image_base + vaddr;
        img.sections.push_back({nm, va, vsize, p});
        if (vsize) img.segments.push_back({va, p, slice_padded(d, rawptr, rawsize, vsize ? vsize : rawsize)});
    }
    if (img.segments.empty()) return make_error("PE: no sections");
    if (!r.ok) return make_error("PE: truncated or malformed headers");
    // (Import directory parsing is a future step; headers/sections/entry are enough
    // for load + run + section analysis today.)
    return img;
}

Result<LoadedImage> parse_image(const std::vector<u8>& d, Addr flat_base) {
    if (d.size() >= 4 && d[0] == 0x7f && d[1] == 'E' && d[2] == 'L' && d[3] == 'F')
        return load_elf64(d);
    if (d.size() >= 2 && d[0] == 'M' && d[1] == 'Z') {
        auto pe = load_pe64(d);
        if (pe) return pe;  // else fall through to flat
    }
    LoadedImage img;
    img.format = "flat";
    img.entry = flat_base;
    img.segments.push_back({flat_base, perm::RWX, d});
    return img;
}

Result<LoadedImage> load_image_file(const std::string& path, Addr flat_base) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return make_error("cannot open " + path);
    std::vector<u8> d{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    if (d.empty()) return make_error("empty file: " + path);
    return parse_image(d, flat_base);
}

}  // namespace dede
