// SPDX-License-Identifier: Apache-2.0
//
// A minimal, hand-built PE32+ (x86-64) image for exercising the loader's data-
// directory parsing: one .text section, a .rsrc tree with a single leaf
// ("DEDE", type 6 / name 1 / lang 0x409), and a .pdata table with one
// RUNTIME_FUNCTION [0x401000, 0x401010) unwind=0x404000. image_base = 0x400000.
#pragma once

#include <cstring>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::samples {

inline std::vector<u8> make_pe64_fixture() {
    std::vector<u8> d(0x700, 0);
    auto p16 = [&](u64 o, u16 v) { std::memcpy(&d[o], &v, 2); };
    auto p32 = [&](u64 o, u32 v) { std::memcpy(&d[o], &v, 4); };
    auto p64 = [&](u64 o, u64 v) { std::memcpy(&d[o], &v, 8); };

    d[0] = 'M'; d[1] = 'Z';
    p32(0x3c, 0x40);                 // e_lfanew -> PE header at 0x40
    d[0x40] = 'P'; d[0x41] = 'E';    // "PE\0\0"
    p16(0x44, 0x8664);               // machine = AMD64
    p16(0x46, 3);                    // NumberOfSections
    p16(0x54, 240);                  // SizeOfOptionalHeader
    p16(0x56, 0x22);                 // Characteristics (executable | large-address)

    const u64 opt = 0x58;            // pe(0x40) + 24
    p16(opt + 0, 0x20b);             // PE32+ magic
    p32(opt + 16, 0x1000);           // AddressOfEntryPoint (RVA)
    p64(opt + 24, 0x400000);         // ImageBase
    p32(opt + 32, 0x1000);           // SectionAlignment
    p32(opt + 36, 0x200);            // FileAlignment
    p32(opt + 108, 16);              // NumberOfRvaAndSizes
    p32(opt + 112 + 2 * 8, 0x2000);  p32(opt + 112 + 2 * 8 + 4, 0x100);  // dir[2] resource
    p32(opt + 112 + 3 * 8, 0x3000);  p32(opt + 112 + 3 * 8 + 4, 0x0c);   // dir[3] exception

    const u64 st = opt + 240;        // section table
    auto sec = [&](u64 base, const char* nm, u32 vsize, u32 vaddr, u32 rawsize, u32 rawptr, u32 chars) {
        std::memcpy(&d[base], nm, std::strlen(nm));
        p32(base + 8, vsize); p32(base + 12, vaddr);
        p32(base + 16, rawsize); p32(base + 20, rawptr);
        p32(base + 36, chars);
    };
    sec(st + 0,  ".text",  0x10,  0x1000, 0x10,  0x200, 0x60000020);
    sec(st + 40, ".rsrc",  0x100, 0x2000, 0x100, 0x400, 0x40000040);
    sec(st + 80, ".pdata", 0x10,  0x3000, 0x10,  0x600, 0x40000040);

    // .text @ file 0x200: mov rax,0x2a; ret
    const u8 code[] = {0x48, 0xC7, 0xC0, 0x2A, 0, 0, 0, 0xC3};
    std::memcpy(&d[0x200], code, sizeof code);

    // .rsrc @ file 0x400: type dir -> name dir -> lang dir -> data entry -> "DEDE"
    p16(0x40e, 1);               // type dir: NumberOfIdEntries
    p32(0x410, 6);               //   entry id = 6
    p32(0x414, 0x80000018);      //   -> subdir at rsrc+0x18
    p16(0x426, 1);               // name dir
    p32(0x428, 1);               //   entry id = 1
    p32(0x42c, 0x80000030);      //   -> subdir at rsrc+0x30
    p16(0x43e, 1);               // lang dir
    p32(0x440, 0x409);           //   entry id = 0x409
    p32(0x444, 0x48);            //   -> data entry at rsrc+0x48 (high bit clear)
    p32(0x448, 0x2058);          // data entry: DataRVA
    p32(0x44c, 4);               //   Size
    std::memcpy(&d[0x458], "DEDE", 4);  // payload @ rsrc+0x58 (RVA 0x2058)

    // .pdata @ file 0x600: one RUNTIME_FUNCTION (begin, end, unwind RVAs)
    p32(0x600, 0x1000); p32(0x604, 0x1010); p32(0x608, 0x4000);
    return d;
}

}  // namespace dede::samples
