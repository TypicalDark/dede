// SPDX-License-Identifier: Apache-2.0
//
// Binary loaders: turn a real on-disk program (ELF64, PE64) or a flat code blob
// into a LoadedImage the session can map and run. This is what moves "import
// analysis / section headers / symbol recovery / format support" from out-of-scope
// to in-scope — dede can open an actual binary, not just a raw blob.
#pragma once

#include <string>
#include <vector>

#include "dede/common/memory.hpp"  // perm::*
#include "dede/common/types.hpp"

namespace dede {

struct LoadSegment {
    Addr vaddr = 0;
    u8 perms = 0;
    std::vector<u8> bytes;  // already zero-padded to the memory size
};

struct LoadSection {
    std::string name;
    Addr addr = 0;
    u64 size = 0;
    u8 perms = 0;
};

struct LoadSymbol {
    Addr addr = 0;
    std::string name;
    bool is_func = false;
};

struct LoadedImage {
    std::string format = "flat";  // "elf64" | "pe64" | "flat"
    Arch arch = Arch::X86_64;
    Addr entry = 0x1000;
    std::vector<LoadSegment> segments;
    std::vector<LoadSection> sections;
    std::vector<LoadSymbol> symbols;      // defined functions/objects
    std::vector<std::string> imports;     // imported (undefined) symbol names
};

// Auto-detect by magic: ELF -> load_elf, MZ/PE -> load_pe, else flat at 0x1000.
Result<LoadedImage> load_image_file(const std::string& path, Addr flat_base = 0x1000);

// Parse an in-memory image (same dispatch as load_image_file).
Result<LoadedImage> parse_image(const std::vector<u8>& data, Addr flat_base = 0x1000);

Result<LoadedImage> load_elf64(const std::vector<u8>& data);
Result<LoadedImage> load_pe64(const std::vector<u8>& data);

}  // namespace dede
