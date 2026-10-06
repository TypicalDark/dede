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

// A leaf of the PE .rsrc tree (type / id / language path + the raw bytes).
struct Resource {
    u32 type_id = 0;   // RT_* (3=icon, 6=string, 10=rcdata, 16=version, 24=manifest, ...)
    u32 name_id = 0;   // id (named resources use a synthetic id, name in `name`)
    u32 lang_id = 0;
    std::string name;  // non-empty for name-identified resources
    Addr rva = 0;
    u32 size = 0;
    std::vector<u8> bytes;
};

// A PE64 .pdata RUNTIME_FUNCTION record (x64 table-based exception handling).
struct ExceptionEntry {
    Addr begin = 0;    // VA of the protected range start
    Addr end = 0;      // VA one past the range
    Addr unwind = 0;   // VA of the UNWIND_INFO
};

struct LoadedImage {
    std::string format = "flat";  // "elf64" | "pe64" | "flat"
    Arch arch = Arch::X86_64;
    Addr entry = 0x1000;
    std::vector<LoadSegment> segments;
    std::vector<LoadSection> sections;
    std::vector<LoadSymbol> symbols;        // defined functions/objects
    std::vector<std::string> imports;       // imported (undefined) symbol names
    std::vector<Resource> resources;        // PE .rsrc leaves (empty for ELF/flat)
    std::vector<ExceptionEntry> exceptions; // PE .pdata RUNTIME_FUNCTIONs (empty otherwise)
};

// Auto-detect by magic: ELF -> load_elf, MZ/PE -> load_pe, else flat at 0x1000.
Result<LoadedImage> load_image_file(const std::string& path, Addr flat_base = 0x1000);

// Parse an in-memory image (same dispatch as load_image_file).
Result<LoadedImage> parse_image(const std::vector<u8>& data, Addr flat_base = 0x1000);

Result<LoadedImage> load_elf64(const std::vector<u8>& data);
Result<LoadedImage> load_pe64(const std::vector<u8>& data);

}  // namespace dede
