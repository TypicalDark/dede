// SPDX-License-Identifier: Apache-2.0
//
// The ELF/PE/flat loaders: parse a hand-built minimal ELF64, load it into a
// session, and run it; plus flat fallback and malformed-input handling.
#include <cstring>
#include <vector>

#include "check.hpp"
#include "dede/loader/loader.hpp"
#include "dede/samples/pe_fixture.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
void put(std::vector<u8>& v, u64 off, const void* p, std::size_t n) {
    if (v.size() < off + n) v.resize(off + n, 0);
    std::memcpy(&v[off], p, n);
}
template <typename T> void putT(std::vector<u8>& v, u64 off, T x) { put(v, off, &x, sizeof x); }

// A minimal ELF64: Ehdr + one PT_LOAD phdr + code (mov rax,7 ; hlt).
std::vector<u8> minimal_elf() {
    const u64 kVaddr = 0x400000, kCodeOff = 0x78;
    std::vector<u8> code = {0x48, 0xC7, 0xC0, 0x07, 0x00, 0x00, 0x00, 0xF4};  // mov rax,7; hlt
    std::vector<u8> e;
    // Ehdr
    const u8 ident[16] = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    put(e, 0, ident, 16);
    putT<u16>(e, 16, 2);        // e_type = ET_EXEC
    putT<u16>(e, 18, 62);       // e_machine = x86-64
    putT<u32>(e, 20, 1);        // e_version
    putT<u64>(e, 24, kVaddr + kCodeOff);  // e_entry
    putT<u64>(e, 32, 64);       // e_phoff
    putT<u64>(e, 40, 0);        // e_shoff
    putT<u32>(e, 48, 0);        // e_flags
    putT<u16>(e, 52, 64);       // e_ehsize
    putT<u16>(e, 54, 56);       // e_phentsize
    putT<u16>(e, 56, 1);        // e_phnum
    // Phdr @ 64
    putT<u32>(e, 64, 1);        // PT_LOAD
    putT<u32>(e, 68, 5);        // R+X
    putT<u64>(e, 72, 0);        // p_offset
    putT<u64>(e, 80, kVaddr);   // p_vaddr
    putT<u64>(e, 88, kVaddr);   // p_paddr
    putT<u64>(e, 96, kCodeOff + code.size());  // p_filesz
    putT<u64>(e, 104, kCodeOff + code.size()); // p_memsz
    putT<u64>(e, 112, 0x1000);  // p_align
    put(e, kCodeOff, code.data(), code.size());
    return e;
}
}  // namespace

TEST("ELF64 parse: entry, segment, perms") {
    auto r = load_elf64(minimal_elf());
    CHECK(r.ok());
    CHECK_EQ(r.value().format, std::string("elf64"));
    CHECK_EQ(r.value().entry, 0x400078u);
    CHECK_EQ(r.value().segments.size(), 1u);
    CHECK_EQ(r.value().segments[0].vaddr, 0x400000u);
    CHECK((r.value().segments[0].perms & perm::X) != 0);
}

TEST("load an ELF into a session and run it") {
    auto img = parse_image(minimal_elf());
    CHECK(img.ok());
    AnalysisSession s(Arch::X86_64);
    CHECK(s.load_image(img.value()).ok());
    CHECK_EQ(s.rip(), 0x400078u);
    CHECK_EQ(s.image_format(), std::string("elf64"));
    CHECK(s.run().status == StepOutcome::Status::Halted);
    CHECK_EQ(s.read_reg(Reg::Rax), 7u);
}

TEST("flat fallback for a raw blob") {
    auto img = parse_image({0x90, 0x90, 0xF4}, 0x1000);
    CHECK(img.ok());
    CHECK_EQ(img.value().format, std::string("flat"));
    CHECK_EQ(img.value().entry, 0x1000u);
}

TEST("malformed ELF is rejected, not crashed") {
    std::vector<u8> bad = {0x7f, 'E', 'L', 'F', 2, 1, 1};  // truncated
    CHECK(!load_elf64(bad).ok());
}

TEST("PE64 loader parses .rsrc resources and the .pdata exception table") {
    auto img = load_pe64(samples::make_pe64_fixture());
    CHECK(img.ok());
    CHECK_EQ(img.value().format, std::string("pe64"));
    CHECK_EQ(img.value().entry, 0x401000u);

    CHECK_EQ(img.value().resources.size(), 1u);
    const auto& r = img.value().resources[0];
    CHECK_EQ(r.type_id, 6u);
    CHECK_EQ(r.name_id, 1u);
    CHECK_EQ(r.lang_id, 0x409u);
    CHECK_EQ(r.size, 4u);
    CHECK_EQ(std::string(r.bytes.begin(), r.bytes.end()), std::string("DEDE"));

    CHECK_EQ(img.value().exceptions.size(), 1u);
    CHECK_EQ(img.value().exceptions[0].begin, 0x401000u);
    CHECK_EQ(img.value().exceptions[0].end, 0x401010u);
    CHECK_EQ(img.value().exceptions[0].unwind, 0x404000u);
}

int main() { return dede::test::run_all(); }
