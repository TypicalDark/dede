// SPDX-License-Identifier: Apache-2.0
#include "check.hpp"
#include "dede/disasm/assembler.hpp"
#include "dede/disasm/disassembler.hpp"

using namespace dede;

TEST("capstone decodes mov and extracts structured operands") {
    auto d = make_disassembler(Arch::X86_64);
    std::vector<u8> code = {0x48, 0xC7, 0xC0, 0x10, 0x00, 0x00, 0x00};  // mov rax, 0x10
    auto r = d->decode_one(code.data(), code.size(), 0x1000);
    CHECK(r.ok());
    CHECK_EQ(r.value().mnemonic, std::string("mov"));
    CHECK_EQ(r.value().size, 7u);
    CHECK_EQ(r.value().operands.size(), 2u);
    CHECK(r.value().operands[0].kind == OpKind::Reg);
    CHECK(r.value().operands[0].reg == Reg::Rax);
    CHECK(r.value().operands[1].kind == OpKind::Imm);
    CHECK_EQ(r.value().operands[1].imm, 0x10);
}

TEST("control-flow classification") {
    auto d = make_disassembler(Arch::X86_64);
    std::vector<u8> jmp = {0xE9, 0x00, 0x00, 0x00, 0x00};  // jmp rel32
    std::vector<u8> ret = {0xC3};
    std::vector<u8> call = {0xE8, 0x00, 0x00, 0x00, 0x00};
    CHECK(d->decode_one(jmp.data(), jmp.size(), 0x1000).value().cf.is_branch);
    CHECK(d->decode_one(ret.data(), ret.size(), 0x1000).value().cf.is_ret);
    CHECK(d->decode_one(call.data(), call.size(), 0x1000).value().cf.is_call);
}

TEST("flyweight decode cache shares identical decodes") {
    auto d = make_disassembler(Arch::X86_64);
    DecodeCache cache(*d);
    std::vector<u8> code = {0x90};  // nop
    auto a = cache.at(code.data(), code.size(), 0x1000);
    auto b = cache.at(code.data(), code.size(), 0x1000);
    CHECK(a.get() == b.get());    // same shared instruction
    CHECK_EQ(cache.size(), 1u);
}

TEST("decode cache versions self-modifying code by bytes") {
    auto d = make_disassembler(Arch::X86_64);
    DecodeCache cache(*d);
    std::vector<u8> nop = {0x90};
    std::vector<u8> ret = {0xC3};
    auto a = cache.at(nop.data(), nop.size(), 0x1000);
    auto b = cache.at(ret.data(), ret.size(), 0x1000);  // same addr, different bytes
    CHECK(a.get() != b.get());
    CHECK_EQ(cache.size(), 2u);
}

TEST("in-tree assembler encodes the patch instructions") {
    auto a = make_assembler(Arch::X86_64);
    CHECK_EQ(a->assemble("nop", 0).value().size(), 1u);
    CHECK_EQ(a->assemble("int3", 0).value()[0], 0xCCu);
    CHECK_EQ(a->assemble("ret", 0).value()[0], 0xC3u);
    auto mov = a->assemble("mov rax, 0x1234", 0);
    CHECK(mov.ok());
    CHECK_EQ(mov.value()[0], 0x48u);  // REX.W
    CHECK_EQ(mov.value()[1], 0xB8u);  // mov rax, imm64
    // jmp is encoded relative to the given address.
    auto jmp = a->assemble("jmp 0x100", 0x100);
    CHECK(jmp.ok());
    CHECK_EQ(jmp.value()[0], 0xE9u);
}

int main() { return dede::test::run_all(); }
