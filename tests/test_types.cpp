// SPDX-License-Identifier: Apache-2.0
//
// Tests constraint-based type inference: pointer detection from a dereference,
// signedness from a signed jcc, parameter recovery from live-in argument
// registers, and the recovered signature.
#include <optional>
#include <vector>

#include "check.hpp"
#include "dede/disasm/disassembler.hpp"
#include "dede/types/types.hpp"

using namespace dede;
using namespace dede::types;

namespace {
FuncTypes infer(const std::vector<u8>& code) {
    auto dis = make_disassembler(Arch::X86_64);
    ByteReader read = [&code](Addr a) -> std::optional<u8> {
        if (a >= 0x1000 && a < 0x1000 + code.size()) return code[a - 0x1000];
        return std::nullopt;
    };
    return infer_function(*dis, read, 0x1000);
}
}  // namespace

TEST("infers pointer param from a dereference and signed param from a signed compare") {
    // mov rax,[rdi] ; cmp rax,rsi ; jl L ; mov rax,1 ; ret ; L: xor eax,eax ; ret
    FuncTypes ft = infer({0x48, 0x8B, 0x07, 0x48, 0x39, 0xF0, 0x7C, 0x07,
                          0x48, 0xC7, 0xC0, 0x01, 0, 0, 0, 0xC3, 0x31, 0xC0, 0xC3});
    CHECK_EQ(ft.params.size(), 2u);
    CHECK(ft.params[0].reg == Reg::Rdi);
    CHECK(ft.regs[Reg::Rdi].cls == TClass::Pointer);
    CHECK_EQ(c_type(ft.regs[Reg::Rdi]), std::string("void *"));
    CHECK(ft.params[1].reg == Reg::Rsi);
    CHECK(ft.regs[Reg::Rsi].sign == Sign::Signed);
    // signature names params by register and types them
    std::string sig = ft.signature();
    CHECK(sig.find("void * rdi") != std::string::npos);
    CHECK(sig.find("sub_1000") != std::string::npos);
}

TEST("movzx pins unsigned, movsx pins signed") {
    // movzx eax, byte [rdi]  -> eax unsigned 32; ret
    FuncTypes z = infer({0x0F, 0xB6, 0x07, 0xC3});
    CHECK(z.regs[Reg::Rax].sign == Sign::Unsigned);
    // movsx eax, byte [rdi] -> eax signed 32; ret
    FuncTypes s = infer({0x0F, 0xBE, 0x07, 0xC3});
    CHECK(s.regs[Reg::Rax].sign == Sign::Signed);
}

TEST("a leaf function with no args has a void parameter list") {
    // mov rax, 0x2a ; ret
    FuncTypes ft = infer({0x48, 0xC7, 0xC0, 0x2A, 0, 0, 0, 0xC3});
    CHECK(ft.params.empty());
    CHECK(ft.signature().find("(void)") != std::string::npos);
}

int main() { return dede::test::run_all(); }
