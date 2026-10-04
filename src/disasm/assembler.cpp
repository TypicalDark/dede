// SPDX-License-Identifier: Apache-2.0
//
// A compact in-tree x86-64 encoder. It covers the instructions the patch/macro
// path emits (nop/int3/ret/hlt, jmp rel32, mov r64, imm). When DEDE_WITH_ASMJIT
// is defined this whole file is replaced by the asmjit adapter (see
// asmjit_assembler.cpp); the interface is identical so callers never change.
#ifndef DEDE_WITH_ASMJIT

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

#include "dede/disasm/assembler.hpp"

namespace dede {
namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(std::string s) {
    auto issp = [](unsigned char c) { return std::isspace(c); };
    while (!s.empty() && issp(s.front())) s.erase(s.begin());
    while (!s.empty() && issp(s.back())) s.pop_back();
    return s;
}

bool parse_int(const std::string& tok, i64& out) {
    try {
        std::size_t pos = 0;
        out = std::stoll(tok, &pos, 0);  // base 0 => honours 0x / 0 prefixes
        return pos == tok.size();
    } catch (...) {
        return false;
    }
}

void put32(std::vector<u8>& v, u32 x) {
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<u8>((x >> (8 * i)) & 0xff));
}
void put64(std::vector<u8>& v, u64 x) {
    for (int i = 0; i < 8; ++i) v.push_back(static_cast<u8>((x >> (8 * i)) & 0xff));
}

class BuiltinAssembler final : public IAssembler {
public:
    std::string backend_name() const override { return "dede-builtin"; }

    Result<std::vector<u8>> assemble(const std::string& line, Addr at) const override {
        std::string s = trim(line);
        // strip trailing comment
        if (auto h = s.find(';'); h != std::string::npos) s = trim(s.substr(0, h));
        if (s.empty()) return std::vector<u8>{};

        std::string mnem, rest;
        if (auto sp = s.find(' '); sp != std::string::npos) {
            mnem = lower(s.substr(0, sp));
            rest = trim(s.substr(sp + 1));
        } else {
            mnem = lower(s);
        }

        if (mnem == "nop") return std::vector<u8>{0x90};
        if (mnem == "int3") return std::vector<u8>{0xCC};
        if (mnem == "ret") return std::vector<u8>{0xC3};
        if (mnem == "hlt") return std::vector<u8>{0xF4};

        if (mnem == "jmp") {
            i64 target = 0;
            if (!parse_int(rest, target)) return make_error("jmp: expected numeric target");
            std::vector<u8> out{0xE9};
            i64 rel = target - (static_cast<i64>(at) + 5);
            put32(out, static_cast<u32>(rel));
            return out;
        }

        if (mnem == "mov") {
            auto comma = rest.find(',');
            if (comma == std::string::npos) return make_error("mov: expected two operands");
            std::string dst = trim(rest.substr(0, comma));
            std::string src = trim(rest.substr(comma + 1));
            auto reg = reg_from_name(lower(dst));
            i64 imm = 0;
            if (!reg) return make_error("mov: unsupported destination '" + dst + "'");
            if (*reg == Reg::Rip || *reg == Reg::Rflags)
                return make_error("mov: cannot target rip/rflags");
            if (!parse_int(src, imm)) return make_error("mov: source must be an immediate");
            unsigned idx = static_cast<unsigned>(*reg);
            std::vector<u8> out;
            out.push_back(idx < 8 ? 0x48 : 0x49);           // REX.W (+B for r8-r15)
            out.push_back(static_cast<u8>(0xB8 + (idx & 7)));  // mov r64, imm64
            put64(out, static_cast<u64>(imm));
            return out;
        }

        return make_error("assembler: unsupported mnemonic '" + mnem + "'");
    }
};

}  // namespace

std::unique_ptr<IAssembler> make_assembler(Arch arch) {
    if (arch != Arch::X86_64) throw DedeError("make_assembler: only x86-64 is implemented");
    return std::make_unique<BuiltinAssembler>();
}

}  // namespace dede

#endif  // DEDE_WITH_ASMJIT
