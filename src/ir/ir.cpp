// SPDX-License-Identifier: Apache-2.0
#include "dede/ir/ir.hpp"

#include <cstdio>
#include <sstream>

namespace dede::ir {

const char* to_string(Op op) noexcept {
    switch (op) {
        case Op::Copy: return "copy";
        case Op::Load: return "load";
        case Op::Store: return "store";
        case Op::Subpiece: return "subpiece";
        case Op::Zext: return "zext";
        case Op::Sext: return "sext";
        case Op::Add: return "add";
        case Op::Sub: return "sub";
        case Op::Mul: return "mul";
        case Op::And: return "and";
        case Op::Or: return "or";
        case Op::Xor: return "xor";
        case Op::Shl: return "shl";
        case Op::Shr: return "shr";
        case Op::Sar: return "sar";
        case Op::Neg: return "neg";
        case Op::Not: return "not";
        case Op::Equal: return "==";
        case Op::NotEqual: return "!=";
        case Op::Less: return "<u";
        case Op::SLess: return "<s";
        case Op::LessEqual: return "<=u";
        case Op::SLessEqual: return "<=s";
        case Op::Carry: return "carry";
        case Op::SCarry: return "scarry";
        case Op::SBorrow: return "sborrow";
        case Op::SignBit: return "signbit";
        case Op::Parity: return "parity";
        case Op::AuxAdd: return "auxadd";
        case Op::AuxSub: return "auxsub";
        case Op::IsZero: return "iszero";
        case Op::Branch: return "branch";
        case Op::CBranch: return "cbranch";
        case Op::BranchInd: return "branchind";
        case Op::Call: return "call";
        case Op::Return: return "return";
        case Op::Intrinsic: return "intrinsic";
    }
    return "?";
}

std::string pretty(const Vn& v) {
    switch (v.kind) {
        case VnKind::None: return "-";
        case VnKind::Const: {
            char b[32];
            std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v.cval);
            return b;
        }
        case VnKind::Reg: return std::string(reg_name(v.reg)) + ":" + std::to_string(v.size);
        case VnKind::Temp: return "t" + std::to_string(v.temp) + ":" + std::to_string(v.size);
        case VnKind::Flag: {
            const char* n[] = {"CF", "PF", "AF", "ZF", "SF", "OF"};
            return n[static_cast<int>(v.flag)];
        }
    }
    return "?";
}

std::string pretty(const Insn& in) {
    std::ostringstream o;
    if (in.op == Op::Store) {
        o << "mem[" << pretty(in.a) << "] = " << pretty(in.b);
        return o.str();
    }
    if (in.op == Op::Intrinsic) { o << "intrinsic(" << in.note << ")"; return o.str(); }
    if (in.op == Op::Branch || in.op == Op::Call || in.op == Op::BranchInd)
        { o << to_string(in.op) << " " << pretty(in.a); return o.str(); }
    if (in.op == Op::CBranch) { o << "if " << pretty(in.a) << " goto " << pretty(in.b); return o.str(); }
    if (in.op == Op::Return) return "return";
    if (!in.out.is_none()) o << pretty(in.out) << " = ";
    o << to_string(in.op);
    if (!in.a.is_none()) o << " " << pretty(in.a);
    if (!in.b.is_none()) o << ", " << pretty(in.b);
    return o.str();
}

std::string pretty(const Block& b) {
    std::ostringstream o;
    char h[32];
    std::snprintf(h, sizeof h, "block 0x%llx:\n", (unsigned long long)b.start);
    o << h;
    for (const auto& in : b.code) o << "  " << pretty(in) << "\n";
    return o.str();
}

}  // namespace dede::ir
