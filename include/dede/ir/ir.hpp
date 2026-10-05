// SPDX-License-Identifier: Apache-2.0
//
// dede's decompiler IR — one small, orthogonal, P-code-flavoured operation set
// over typed Varnodes (register / constant / temporary / flag). Machine
// instructions lift to a list of these; every later decompiler pass (SSA,
// data-flow, structuring, typing) works on this uniform form rather than on
// x86 quirks. Flags are explicit Varnodes written by explicit ops, so a later
// pass can re-fuse a cmp/jcc pair back into a high-level comparison.
//
// Design per docs/DECOMPILER.md (M1). The lifter is derived from the interpreter
// semantics and validated by differential execution (tests/test_ir.cpp).
#pragma once

#include <string>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::ir {

enum class Op : unsigned char {
    Copy,        // out = a
    Load,        // out = mem[a]           (size = out.size)
    Store,       // mem[a] = b             (size = b.size)
    Subpiece,    // out = (a >> (b*8)) truncated to out.size
    Zext,        // out = zero-extend(a)
    Sext,        // out = sign-extend(a)
    Add, Sub, Mul, And, Or, Xor, Shl, Shr, Sar, Neg, Not,
    // comparisons / flag producers (out is a 1-byte bool/flag)
    Equal, NotEqual, Less, SLess, LessEqual, SLessEqual,
    Carry,       // unsigned add carry out of top bit
    SCarry,      // signed add overflow (OF for add)
    SBorrow,     // signed sub overflow (OF for sub)
    SignBit,     // top bit of a
    Parity,      // x86 PF of low byte of a
    AuxAdd,      // AF for a+b
    AuxSub,      // AF for a-b
    IsZero,      // out = (a == 0)
    // control flow
    Branch,      // goto a (const target)
    CBranch,     // if (a) goto b
    BranchInd,   // goto a (computed)
    Call,        // call a
    Return,      // ret
    Intrinsic,   // unmodeled effect (note holds the mnemonic)
};

enum class VnKind : unsigned char { None, Const, Reg, Temp, Flag };
enum class Flag : unsigned char { CF, PF, AF, ZF, SF, OF };

struct Vn {
    VnKind kind = VnKind::None;
    long long cval = 0;        // Const value
    Reg reg = Reg::Rax;        // Reg
    int temp = 0;              // Temp id
    Flag flag = Flag::CF;      // Flag
    unsigned char size = 8;    // bytes (1/2/4/8); flags are 1

    static Vn none() { return {}; }
    static Vn k(long long v, unsigned char sz = 8) { Vn n; n.kind = VnKind::Const; n.cval = v; n.size = sz; return n; }
    static Vn r(Reg rr, unsigned char sz = 8) { Vn n; n.kind = VnKind::Reg; n.reg = rr; n.size = sz; return n; }
    static Vn t(int id, unsigned char sz = 8) { Vn n; n.kind = VnKind::Temp; n.temp = id; n.size = sz; return n; }
    static Vn f(Flag ff) { Vn n; n.kind = VnKind::Flag; n.flag = ff; n.size = 1; return n; }

    bool is_none() const { return kind == VnKind::None; }
};

struct Insn {
    Op op;
    Vn out;         // destination (none if the op has no value output)
    Vn a, b;        // inputs
    Addr addr = 0;  // source machine-instruction address
    std::string note;
};

struct Block {
    Addr start = 0;
    std::vector<Insn> code;
};

const char* to_string(Op op) noexcept;
std::string pretty(const Vn& v);
std::string pretty(const Insn& in);
std::string pretty(const Block& b);

}  // namespace dede::ir
