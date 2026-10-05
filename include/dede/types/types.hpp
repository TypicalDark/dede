// SPDX-License-Identifier: Apache-2.0
//
// A modest, TIE-style constraint-based type system (docs/DECOMPILER.md, M6). A
// three-axis lattice (class × width × sign) per register, refined by constraints
// generated from how values are USED: a memory-base register is a pointer, an
// operand's size pins its width, a mnemonic's flavour (movsx/movzx, signed vs
// unsigned jcc) pins its sign. Solved by meet toward Bottom (refinement) with a
// Top/Bottom conflict fallback. Feeds typed signatures into the decompiler.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "dede/analysis/cfg.hpp"
#include "dede/common/types.hpp"
#include "dede/disasm/disassembler.hpp"

namespace dede::types {

enum class TClass : unsigned char { Top, Integer, Pointer, Code, Bool, Bottom };
enum class Sign : unsigned char { Unknown, Signed, Unsigned };

struct LType {
    TClass cls = TClass::Top;
    unsigned char width = 0;  // bytes; 0 = unknown
    Sign sign = Sign::Unknown;
};

// meet = refine toward Bottom (combine two facts about the same value).
LType meet(LType a, LType b);
// The C spelling of a recovered type ("int64_t", "uint32_t", "void *", ...).
std::string c_type(const LType& t);

struct Param {
    Reg reg;
    LType type;
};

struct FuncTypes {
    Addr entry = 0;
    LType ret;
    std::vector<Param> params;       // in calling-convention (SysV) order
    std::map<Reg, LType> regs;       // inferred per-register view

    // "int64_t sub_<entry>(uint32_t a1, void *a2)".
    std::string signature() const;
};

// Infer types for the function at `entry` from its decoded instructions.
FuncTypes infer_function(const IDisassembler& dis, const ByteReader& read, Addr entry);

}  // namespace dede::types
