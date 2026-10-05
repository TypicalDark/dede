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

// A recovered field of an aggregate the pointer points at: the dereference
// offset, the access width, and whether the loaded value is itself a pointer.
struct Field {
    i64 offset = 0;
    unsigned char width = 8;
    Sign sign = Sign::Unknown;
    bool is_pointer = false;
};

// A struct or array recovered from how a pointer is dereferenced within the
// function (ASI-lite: cluster `[p+off]` accesses into fields; `[p+idx*scale]`
// into an array). Intra-function only — no nested/recursive-type recovery yet.
struct Aggregate {
    bool is_array = false;
    unsigned stride = 0;             // array element stride (bytes)
    std::vector<Field> fields;       // struct fields, unique + sorted by offset
    std::string tag;                 // C tag, e.g. "s_rdi"

    const Field* field_at(i64 off) const {
        for (const auto& f : fields) if (f.offset == off) return &f;
        return nullptr;
    }
};

struct FuncTypes {
    Addr entry = 0;
    LType ret;
    std::vector<Param> params;             // in calling-convention (SysV) order
    std::map<Reg, LType> regs;             // inferred per-register view
    std::map<Reg, Aggregate> aggregates;   // recovered struct/array per pointer base

    // "int64_t sub_<entry>(uint32_t a1, void *a2)".
    std::string signature() const;
    // C `struct`/typedef definitions for the recovered aggregates (may be empty),
    // emitted above the function body.
    std::string aggregate_defs() const;
};

// Infer types for the function at `entry` from its decoded instructions.
FuncTypes infer_function(const IDisassembler& dis, const ByteReader& read, Addr entry);

}  // namespace dede::types
