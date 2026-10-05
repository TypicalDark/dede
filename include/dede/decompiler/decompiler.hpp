// SPDX-License-Identifier: Apache-2.0
//
// The decompiler interface. The DEFAULT backend is dede's own native decompiler
// (src/decompiler/native.cpp): it lifts to IR, builds constant-folded expression
// trees, re-fuses cmp/jcc, recovers types/structs/arrays, and emits structured,
// goto-minimized C. Ghidra's native decompiler can be linked behind an Adapter as
// an optional differential oracle when DEDE_WITH_GHIDRA is set (feeding it bytes
// from the live trace via a LoadImage subclass). A linear per-instruction
// pseudocode view remains as a last-resort fallback. Passes over the decoded
// stream are Visitors.
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "dede/common/status.hpp"
#include "dede/disasm/disassembler.hpp"

namespace dede {

// A byte oracle over the whole loaded image (same shape as the CFG reader): it
// lets the decompiler read code-adjacent *data* — jump tables in .rodata — that
// may lie outside the `code` window handed to decompile().
using DecompReader = std::function<std::optional<u8>(Addr)>;

class IDecompiler {
public:
    virtual ~IDecompiler() = default;
    virtual std::string name() const = 0;

    // Decompile `code` (loaded at `addr`) into pseudocode text.
    virtual Result<std::string> decompile(const std::vector<u8>& code, Addr addr) = 0;

    // As above, but with a reader over the full image so jump tables outside the
    // `code` window are still recovered. The default ignores it (the bounded
    // `code` view is all some backends have), so existing callers keep working.
    virtual Result<std::string> decompile(const std::vector<u8>& code, Addr addr,
                                          const DecompReader& image) {
        (void)image;
        return decompile(code, addr);
    }
};

// Visitor (GoF) over decoded instructions. A decompiler pass implements this and
// is driven across the instruction stream; the stream does not know the passes.
class IInsnVisitor {
public:
    virtual ~IInsnVisitor() = default;
    virtual void visit_data(const DecodedInsn&) = 0;     // mov/lea/push/pop/...
    virtual void visit_arith(const DecodedInsn&) = 0;    // add/sub/and/.../shifts
    virtual void visit_branch(const DecodedInsn&) = 0;   // jmp/jcc
    virtual void visit_call(const DecodedInsn&) = 0;     // call
    virtual void visit_ret(const DecodedInsn&) = 0;      // ret
    virtual void visit_other(const DecodedInsn&) = 0;    // everything else
};

// Dispatch one instruction to the right visitor method (the "accept" side).
void accept(const DecodedInsn& in, IInsnVisitor& v);

// Factory: the Ghidra adapter when compiled in, else the linear fallback.
std::unique_ptr<IDecompiler> make_decompiler(IDisassembler& disasm);

}  // namespace dede
