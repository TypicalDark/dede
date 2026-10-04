// SPDX-License-Identifier: Apache-2.0
//
// The decompiler interface. The real backend is Ghidra's native decompiler,
// linked behind an Adapter when DEDE_WITH_GHIDRA is set (feeding it bytes from
// the live trace via a LoadImage subclass). Without it, a linear-pseudocode
// fallback gives a readable, structured view so `decompile` always does
// something honest. Passes over the decoded stream are Visitors.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "dede/common/status.hpp"
#include "dede/disasm/disassembler.hpp"

namespace dede {

class IDecompiler {
public:
    virtual ~IDecompiler() = default;
    virtual std::string name() const = 0;

    // Decompile `code` (loaded at `addr`) into pseudocode text.
    virtual Result<std::string> decompile(const std::vector<u8>& code, Addr addr) = 0;
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
