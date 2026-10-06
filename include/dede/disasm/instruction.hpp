// SPDX-License-Identifier: Apache-2.0
//
// A decoded instruction in architecture-neutral C++ terms. The Capstone C API
// never escapes the disasm library; everything above sees only these types.
#pragma once

#include <string>
#include <vector>

#include "dede/common/cpu_state.hpp"  // Width
#include "dede/common/types.hpp"

namespace dede {

enum class OpKind { None, Reg, Imm, Mem, SegReg, Xmm };

// x86 segment registers (read by anti-VM checks via `mov ax, cs` etc.).
enum class SegReg : u8 { CS, SS, DS, ES, FS, GS };

// A memory operand of the form [base + index*scale + disp].
struct MemOperand {
    bool has_base = false;
    Reg base = Reg::Rax;
    bool has_index = false;
    Reg index = Reg::Rax;
    u32 scale = 1;
    i64 disp = 0;
    unsigned size = 0;  // access size in bytes
};

struct Operand {
    OpKind kind = OpKind::None;

    // Reg operand:
    Reg reg = Reg::Rax;
    Width width = Width::B8;

    // SegReg operand:
    SegReg seg = SegReg::CS;

    // Imm operand:
    i64 imm = 0;

    // Xmm operand: 0..15 (SSE/SSE2 128-bit vector register).
    int xmm = 0;

    // Mem operand:
    MemOperand mem{};

    unsigned size = 0;  // operand size in bytes (1/2/4/8)

    // False when this operand names a register the interpreter does not model
    // (e.g. ah/bh high bytes, segment or vector registers). Disassembly text is
    // still valid; the interpreter treats such an instruction as unsupported.
    bool supported = true;
};

// Control-flow role, derived from Capstone instruction groups.
struct CfInfo {
    bool is_branch = false;       // any jmp/jcc
    bool is_cond_branch = false;  // jcc
    bool is_call = false;
    bool is_ret = false;
};

struct DecodedInsn {
    Addr addr = 0;
    unsigned size = 0;
    std::vector<u8> bytes;
    std::string mnemonic;  // e.g. "mov"
    std::string op_str;    // e.g. "rax, 0x10"
    unsigned id = 0;       // Capstone instruction id (opaque to callers)
    std::vector<Operand> operands;
    CfInfo cf;

    std::string text() const {
        return op_str.empty() ? mnemonic : (mnemonic + " " + op_str);
    }
};

}  // namespace dede
