// SPDX-License-Identifier: Apache-2.0
//
// Frame-pointer (rbp-chain) stack unwinding + a best-effort return-address check,
// computed from the machine state at the *current* tick. Because it reads live
// state rather than accumulating a forward-only shadow stack, the unwind is
// correct at any point reached by time-travel (seek/step_back) — unwind after
// stepping back and you get the stack as it was then.
//
// Scope/limits (be honest about them):
//  - Unwinding needs rbp-based frames; frameless (`-fomit-frame-pointer` / many
//    -O2 functions) or mid-prologue frames are not reconstructed (this is how
//    gdb/lldb unwind without CFI/DWARF).
//  - The integrity check is a BEST-EFFORT heuristic: a legitimate return address
//    is immediately preceded by a `call`, so a saved return address that is not
//    call-preceded is flagged (stack smashing / ROP / overwrite). It is byte-
//    level, so a determined attacker who sprays call-shaped bytes before the
//    target can evade it; an exact shadow-stack CFI (compare each ret against the
//    address the matching call pushed) is the documented next step.
#pragma once

#include <vector>

#include "dede/analysis/cfg.hpp"  // ByteReader
#include "dede/disasm/disassembler.hpp"

namespace dede {

struct StackFrame {
    Addr frame_ptr = 0;      // the rbp value for this frame
    Addr return_addr = 0;    // saved return address ([rbp+8])
    bool ret_call_preceded = false;  // is return_addr immediately after a `call`?
    bool is_base = false;    // outermost frame (saved rbp == 0); its return is the
                             // process entry, not a real caller — excluded from CFI
};

// Walk the rbp chain from `rbp` (with the live `rip` as the innermost pc), reading
// saved-rbp at [rbp] and return-addr at [rbp+8]. Stops on a null/garbage frame
// pointer, a non-increasing chain (loop guard), an unreadable slot, or `max`.
std::vector<StackFrame> unwind_stack(const IDisassembler& dis, const ByteReader& read,
                                     Addr rip, u64 rbp, std::size_t max_frames = 64);

// True if some `call` instruction ends exactly at `addr` (a valid return site).
bool is_call_preceded(const IDisassembler& dis, const ByteReader& read, Addr addr);

struct IntegrityReport {
    std::vector<StackFrame> frames;
    std::vector<Addr> violations;  // return addresses that are not call-preceded
    bool intact() const { return violations.empty(); }
};

// Unwind + flag every frame whose return address is not call-preceded.
IntegrityReport check_stack_integrity(const IDisassembler& dis, const ByteReader& read,
                                      Addr rip, u64 rbp, std::size_t max_frames = 64);

// Convenience overloads that build the disassembler from `arch` internally.
std::vector<StackFrame> unwind_stack(Arch arch, const ByteReader& read, Addr rip, u64 rbp,
                                     std::size_t max_frames = 64);
IntegrityReport check_stack_integrity(Arch arch, const ByteReader& read, Addr rip, u64 rbp,
                                      std::size_t max_frames = 64);

}  // namespace dede
