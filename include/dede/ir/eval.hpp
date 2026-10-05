// SPDX-License-Identifier: Apache-2.0
//
// A reference evaluator for the IR — executes a straight-line list of Insns
// against a register file, flag set, and memory provided via callbacks. Used by
// the differential-execution test (interpret an instruction, interpret its lifted
// IR, assert identical register/flag/memory effects) and, later, by constant-
// folding/validation passes.
#pragma once

#include <functional>
#include <optional>
#include <vector>

#include "dede/ir/ir.hpp"

namespace dede::ir {

struct EvalEnv {
    std::function<u64(Reg)> get_reg;                 // full 64-bit register
    std::function<void(Reg, u64)> set_reg;           // full 64-bit write
    std::function<bool(Flag)> get_flag;
    std::function<void(Flag, bool)> set_flag;
    std::function<u64(Addr, unsigned)> load;         // size bytes
    std::function<void(Addr, unsigned, u64)> store;  // size bytes
};

// Execute `code`. Returns a branch/call target if the block ended in one.
std::optional<Addr> eval(const std::vector<Insn>& code, EvalEnv& env);

}  // namespace dede::ir
