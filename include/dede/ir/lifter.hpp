// SPDX-License-Identifier: Apache-2.0
//
// Lift decoded x86-64 instructions / basic blocks into dede IR (see ir.hpp).
#pragma once

#include <vector>

#include "dede/analysis/cfg.hpp"         // BasicBlock
#include "dede/disasm/instruction.hpp"   // DecodedInsn
#include "dede/ir/ir.hpp"

namespace dede::ir {

std::vector<Insn> lift_insn(const DecodedInsn& in);
Block lift_block(const BasicBlock& bb);

}  // namespace dede::ir
