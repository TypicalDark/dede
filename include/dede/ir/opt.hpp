// SPDX-License-Identifier: Apache-2.0
//
// Data-flow simplification over the IR (Batch 5, T5.2). `simplify_block` runs a
// semantics-preserving optimizer over one basic block's straight-line Insn list:
//
//   * constant folding + constant propagation (a value known constant is
//     substituted and arithmetic over constants is evaluated at analysis time),
//   * copy propagation (a register/temp that merely aliases another value is
//     forwarded to its uses so the copy itself becomes dead),
//   * common-subexpression elimination (identical pure computations are
//     value-numbered and computed once), and
//   * dead-code elimination (pure value defs with no remaining use are dropped;
//     Store / Call / branch / Intrinsic side effects are always kept).
//
// Within a basic block there are no control-flow joins, so every definition is
// effectively in SSA form already (temps are single-assignment; a register's
// "current value" is tracked as it is rewritten). Register and flag values that
// the block computes are re-materialized at its exit so the block's observable
// effect — exit register/flag state, memory writes, and the terminating
// branch/condition — is unchanged. That invariant is checked by differential
// evaluation in tests/test_ir.cpp: the optimized block evaluates bit-identically
// to the original for every seeded input state.
//
// Cross-block value propagation (through phi nodes placed via the dominance
// frontier) builds on ir/ssa.hpp; the decompiler currently applies this
// optimizer per basic block.
#pragma once

#include <vector>

#include "dede/common/types.hpp"
#include "dede/ir/ir.hpp"

namespace dede::ir {

struct OptStats {
    unsigned folded = 0;      // constant sub-expressions evaluated
    unsigned propagated = 0;  // copy/const uses forwarded
    unsigned cse = 0;         // redundant computations reused
    unsigned dce = 0;         // dead definitions removed
    unsigned before = 0;      // instruction count in
    unsigned after = 0;       // instruction count out
};

// Simplify one basic block. Registers and flags are treated as live out of the
// block (conservative: a successor may read any of them), so only values whose
// definition is killed before any use are removed. Pure arithmetic and all
// flag-producer ops are preserved in place, so the decompiler's cmp/jcc
// re-fusion still sees them. `cse` enables common-subexpression elimination
// (safe for the standalone optimizer; the decompiler disables it so a flag-
// feeding sub/and is never merged away before re-fusion reads it). Blocks
// containing a Call, indirect branch, or Intrinsic are returned unchanged (their
// clobber/aliasing effects are out of this pass's conservative model).
std::vector<Insn> simplify_block(const std::vector<Insn>& code, bool cse = true,
                                 OptStats* stats = nullptr);

}  // namespace dede::ir
