// SPDX-License-Identifier: Apache-2.0
//
// SSA foundations over a control-flow graph (Batch 5, T5.1): a dominator tree
// (Cooper-Harvey-Kennedy iterative algorithm), dominance frontiers, and Cytron
// phi placement. These are the textbook preconditions for cross-block data-flow
// — a value's definitions in different blocks meet at a join only through a phi
// placed on the iterated dominance frontier of its definition sites.
//
// The graph is given abstractly (node list + entry + successor adjacency keyed
// by Addr) so this works off the analysis `Cfg` without depending on it, and so
// the same code serves post-dominators (pass the reverse graph with a virtual
// exit as entry). The per-basic-block optimizer in ir/opt.hpp consumes the
// straight-line (no-join) case today; this module is the join-aware extension.
#pragma once

#include <map>
#include <set>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::ir {

// Immediate-dominator tree: idom[n] is n's immediate dominator; idom[entry] ==
// entry. Unreachable nodes are omitted. Successors are given per node; the node
// list fixes the universe (order does not matter).
std::map<Addr, Addr> dominator_tree(const std::vector<Addr>& nodes, Addr entry,
                                    const std::map<Addr, std::vector<Addr>>& succ);

// True if a dominates b (walking b up the idom tree to a). a dominates itself.
bool dominates(const std::map<Addr, Addr>& idom, Addr a, Addr b);

// Dominance frontier per node: DF[n] = the nodes where n's dominance stops —
// the classic join points. Needs the idom tree and the successor adjacency.
std::map<Addr, std::set<Addr>> dominance_frontier(const std::vector<Addr>& nodes,
                                                  const std::map<Addr, Addr>& idom,
                                                  const std::map<Addr, std::vector<Addr>>& succ);

// Cytron phi placement: given, per variable id, the set of blocks that define it,
// return the set of variable ids that need a phi at each block (iterated
// dominance frontier of the definition sites). Variable ids are opaque ints
// (e.g. a register or stack-slot number).
std::map<Addr, std::set<int>> place_phis(const std::map<int, std::set<Addr>>& def_sites,
                                         const std::map<Addr, std::set<Addr>>& df);

}  // namespace dede::ir
