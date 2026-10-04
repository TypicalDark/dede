// SPDX-License-Identifier: Apache-2.0
//
// Control-flow-graph / code-flow analysis over a function, built from the live
// (possibly self-modified) byte image rather than a static file — the Ghidra-like
// "code flow" view. Produces basic blocks + typed edges, a graphviz-dot export,
// and a simple layered layout for the GUI to draw.
#pragma once

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "dede/disasm/disassembler.hpp"

namespace dede {

// Reads one guest byte; empty means unmapped (stops a sweep).
using ByteReader = std::function<std::optional<u8>(Addr)>;

enum class EdgeKind { Fallthrough, Taken, NotTaken, Jump, Call };
const char* to_string(EdgeKind k) noexcept;

struct BasicBlock {
    Addr start = 0;
    Addr end = 0;  // one past the last byte
    std::vector<DecodedInsn> insns;
    bool terminates = false;  // ends in ret/hlt/unknown with no successor
};

struct CfgEdge {
    Addr from = 0;  // source block start
    Addr to = 0;    // target block start (or call target)
    EdgeKind kind = EdgeKind::Fallthrough;
};

struct Cfg {
    Addr entry = 0;
    std::vector<BasicBlock> blocks;
    std::vector<CfgEdge> edges;

    const BasicBlock* block_at(Addr start) const;

    // Graphviz DOT (feed to `dot -Tsvg`); nodes labelled with disassembly.
    std::string to_dot() const;

    // A simple layered (BFS-depth) layout: block start -> (col, row). Enough for
    // the GUI to place nodes without pulling in a graph library.
    std::map<Addr, std::pair<int, int>> layout() const;
};

// Build the CFG of the function at `entry`. Follows direct branches; an indirect
// branch/ret/hlt/undecodable byte ends a block. Bounded by max_blocks.
Cfg build_cfg(const IDisassembler& disasm, const ByteReader& read, Addr entry,
              std::size_t max_blocks = 1024);

}  // namespace dede
