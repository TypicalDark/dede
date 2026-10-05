// SPDX-License-Identifier: Apache-2.0
#include "dede/analysis/cfg.hpp"

#include <algorithm>
#include <deque>
#include <set>
#include <sstream>

namespace dede {

const char* to_string(EdgeKind k) noexcept {
    switch (k) {
        case EdgeKind::Fallthrough: return "fallthrough";
        case EdgeKind::Taken: return "taken";
        case EdgeKind::NotTaken: return "not-taken";
        case EdgeKind::Jump: return "jump";
        case EdgeKind::Call: return "call";
    }
    return "?";
}

const BasicBlock* Cfg::block_at(Addr start) const {
    for (const auto& b : blocks)
        if (b.start == start) return &b;
    return nullptr;
}

namespace {

// Read up to 15 bytes for a decode attempt; empty if the first byte is unmapped.
std::vector<u8> read_insn_bytes(const ByteReader& read, Addr a) {
    std::vector<u8> buf;
    for (unsigned i = 0; i < 15; ++i) {
        auto b = read(a + i);
        if (!b) break;
        buf.push_back(*b);
    }
    return buf;
}

std::optional<Addr> direct_target(const DecodedInsn& in) {
    if (!in.operands.empty() && in.operands[0].kind == OpKind::Imm)
        return static_cast<Addr>(in.operands[0].imm);
    return std::nullopt;
}

}  // namespace

Cfg build_cfg(const IDisassembler& disasm, const ByteReader& read, Addr entry, std::size_t max_blocks) {
    Cfg cfg;
    cfg.entry = entry;

    // --- Phase 1: decode all reachable instructions and discover block leaders.
    std::map<Addr, DecodedInsn> insns;
    std::set<Addr> leaders{entry};
    std::set<Addr> swept;
    std::deque<Addr> wl{entry};
    while (!wl.empty() && insns.size() < max_blocks * 64) {
        Addr a = wl.front();
        wl.pop_front();
        if (swept.count(a)) continue;
        swept.insert(a);
        Addr pc = a;
        while (true) {
            if (insns.count(pc)) break;  // joins an already-decoded run
            auto bytes = read_insn_bytes(read, pc);
            if (bytes.empty()) break;
            auto r = disasm.decode_one(bytes.data(), bytes.size(), pc);
            if (!r) break;
            DecodedInsn in = r.value();
            Addr next = in.addr + in.size;
            insns.emplace(pc, in);
            if (in.cf.is_ret || in.mnemonic == "hlt") break;
            if (in.cf.is_branch) {
                if (auto t = direct_target(in)) { leaders.insert(*t); wl.push_back(*t); }
                if (in.cf.is_cond_branch) { leaders.insert(next); wl.push_back(next); }
                break;
            }
            // call falls through within the function; keep sweeping.
            pc = next;
        }
    }

    // --- Phase 2: build one block per leader, up to the next leader/terminator.
    for (Addr L : leaders) {
        if (cfg.blocks.size() >= max_blocks) break;
        if (!insns.count(L)) continue;
        BasicBlock bb;
        bb.start = L;
        Addr pc = L;
        while (insns.count(pc)) {
            const DecodedInsn& in = insns.at(pc);
            bb.insns.push_back(in);
            Addr next = in.addr + in.size;
            // A call is a reference to another function, not intraprocedural flow:
            // record it in `calls`, keep it out of the flow edges, and keep sweeping
            // (the call returns and falls through to the next instruction).
            if (in.cf.is_call)
                if (auto t = direct_target(in)) cfg.calls.emplace_back(L, *t);
            if (in.cf.is_ret || in.mnemonic == "hlt") { bb.terminates = true; break; }
            if (in.cf.is_branch) {
                auto t = direct_target(in);
                if (in.cf.is_cond_branch) {
                    if (t) cfg.edges.push_back({L, *t, EdgeKind::Taken});
                    cfg.edges.push_back({L, next, EdgeKind::NotTaken});
                } else if (t) {
                    cfg.edges.push_back({L, *t, EdgeKind::Jump});
                } else {
                    bb.terminates = true;  // indirect jump: unknown successor
                }
                break;
            }
            pc = next;
            if (leaders.count(pc)) {  // next instruction starts another block
                cfg.edges.push_back({L, pc, EdgeKind::Fallthrough});
                break;
            }
        }
        bb.end = pc;
        cfg.blocks.push_back(std::move(bb));
    }

    std::sort(cfg.blocks.begin(), cfg.blocks.end(),
              [](const BasicBlock& a, const BasicBlock& b) { return a.start < b.start; });
    return cfg;
}

std::string Cfg::to_dot() const {
    std::ostringstream os;
    os << "digraph cfg {\n  node [shape=box fontname=\"monospace\" fontsize=10];\n";
    for (const auto& b : blocks) {
        os << "  \"" << std::hex << b.start << "\" [label=\"";
        os << "loc_" << std::hex << b.start << "\\l";
        for (const auto& in : b.insns) os << in.text() << "\\l";
        os << "\"];\n";
    }
    for (const auto& e : edges) {
        const char* color = e.kind == EdgeKind::Taken ? "darkgreen"
                          : e.kind == EdgeKind::NotTaken ? "red"
                          : e.kind == EdgeKind::Call ? "blue" : "black";
        os << "  \"" << std::hex << e.from << "\" -> \"" << e.to
           << "\" [color=" << color << " label=\"" << to_string(e.kind) << "\"];\n";
    }
    os << "}\n";
    return os.str();
}

std::map<Addr, std::pair<int, int>> Cfg::layout() const {
    std::map<Addr, std::pair<int, int>> pos;
    std::map<Addr, int> depth;
    std::deque<Addr> q;
    if (!blocks.empty()) { depth[entry] = 0; q.push_back(entry); }

    // BFS assigns a row (depth); successor edges deepen.
    while (!q.empty()) {
        Addr a = q.front(); q.pop_front();
        for (const auto& e : edges) {
            if (e.from != a || e.kind == EdgeKind::Call) continue;
            if (!depth.count(e.to)) { depth[e.to] = depth[a] + 1; q.push_back(e.to); }
        }
    }
    // Any block not reached from entry gets a trailing row.
    int maxd = 0;
    for (auto& [a, d] : depth) maxd = std::max(maxd, d);
    for (const auto& b : blocks)
        if (!depth.count(b.start)) depth[b.start] = ++maxd;

    // Column = order among blocks sharing a row.
    std::map<int, int> col_counter;
    for (const auto& b : blocks) {
        int row = depth[b.start];
        int col = col_counter[row]++;
        pos[b.start] = {col, row};
    }
    return pos;
}

}  // namespace dede
