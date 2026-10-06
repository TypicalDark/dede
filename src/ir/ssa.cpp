// SPDX-License-Identifier: Apache-2.0
#include "dede/ir/ssa.hpp"

#include <algorithm>
#include <deque>
#include <unordered_map>

namespace dede::ir {
namespace {

// Reverse-postorder numbering over the successor graph from entry.
std::vector<Addr> reverse_postorder(Addr entry, const std::map<Addr, std::vector<Addr>>& succ,
                                    const std::set<Addr>& universe) {
    std::vector<Addr> post;
    std::set<Addr> seen;
    // iterative DFS postorder
    std::vector<std::pair<Addr, std::size_t>> stack;
    stack.push_back({entry, 0});
    seen.insert(entry);
    while (!stack.empty()) {
        auto& [n, i] = stack.back();
        auto it = succ.find(n);
        if (it != succ.end() && i < it->second.size()) {
            Addr s = it->second[i++];
            if (universe.count(s) && !seen.count(s)) { seen.insert(s); stack.push_back({s, 0}); }
        } else {
            post.push_back(n);
            stack.pop_back();
        }
    }
    std::reverse(post.begin(), post.end());
    return post;
}

}  // namespace

std::map<Addr, Addr> dominator_tree(const std::vector<Addr>& nodes, Addr entry,
                                    const std::map<Addr, std::vector<Addr>>& succ) {
    std::set<Addr> universe(nodes.begin(), nodes.end());
    universe.insert(entry);

    // Reverse postorder gives each reachable node a number; predecessors come
    // from inverting the (reachable) successor edges.
    std::vector<Addr> rpo = reverse_postorder(entry, succ, universe);
    std::unordered_map<Addr, int> num;
    for (int i = 0; i < static_cast<int>(rpo.size()); ++i) num[rpo[i]] = i;

    std::map<Addr, std::vector<Addr>> preds;
    for (Addr n : rpo) {
        auto it = succ.find(n);
        if (it == succ.end()) continue;
        for (Addr s : it->second)
            if (num.count(s)) preds[s].push_back(n);
    }

    const int kUndef = -1;
    std::unordered_map<Addr, int> idom_n;  // idom as rpo index
    for (Addr n : rpo) idom_n[n] = kUndef;
    idom_n[entry] = num[entry];

    auto intersect = [&](Addr b1, Addr b2) {
        int f1 = num[b1], f2 = num[b2];
        while (f1 != f2) {
            while (f1 > f2) f1 = idom_n[rpo[f1]];  // higher rpo index = later = walk up
            while (f2 > f1) f2 = idom_n[rpo[f2]];
        }
        return rpo[f1];
    };

    bool changed = true;
    while (changed) {
        changed = false;
        for (Addr b : rpo) {
            if (b == entry) continue;
            Addr new_idom = 0;
            bool have = false;
            for (Addr p : preds[b]) {
                if (idom_n[p] == kUndef) continue;
                if (!have) { new_idom = p; have = true; }
                else new_idom = intersect(p, new_idom);
            }
            if (have && idom_n[b] != num[new_idom]) { idom_n[b] = num[new_idom]; changed = true; }
        }
    }

    std::map<Addr, Addr> idom;
    for (Addr n : rpo) idom[n] = (idom_n[n] == kUndef) ? n : rpo[idom_n[n]];
    idom[entry] = entry;
    return idom;
}

bool dominates(const std::map<Addr, Addr>& idom, Addr a, Addr b) {
    if (a == b) return true;
    auto it = idom.find(b);
    if (it == idom.end()) return false;
    Addr cur = b;
    for (;;) {
        auto p = idom.find(cur);
        if (p == idom.end()) return false;
        if (p->second == cur) return false;  // reached entry without finding a
        cur = p->second;
        if (cur == a) return true;
    }
}

std::map<Addr, std::set<Addr>> dominance_frontier(const std::vector<Addr>& nodes,
                                                  const std::map<Addr, Addr>& idom,
                                                  const std::map<Addr, std::vector<Addr>>& succ) {
    // Build predecessors restricted to nodes present in the idom tree.
    std::map<Addr, std::vector<Addr>> preds;
    for (Addr n : nodes) {
        auto it = succ.find(n);
        if (it == succ.end()) continue;
        for (Addr s : it->second)
            if (idom.count(s)) preds[s].push_back(n);
    }
    std::map<Addr, std::set<Addr>> df;
    for (Addr b : nodes) df[b];  // ensure every node has an (empty) entry
    for (Addr b : nodes) {
        auto pit = preds.find(b);
        if (pit == preds.end() || pit->second.size() < 2) continue;  // joins only
        auto ib = idom.find(b);
        if (ib == idom.end()) continue;
        for (Addr p : pit->second) {
            Addr runner = p;
            while (runner != ib->second && idom.count(runner)) {
                df[runner].insert(b);
                Addr next = idom.at(runner);
                if (next == runner) break;  // entry
                runner = next;
            }
        }
    }
    return df;
}

std::map<Addr, std::set<int>> place_phis(const std::map<int, std::set<Addr>>& def_sites,
                                         const std::map<Addr, std::set<Addr>>& df) {
    std::map<Addr, std::set<int>> phis;
    for (const auto& [var, sites] : def_sites) {
        std::set<Addr> has_phi;
        std::deque<Addr> work(sites.begin(), sites.end());
        std::set<Addr> in_work(sites.begin(), sites.end());
        while (!work.empty()) {
            Addr n = work.front();
            work.pop_front();
            auto it = df.find(n);
            if (it == df.end()) continue;
            for (Addr y : it->second) {
                if (has_phi.insert(y).second) {
                    phis[y].insert(var);
                    if (!sites.count(y) && !in_work.count(y)) { work.push_back(y); in_work.insert(y); }
                }
            }
        }
    }
    return phis;
}

}  // namespace dede::ir
