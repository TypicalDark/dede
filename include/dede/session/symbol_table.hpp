// SPDX-License-Identifier: Apache-2.0
//
// A tiny symbol table so disassembly, the stack view, and the CFG can show names
// instead of bare addresses. Kept a separate component (not loose methods on the
// Facade) so it can be shared and tested on its own.
#pragma once

#include <map>
#include <optional>
#include <string>

#include "dede/common/types.hpp"

namespace dede {

class SymbolTable {
public:
    void add(Addr a, std::string name) { syms_[a] = std::move(name); }
    void remove(Addr a) { syms_.erase(a); }
    void clear() { syms_.clear(); }

    // Exact name at an address, if any.
    const std::string* at(Addr a) const {
        auto it = syms_.find(a);
        return it == syms_.end() ? nullptr : &it->second;
    }

    // Nearest symbol at or before `a`, as "name+0xoff" (or nullopt if none).
    std::optional<std::string> describe(Addr a) const {
        if (syms_.empty()) return std::nullopt;
        auto it = syms_.upper_bound(a);
        if (it == syms_.begin()) return std::nullopt;
        --it;
        u64 off = a - it->first;
        return off ? (it->second + "+0x" + to_hex(off)) : it->second;
    }

    const std::map<Addr, std::string>& all() const { return syms_; }
    std::size_t size() const { return syms_.size(); }

private:
    static std::string to_hex(u64 v) {
        static const char* d = "0123456789abcdef";
        if (!v) return "0";
        std::string s;
        while (v) { s = d[v & 0xf] + s; v >>= 4; }
        return s;
    }
    std::map<Addr, std::string> syms_;
};

}  // namespace dede
