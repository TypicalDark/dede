// SPDX-License-Identifier: Apache-2.0
#include "dede/symbols/siglib.hpp"

namespace dede::sym {

Signature make_signature(const std::string& name, const std::vector<u8>& bytes,
                         const std::vector<std::pair<std::size_t, std::size_t>>& wildcards) {
    Signature s;
    s.name = name;
    s.pattern = bytes;
    s.care.assign(bytes.size(), true);
    for (const auto& [off, len] : wildcards)
        for (std::size_t i = off; i < off + len && i < s.care.size(); ++i) s.care[i] = false;
    return s;
}

bool match_at(const Signature& sig, const ByteReader& read, Addr addr) {
    for (std::size_t i = 0; i < sig.pattern.size(); ++i) {
        if (!sig.care[i]) continue;             // wildcard byte
        auto b = read(addr + i);
        if (!b || *b != sig.pattern[i]) return false;
    }
    return !sig.pattern.empty();
}

std::optional<std::string> identify(const std::vector<Signature>& sigs,
                                    const ByteReader& read, Addr addr) {
    for (const auto& s : sigs)
        if (match_at(s, read, addr)) return s.name;
    return std::nullopt;
}

const std::vector<Signature>& starter_library() {
    // A synthetic starter set. Real deployments generate signatures from library
    // .o/.a files; these demonstrate the masked-pattern mechanism. The call's
    // rel32 displacement (4 bytes after the 0xE8 opcode) is wildcarded so the
    // same routine matches whatever address it is linked at.
    static const std::vector<Signature> lib = [] {
        std::vector<Signature> v;
        // a tiny "wrapper" idiom: endbr64; jmp rel32  -> PLT-style thunk
        v.push_back(make_signature("plt_thunk",
            {0xF3, 0x0F, 0x1E, 0xFA, 0xE9, 0x00, 0x00, 0x00, 0x00},
            {{5, 4}}));  // wildcard the jmp rel32
        return v;
    }();
    return lib;
}

}  // namespace dede::sym
