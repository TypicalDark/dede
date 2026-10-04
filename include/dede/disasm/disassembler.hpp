// SPDX-License-Identifier: Apache-2.0
//
// The disassembler interface (Strategy: swap Capstone for another decoder) and
// a Flyweight decode cache. The concrete Capstone adapter lives in the .cpp so
// the C API never leaks.
#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "dede/common/status.hpp"
#include "dede/disasm/instruction.hpp"

namespace dede {

// Strategy interface over a disassembler backend.
class IDisassembler {
public:
    virtual ~IDisassembler() = default;

    // Decode a single instruction at `addr` from `code` (code[0] is the byte at
    // `addr`). Returns an error if the bytes do not form a valid instruction.
    virtual Result<DecodedInsn> decode_one(const u8* code, std::size_t len,
                                           Addr addr) const = 0;

    // Decode up to `max` instructions (0 = until the buffer is exhausted).
    virtual std::vector<DecodedInsn> decode(const u8* code, std::size_t len,
                                            Addr addr, std::size_t max) const = 0;

    virtual Arch arch() const = 0;
};

// Factory for the default (Capstone) disassembler for a given architecture.
std::unique_ptr<IDisassembler> make_disassembler(Arch arch);

// Flyweight: share decoded instructions across repeated addresses. Keyed by
// (addr, first bytes) so that self-modifying code — where the same address holds
// different bytes over time — is correctly versioned rather than aliased.
class DecodeCache {
public:
    explicit DecodeCache(IDisassembler& disasm) : disasm_(disasm) {}

    // Decode at `addr`, returning a shared, cached instruction when the bytes
    // match a previous decode at that address.
    std::shared_ptr<const DecodedInsn> at(const u8* code, std::size_t len, Addr addr);

    void invalidate(Addr addr);
    void clear() { cache_.clear(); }
    std::size_t size() const noexcept { return cache_.size(); }

private:
    struct Key {
        Addr addr;
        u64 tag;  // hash of the leading bytes — distinguishes code versions
        bool operator==(const Key& o) const { return addr == o.addr && tag == o.tag; }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return std::hash<u64>{}(k.addr) ^ (std::hash<u64>{}(k.tag) << 1);
        }
    };

    IDisassembler& disasm_;
    std::unordered_map<Key, std::shared_ptr<const DecodedInsn>, KeyHash> cache_;
};

}  // namespace dede
