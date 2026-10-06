// SPDX-License-Identifier: Apache-2.0
//
// FLIRT-style library-function signatures (Batch 6, T6.1): a masked byte-pattern
// matcher that names known library code regardless of where it was linked.
// Each signature is a byte pattern with a per-byte mask; masked-out bytes
// (wildcards) cover relocation-/link-address-dependent fields — notably the
// rel32 displacement of a `call`/`jmp` — so the same function matches across
// builds linked at different addresses. This is the mechanism IDA's FLIRT and
// Ghidra's function-ID use to turn statically-linked library code back into
// named symbols; here it is a framework plus a small starter set.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "dede/analysis/cfg.hpp"  // ByteReader
#include "dede/common/types.hpp"

namespace dede::sym {

struct Signature {
    std::string name;
    std::vector<u8> pattern;    // expected bytes
    std::vector<bool> care;     // care[i] == false => wildcard (any byte matches)
};

// Build a signature from a function's bytes, wildcarding the given [offset,len)
// byte ranges (e.g. rel32 displacement fields that vary by link address).
Signature make_signature(const std::string& name, const std::vector<u8>& bytes,
                         const std::vector<std::pair<std::size_t, std::size_t>>& wildcards);

// Does `sig` match the bytes at `addr`?
bool match_at(const Signature& sig, const ByteReader& read, Addr addr);

// First signature that matches at `addr`, or nullopt.
std::optional<std::string> identify(const std::vector<Signature>& sigs,
                                    const ByteReader& read, Addr addr);

// A small starter library (synthetic, for demonstration/tests).
const std::vector<Signature>& starter_library();

}  // namespace dede::sym
