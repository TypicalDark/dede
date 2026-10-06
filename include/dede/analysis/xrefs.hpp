// SPDX-License-Identifier: Apache-2.0
//
// Cross-reference (xref) index + whole-image function discovery over the live
// byte image. Xrefs are the backbone of navigation ("who calls / reads / writes
// this?"): a linear sweep decodes a range and records code references (direct
// call/jump targets) and data references (rip-relative and absolute memory
// operands, plus address-taking `lea`). Function discovery unions caller-supplied
// seeds (loader symbols), call targets from the xref sweep, and prologue-
// signature matches — so functions reached only indirectly are still found.
#pragma once

#include <cstdint>
#include <vector>

#include "dede/analysis/cfg.hpp"  // ByteReader
#include "dede/disasm/disassembler.hpp"

namespace dede {

enum class XrefKind : u8 { Call, Jump, Read, Write, AddrOf };
const char* to_string(XrefKind k) noexcept;

struct Xref {
    Addr from = 0;             // the referencing instruction
    Addr to = 0;               // the referenced address
    XrefKind kind = XrefKind::Call;
};

// Linear-sweep decode of [lo, hi) collecting code + data xrefs. Undecodable
// bytes advance by one (a linear sweep desyncs on data; that is inherent and
// why dynamic/CFG views complement it).
std::vector<Xref> build_xrefs(const IDisassembler& dis, const ByteReader& read, Addr lo, Addr hi);
std::vector<Xref> build_xrefs(Arch arch, const ByteReader& read, Addr lo, Addr hi);

// Every xref that targets `addr` (the "references to" query).
std::vector<Xref> refs_to(const std::vector<Xref>& xrefs, Addr addr);

// Whole-image function discovery: the sorted/unique union of `seeds` (e.g. loader
// symbols), call targets from an xref sweep of [lo, hi), and prologue-signature
// matches (`push rbp; mov rbp,rsp`, `endbr64`) that decode cleanly at an aligned
// position. Catches functions reached only indirectly or not reached from a
// chosen entry at all.
std::vector<Addr> discover_functions(const IDisassembler& dis, const ByteReader& read, Addr lo, Addr hi,
                                     const std::vector<Addr>& seeds = {});
std::vector<Addr> discover_functions(Arch arch, const ByteReader& read, Addr lo, Addr hi,
                                     const std::vector<Addr>& seeds = {});

}  // namespace dede
