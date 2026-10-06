// SPDX-License-Identifier: Apache-2.0
//
// Higher-level recovery passes over decoded code, aimed at obfuscation and C++
// constructs that a flat-machine-code view normally loses:
//
//   * scan_stack_strings  — the compile-time string-obfuscation idiom (a short
//     loop that XOR-decrypts a buffer in place). We detect the *emitted* idiom,
//     not the source template, so the verdict is deliberately bounded.
//   * find_clones         — operand-normalized, rolling-hash window clustering
//     that spots the same instruction fragment inlined at several call sites
//     (register renaming does not hide it, because operands are normalized to
//     their kind, not their specific register).
//   * scan_vtables        — runs of code pointers in a read-only region, i.e.
//     C++ virtual-method tables, with the Itanium type_info class name when the
//     ABI layout is present.
//
// Everything works off a ByteReader + Arch, so this stays in dede_analysis with
// no dependency back into session. The *dynamic* half of virtual-call
// resolution (observing indirect-call targets at run time) lives in
// include/dede/session/vcall_tracker.hpp, which binds to the run-point system.
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "dede/analysis/scan.hpp"  // Finding
#include "dede/common/types.hpp"
#include "dede/disasm/disassembler.hpp"

namespace dede {

// --- T4.1 stack-string / compile-time obfuscation ---------------------------

// Detect the XOR-decrypt-loop idiom in [lo, hi): a short loop (closed by a
// backward conditional branch) whose body both XORs and stores to memory — the
// shape emitted by constexpr/template string obfuscators and simple packers.
// Each finding names the buffer the loop writes (base+disp form). A plain
// counting loop with no XOR/store stays silent.
std::vector<Finding> scan_stack_strings(Arch arch, const ByteReader& read, Addr lo, Addr hi);

// --- T4.2 inline / clone detection ------------------------------------------

// One cluster of identical (operand-normalized) instruction windows that occur
// at two or more distinct sites — a fragment inlined/cloned across functions.
struct CloneCluster {
    u64 hash = 0;                 // component id (opaque)
    std::size_t window = 0;       // matched run length, in instructions
    std::vector<Addr> sites;      // start address of each occurrence
};

// Cluster matching instruction runs across the given function entries.
// Instructions are normalized to "mnemonic + operand-kinds" so that register
// renaming does not break a match. Equal-length windows seed the search and
// each seed is extended to its maximal common run, so one inlined fragment
// yields one cluster (not one per sliding offset). A cluster is reported only
// when a run of >= `window` instructions appears at >= 2 distinct sites.
std::vector<CloneCluster> find_clones(Arch arch, const ByteReader& read,
                                      const std::vector<Addr>& func_entries,
                                      std::size_t window = 6,
                                      std::size_t max_insns_per_func = 256);

// --- T4.3 vtable / RTTI (static half) ---------------------------------------

struct Vtable {
    Addr addr = 0;                 // address of the first function slot
    std::vector<Addr> slots;       // code pointers (virtual method targets)
    std::string type_name;         // Itanium type_info name, "" if absent/unknown
};

// Scan [lo, hi) for runs of >= min_slots consecutive pointer-sized values that
// all point into [code_lo, code_hi) — candidate virtual-method tables. When the
// Itanium ABI layout is present (vtable[-1] -> type_info, type_info+8 -> name
// string), the mangled class name is read and lightly demangled.
std::vector<Vtable> scan_vtables(const ByteReader& read, Addr lo, Addr hi,
                                 Addr code_lo, Addr code_hi,
                                 std::size_t min_slots = 2);

// Light Itanium name decode: "3Foo" -> "Foo", "N3abc3defE" -> "abc::def".
// Returns "" if the input is not a plausible mangled name.
std::string itanium_demangle_name(const std::string& mangled);

}  // namespace dede
