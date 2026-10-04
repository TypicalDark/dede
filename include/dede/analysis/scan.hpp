// SPDX-License-Identifier: Apache-2.0
//
// Static scanning / metrics over a byte image: entropy, opcode histograms, string
// extraction, cyclomatic complexity, a pluggable protection detector framework,
// and a program call graph. These power the effectiveness-test harness and the
// shell's `scan`/`entropy`/`opcodes`/`strings`/`callgraph` commands.
//
// Everything works off a ByteReader + Arch, so the analysis library keeps
// depending only on disasm (no cycle back to session).
#pragma once

#include <map>
#include <string>
#include <vector>

#include "dede/analysis/cfg.hpp"
#include "dede/common/types.hpp"
#include "dede/disasm/disassembler.hpp"

namespace dede {

// --- metrics ----------------------------------------------------------------

// Shannon entropy (bits/byte, 0..8) over [addr, addr+len). Unmapped bytes skipped.
double shannon_entropy(const ByteReader& read, Addr addr, u64 len);

// Mnemonic frequency over up to `count` instructions from `addr`, most-common first.
std::vector<std::pair<std::string, u64>> opcode_histogram(Arch arch, const ByteReader& read,
                                                          Addr addr, std::size_t count);

struct FoundString {
    Addr addr;
    std::string text;
};
std::vector<FoundString> extract_strings(const ByteReader& read, Addr addr, u64 len,
                                         std::size_t min_len = 4);

// Cyclomatic complexity M = E - N + 2 for a function CFG.
int cyclomatic_complexity(const Cfg& cfg);

// --- protection / anti-analysis detection (pluggable) -----------------------

struct Finding {
    std::string category;   // e.g. "anti-vm", "timing", "crypto", "self-modifying"
    std::string rule;       // which detector / what matched
    Addr addr = 0;
    std::string detail;
    std::string severity;   // "info" | "notice" | "warning"
};

// A detector inspects decoded instructions and emits findings. New protection
// patterns are added by registering another detector (future-proofing).
class IDetector {
public:
    virtual ~IDetector() = default;
    virtual std::string name() const = 0;
    virtual void inspect(const DecodedInsn& in, std::vector<Finding>& out) const = 0;
};

// Run every registered detector over up to `count` instructions from `addr`.
std::vector<Finding> detect(Arch arch, const ByteReader& read, Addr addr, std::size_t count);

// Names of the registered detectors (for reporting / `scan list`).
std::vector<std::string> detector_names();

// --- call graph -------------------------------------------------------------

struct CallGraph {
    struct Node { Addr entry; std::size_t blocks; };
    std::vector<Node> funcs;
    std::vector<std::pair<Addr, Addr>> calls;  // caller entry -> callee entry
};
CallGraph build_call_graph(Arch arch, const ByteReader& read, Addr entry,
                           std::size_t max_funcs = 128);

}  // namespace dede
