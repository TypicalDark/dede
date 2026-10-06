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

// Instruction addresses in [entry, entry+range) that a linear sweep decodes but
// the CFG from `entry` never reaches — i.e. dead/unreachable code.
std::vector<Addr> unreachable_insns(Arch arch, const ByteReader& read, Addr entry, u64 range);

// CRC-32 (IEEE) and FNV-1a over a region — integrity/identity hashing.
u32 crc32(const ByteReader& read, Addr addr, u64 len);
u64 fnv1a(const ByteReader& read, Addr addr, u64 len);

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

// --- packer / protector identification --------------------------------------
// A section as the packer scan sees it (built from the loader's LoadSection).
struct PackerSection {
    std::string name;
    Addr addr = 0;
    u64 size = 0;
    bool exec = false;
};
// Flag known packer/protector section-name signatures and high-entropy
// executable sections (packed/encrypted code). Behavioral confirmation (W^X /
// self-decrypt at runtime) is separate and upgrades confidence.
std::vector<Finding> scan_packer(const std::vector<PackerSection>& sections, const ByteReader& read);

// --- call graph -------------------------------------------------------------

struct CallGraph {
    struct Node { Addr entry; std::size_t blocks; };
    std::vector<Node> funcs;
    std::vector<std::pair<Addr, Addr>> calls;  // caller entry -> callee entry
};
CallGraph build_call_graph(Arch arch, const ByteReader& read, Addr entry,
                           std::size_t max_funcs = 128);

// Function entries that are (transitively) recursive — a cycle in the call graph.
std::vector<Addr> recursive_functions(const CallGraph& g);

// --- JSON export ------------------------------------------------------------
std::string to_json(const Cfg& cfg);
std::string to_json(const CallGraph& g);
std::string to_json(const std::vector<Finding>& findings);

}  // namespace dede
