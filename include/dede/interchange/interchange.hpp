// SPDX-License-Identifier: Apache-2.0
//
// Cross-tool analysis interchange (Batch 7, T7.2). A documented JSON schema for
// the portable facts an analyst accumulates — symbols, comments, functions, and
// recovered structs — plus a serializer and a small self-contained parser, so
// annotations can move between dede and IDA/Binary Ninja/Ghidra (each of which
// can emit/consume this JSON via a short exporter script; see docs). dede does
// not read a proprietary .idb/.bndb; it interchanges the analysis *facts*.
//
// Schema:
//   { "symbols":   [ {"addr": "0x1000", "name": "main"} ],
//     "comments":  [ {"addr": "0x1004", "text": "loop head"} ],
//     "functions": [ {"addr": "0x1000", "name": "main", "size": 42} ],
//     "structs":   [ {"tag": "s_rdi", "fields": [ {"offset": 0, "width": 8} ] } ] }
// `addr`/`offset`/`width`/`size` accept a JSON number or a "0x..."/decimal string.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "dede/common/types.hpp"

namespace dede::interchange {

struct SymbolEnt { Addr addr = 0; std::string name; };
struct CommentEnt { Addr addr = 0; std::string text; };
struct FunctionEnt { Addr addr = 0; std::string name; u64 size = 0; };
struct FieldEnt { i64 offset = 0; unsigned width = 0; };
struct StructEnt { std::string tag; std::vector<FieldEnt> fields; };

struct AnalysisDoc {
    std::vector<SymbolEnt> symbols;
    std::vector<CommentEnt> comments;
    std::vector<FunctionEnt> functions;
    std::vector<StructEnt> structs;
};

// Serialize to the schema above (pretty-printed, stable key order).
std::string to_json(const AnalysisDoc& doc);

// Parse the schema. Returns nullopt on malformed JSON. Unknown keys are ignored
// (forward-compatible with richer IDA/BN exports).
std::optional<AnalysisDoc> parse_json(const std::string& text);

}  // namespace dede::interchange
