// SPDX-License-Identifier: Apache-2.0
//
// Batch 7: the cross-tool JSON interchange schema round-trips, and a
// foreign-style export (numbers instead of hex strings, extra keys) imports.
#include <optional>
#include <string>

#include "check.hpp"
#include "dede/interchange/interchange.hpp"

using namespace dede;
using namespace dede::interchange;

TEST("analysis doc round-trips through JSON") {
    AnalysisDoc d;
    d.symbols = {{0x1000, "main"}, {0x1040, "helper"}};
    d.comments = {{0x1004, "loop head"}, {0x1010, "has a \"quote\" and\ttab"}};
    d.functions = {{0x1000, "main", 0x40}, {0x1040, "helper", 0x12}};
    d.structs = {{"s_rdi", {{0, 8}, {8, 4}, {16, 8}}}};

    std::string js = to_json(d);
    auto back = parse_json(js);
    CHECK(back.has_value());
    const AnalysisDoc& r = *back;
    CHECK_EQ(r.symbols.size(), 2u);
    CHECK_EQ(r.symbols[0].addr, 0x1000u);
    CHECK_EQ(r.symbols[1].name, std::string("helper"));
    CHECK_EQ(r.comments.size(), 2u);
    CHECK_EQ(r.comments[1].text, std::string("has a \"quote\" and\ttab"));  // escapes survive
    CHECK_EQ(r.functions.size(), 2u);
    CHECK_EQ(r.functions[0].size, 0x40u);
    CHECK_EQ(r.structs.size(), 1u);
    CHECK_EQ(r.structs[0].tag, std::string("s_rdi"));
    CHECK_EQ(r.structs[0].fields.size(), 3u);
    CHECK_EQ(r.structs[0].fields[2].offset, 16);
}

TEST("imports a foreign-style export (numeric addrs, unknown keys)") {
    // mimics an IDA/BN exporter: addr as a number, extra keys we ignore.
    std::string js = R"({
      "tool": "ida",
      "symbols": [ {"addr": 4096, "name": "start", "flags": 7} ],
      "comments": [ {"addr": "0x1008", "text": "entry"} ],
      "functions": [],
      "extra": {"nested": [1,2,3]}
    })";
    auto d = parse_json(js);
    CHECK(d.has_value());
    CHECK_EQ(d->symbols.size(), 1u);
    CHECK_EQ(d->symbols[0].addr, 4096u);           // JSON number form
    CHECK_EQ(d->symbols[0].name, std::string("start"));
    CHECK_EQ(d->comments.size(), 1u);
    CHECK_EQ(d->comments[0].addr, 0x1008u);        // "0x..." string form
}

TEST("malformed JSON is rejected, not crashed") {
    CHECK(!parse_json("{ not valid ").has_value());
    CHECK(!parse_json("").has_value());
    CHECK(!parse_json("[1,2,3]").has_value());     // top-level must be an object
}

int main() { return dede::test::run_all(); }
