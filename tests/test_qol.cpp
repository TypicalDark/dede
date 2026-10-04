// SPDX-License-Identifier: Apache-2.0
#include <vector>

#include "check.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

TEST("symbol table describes nearest symbol with offset") {
    SymbolTable t;
    t.add(0x1000, "main");
    t.add(0x1040, "helper");
    CHECK(t.at(0x1000) != nullptr);
    CHECK_EQ(*t.describe(0x1000), std::string("main"));
    CHECK_EQ(*t.describe(0x1008), std::string("main+0x8"));
    CHECK_EQ(*t.describe(0x1040), std::string("helper"));
    CHECK(!t.describe(0x0).has_value());
}

TEST("memory search finds a byte pattern") {
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RW);
    s.load(0x1000, {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD}, perm::RW);
    auto hits = s.search(0x1000, 0x1000, {0xDE, 0xAD});
    CHECK_EQ(hits.size(), 2u);
    CHECK_EQ(hits[0], 0x1000u);
    CHECK_EQ(hits[1], 0x1005u);
}

TEST("who_wrote identifies the writing instruction (time-travel query)") {
    AnalysisSession s;
    s.map(0x1000, 0x1000, perm::RWX);
    s.map(0x70000, 0x1000, perm::RW);
    // mov rax, 0x12345678 ; mov [0x70000], rax ; hlt
    s.load(0x1000,
           {0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12,                    // mov rax, 0x12345678
            0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x07, 0x00,             // mov [0x70000], rax
            0xF4},                                                       // hlt
           perm::RWX);
    s.set_entry(0x1000);
    s.run();
    auto w = s.who_wrote(0x70000, 8);
    CHECK(w.has_value());
    CHECK_EQ(w->pc, 0x1007u);   // the `mov [mem], rax` instruction
    CHECK_EQ(w->value, 0x12345678u);
}

TEST("session save/load round-trips memory, registers, and symbols") {
    std::string path = "/tmp/dede_session_test.txt";
    {
        AnalysisSession s;
        s.map(0x2000, 0x1000, perm::RWX);
        s.load(0x2000, {0x90, 0x90, 0xF4}, perm::RWX);  // nop nop hlt
        s.set_entry(0x2000);
        s.write_reg(Reg::Rbx, 0xCAFEBABE);
        s.symbols().add(0x2000, "entry");
        CHECK(s.save_session(path).ok());
    }
    AnalysisSession s2;
    CHECK(s2.load_session(path).ok());
    CHECK_EQ(s2.rip(), 0x2000u);
    CHECK_EQ(s2.read_reg(Reg::Rbx), 0xCAFEBABEu);
    CHECK_EQ(s2.read_mem(0x2000, 1).value(), 0x90u);
    CHECK_EQ(s2.read_mem(0x2002, 1).value(), 0xF4u);
    CHECK(s2.symbols().at(0x2000) != nullptr);
    // And it runs to completion after loading.
    CHECK(s2.run().status == StepOutcome::Status::Halted);
}

int main() { return dede::test::run_all(); }
