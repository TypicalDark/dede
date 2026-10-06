// SPDX-License-Identifier: Apache-2.0
//
// Batch 6: C++ demangling, the prototype/type library + calling conventions,
// and FLIRT-style masked signature matching.
#include <optional>
#include <vector>

#include "check.hpp"
#include "dede/symbols/demangle.hpp"
#include "dede/symbols/protodb.hpp"
#include "dede/symbols/siglib.hpp"

using namespace dede;
using namespace dede::sym;

TEST("Itanium demangler handles the common forms") {
    CHECK_EQ(demangle("_Z3foov"), std::string("foo()"));
    CHECK_EQ(demangle("_Z3addii"), std::string("add(int, int)"));
    CHECK_EQ(demangle("_ZN3foo3barEv"), std::string("foo::bar()"));
    CHECK_EQ(demangle("_Z6strlenPKc"), std::string("strlen(const char *)"));
    CHECK_EQ(demangle("_ZN3Foo3barEiPKc"), std::string("Foo::bar(int, const char *)"));
    CHECK_EQ(demangle("_ZN3FooC1Ev"), std::string("Foo::Foo()"));
    CHECK_EQ(demangle("_ZN3FooD1Ev"), std::string("Foo::~Foo()"));
    CHECK_EQ(demangle("_Z4funcPiRi"), std::string("func(int *, int &)"));
    CHECK_EQ(demangle("_ZNSt6vectorIiE9push_backEi"), std::string("std::vector<int>::push_back(int)"));
    // not a mangled name -> unchanged; unparseable -> unchanged (never garbage)
    CHECK_EQ(demangle("main"), std::string("main"));
    CHECK_EQ(demangle("_Znotreallymangled!!"), std::string("_Znotreallymangled!!"));
}

TEST("MSVC demangler recovers a scope-qualified name") {
    CHECK_EQ(demangle("?foo@bar@@YAHXZ"), std::string("bar::foo"));
}

TEST("prototype DB has a usable starter set and strips decoration") {
    CHECK(prototype_count() >= 50u);
    const Proto* sl = lookup_prototype("strlen");
    CHECK(sl != nullptr);
    CHECK_EQ(declaration(*sl), std::string("size_t strlen(const char *)"));
    const Proto* mc = lookup_prototype("memcpy");
    CHECK(mc != nullptr && mc->params.size() == 3);
    // leading underscore + stdcall @N decoration are stripped
    CHECK(lookup_prototype("_recv") != nullptr);
    CHECK(lookup_prototype("recv@16") != nullptr);
    CHECK(lookup_prototype("no_such_function_xyz") == nullptr);
    // variadic rendered with ...
    CHECK_EQ(declaration(*lookup_prototype("printf")), std::string("int printf(const char *, ...)"));
}

TEST("calling-convention detection and argument order") {
    // SysV: first args in RDI, RSI, RDX, ...
    CHECK(detect_callconv({Reg::Rdi, Reg::Rsi}) == CallConv::SysV);
    CHECK(arg_register(CallConv::SysV, 0) == Reg::Rdi);
    CHECK(arg_register(CallConv::SysV, 2) == Reg::Rdx);
    // Win64: first args in RCX, RDX, R8, R9 — and RDI/RSI are never arg regs.
    CHECK(detect_callconv({Reg::Rcx, Reg::Rdx, Reg::R8}) == CallConv::Win64);
    CHECK(arg_register(CallConv::Win64, 0) == Reg::Rcx);
    CHECK(arg_register(CallConv::Win64, 1) == Reg::Rdx);
    CHECK(arg_register(CallConv::Win64, 2) == Reg::R8);
    CHECK(arg_register(CallConv::Win64, 3) == Reg::R9);
    CHECK(arg_register(CallConv::Win64, 4) == Reg::Count);  // 5th arg is stack-passed
}

TEST("FLIRT masked signature matches across link addresses, not a different fn") {
    // A routine `endbr64; call rel32; ret` — the rel32 varies by link address.
    auto body = [](u8 d0, u8 d1, u8 d2, u8 d3) {
        return std::vector<u8>{0xF3, 0x0F, 0x1E, 0xFA, 0xE8, d0, d1, d2, d3, 0xC3};
    };
    std::vector<u8> buildA = body(0x10, 0x20, 0x00, 0x00);
    std::vector<u8> buildB = body(0xAB, 0xCD, 0x01, 0x00);  // same fn, different displacement
    std::vector<u8> other  = {0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3};  // push rbp; mov rbp,rsp; pop rbp; ret

    // signature from build A, wildcarding the 4 displacement bytes at offset 5.
    Signature sig = make_signature("myfunc", buildA, {{5, 4}});

    auto reader = [](const std::vector<u8>& v) {
        return [&v](Addr a) -> std::optional<u8> { return a < v.size() ? std::optional<u8>(v[a]) : std::nullopt; };
    };
    CHECK(match_at(sig, reader(buildA), 0));
    CHECK(match_at(sig, reader(buildB), 0));   // matches despite the different rel32
    CHECK(!match_at(sig, reader(other), 0));   // unrelated code does not match (no FP)

    auto name = identify({sig}, reader(buildB), 0);
    CHECK(name.has_value() && *name == "myfunc");
    CHECK(!identify({sig}, reader(other), 0).has_value());
    CHECK(!starter_library().empty());
}

int main() { return dede::test::run_all(); }
