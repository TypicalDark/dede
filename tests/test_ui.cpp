// SPDX-License-Identifier: Apache-2.0
//
// Tests the headless UI kernel: when-evaluation, the contribution registry,
// context selection, and command dispatch — all without any GUI backend.
#include <string>

#include "check.hpp"
#include "dede/ui/commands.hpp"
#include "dede/ui/context.hpp"
#include "dede/ui/registry.hpp"
#include "dede/ui/services.hpp"

using namespace dede;
using namespace dede::ui;

TEST("when-clause evaluation: flags, negation, and/or") {
    Context ctx;
    ctx.set_flag("paused", true);
    ctx.set_flag("loaded", true);
    CHECK(evaluate_when("", ctx));                          // empty = always
    CHECK(evaluate_when("paused", ctx));
    CHECK(!evaluate_when("running", ctx));
    CHECK(evaluate_when("!running", ctx));
    CHECK(evaluate_when("paused && loaded", ctx));
    CHECK(!evaluate_when("paused && running", ctx));
    CHECK(evaluate_when("running || paused", ctx));
    CHECK(!evaluate_when("running || !loaded", ctx));
}

TEST("context selection drives kind and notifies") {
    Context ctx;
    int hits = 0;
    ctx.subscribe([&](const std::vector<std::string>& keys) {
        for (auto& k : keys) if (k == "sel") ++hits;
    });
    CHECK(!ctx.has_selection());
    ctx.select_insn(0x401000);
    CHECK(ctx.has_selection());
    CHECK(ctx.selection().kind == SelKind::Insn);
    CHECK_EQ(ctx.selection().addr, 0x401000u);
    ctx.select_reg(Reg::Rbx);
    CHECK(ctx.selection().kind == SelKind::Reg);
    CHECK(ctx.selection().reg == Reg::Rbx);
    CHECK_EQ(hits, 2);
}

TEST("registry records contributions from a manifest") {
    Registry reg;
    Manifest m;
    m.id = "test";
    m.commands.push_back({"test.hello", "Say Hello", "Test", "", "", nullptr});
    m.views.push_back({"test.view", "Test View", 0, nullptr});
    m.toolbar.push_back({"test.hello", "exec", ">", "", "", 5});
    m.keybindings.push_back({"F1", "test.hello", ""});
    m.schemas.push_back({"insn", "Instruction", 10,
                         [](const Context& c) { return c.selection().kind == SelKind::Insn; }, nullptr});
    reg.register_module(std::move(m));

    CHECK_EQ(reg.module_count(), 1u);
    CHECK(reg.command("test.hello") != nullptr);
    CHECK(reg.view("test.view") != nullptr);
    CHECK_EQ(reg.key_for("test.hello"), std::string("F1"));

    Context ctx;
    ctx.select_insn(0x1000);
    const InspectorSchema* s = reg.pick_schema(ctx);
    CHECK(s != nullptr);
    CHECK_EQ(s->kind, std::string("insn"));
    ctx.select_reg(Reg::Rax);
    CHECK(reg.pick_schema(ctx) == nullptr);  // no schema matches a register
}

TEST("inspector schema picks highest priority among matches") {
    Registry reg;
    Manifest m;
    m.id = "t";
    auto always = [](const Context&) { return true; };
    m.schemas.push_back({"low", "", 1, always, nullptr});
    m.schemas.push_back({"high", "", 99, always, nullptr});
    m.schemas.push_back({"mid", "", 50, always, nullptr});
    reg.register_module(std::move(m));
    Context ctx;
    CHECK_EQ(reg.pick_schema(ctx)->kind, std::string("high"));
}

TEST("command bus runs enabled handlers and skips disabled ones") {
    Registry reg;
    Context ctx;
    int ran = 0;
    Manifest m;
    m.id = "t";
    m.commands.push_back({"t.always", "Always", "T", "", "",
                          [&](Services&, const std::string&) { ++ran; }});
    m.commands.push_back({"t.paused_only", "Paused only", "T", "paused", "",
                          [&](Services&, const std::string&) { ++ran; }});
    reg.register_module(std::move(m));

    CommandBus bus(reg);
    Services s;
    s.ctx = &ctx;
    s.registry = &reg;
    s.commands = &bus;

    CHECK(bus.execute("t.always", s));
    CHECK_EQ(ran, 1);
    CHECK(!bus.execute("t.paused_only", s));  // disabled (paused flag off)
    CHECK_EQ(ran, 1);
    ctx.set_flag("paused", true);
    CHECK(bus.execute("t.paused_only", s));   // now enabled
    CHECK_EQ(ran, 2);
    CHECK(!bus.execute("t.nope", s));         // unknown command
    CHECK_EQ(bus.history().size(), 2u);
}

TEST("command handler can mutate context and drive selection") {
    Registry reg;
    Context ctx;
    Manifest m;
    m.id = "nav";
    m.commands.push_back({"nav.goto", "Goto", "Nav", "", "",
                          [](Services& s, const std::string& arg) {
                              s.ctx->select_insn(std::stoull(arg, nullptr, 16));
                          }});
    reg.register_module(std::move(m));
    CommandBus bus(reg);
    Services s;
    s.ctx = &ctx;
    s.registry = &reg;
    s.commands = &bus;
    CHECK(bus.execute("nav.goto", s, "401055"));
    CHECK_EQ(ctx.selection().addr, 0x401055u);
}

int main() { return dede::test::run_all(); }
