// SPDX-License-Identifier: Apache-2.0
//
// dede-shot — render the real modular UI shell to SVG from LIVE engine data.
//
// The desktop GUI needs a display + GPU, so it cannot be screen-captured in a
// headless container. Instead this drives a real AnalysisSession, builds the UI
// kernel (Registry + registered feature modules), and renders the whole git-tool
// -style shell through the SVG IPainter — the exact same Shell and panel code the
// ImGui backend runs. Every value shown is live engine output; only the painter
// differs. This is also the headless proof that the modular UI works.
#include <fstream>
#include <string>

#include "dede/samples/tiers.hpp"
#include "dede/session/analysis_session.hpp"
#include "dede/ui/backends/svg_painter.hpp"
#include "dede/ui/commands.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/shell.hpp"

using namespace dede;

namespace {
constexpr float W = 1366, H = 768;

void load_tier(AnalysisSession& s, int n) {
    auto t = samples::make_tier(n);
    s.map(0x1000, 0x10000, perm::RWX);
    s.map(0x70000, 0x10000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x78000);
    s.load(0x1000, t.image, perm::RWX);
    s.set_entry(t.entry);
}

// Render one frame of the shell for a session + UI state to an SVG file.
void render(AnalysisSession& sess, const std::string& out, const std::string& view,
            const std::string& drawer, ui::Selection sel, const std::string& theme_name = "cyan") {
    ui::Registry reg;
    ui::register_modules(reg);
    ui::Context ctx;
    ctx.set_active_view(view);
    if (!drawer.empty()) ctx.set_str("drawer_view", drawer);
    ctx.set_str("insp_tab", "props");
    ctx.select_insn(sel.addr);  // default; overridden below by kind
    if (sel.kind == ui::SelKind::Reg) ctx.select_reg(sel.reg);
    else if (sel.kind == ui::SelKind::Insn) ctx.select_insn(sel.addr);
    else ctx.clear_selection();

    ui::Theme theme = ui::Theme::preset(theme_name);
    ui::CommandBus bus(reg);
    ui::Services s;
    s.engine = &sess;
    s.ctx = &ctx;
    s.registry = &reg;
    s.commands = &bus;
    s.theme = &theme;
    ui::sync_context(s);

    ui::SvgPainter p(W, H, theme.bg);
    ui::Shell shell;
    shell.draw(p, s, {0, 0, W, H});

    std::string svg = p.finish();
    std::ofstream(out) << svg;
    std::printf("wrote %s (%zu bytes)\n", out.c_str(), svg.size());
}
}  // namespace

int main(int argc, char** argv) {
    std::string dir = argc >= 2 ? argv[1] : "docs/img";

    // 1) Overview — tier 1 loop, stepped, disassembly focused, a register selected.
    {
        AnalysisSession s(Arch::X86_64);
        load_tier(s, 1);
        for (int i = 0; i < 5; ++i) s.step();
        render(s, dir + "/ui-shell-overview.svg", "disassembly", "console",
               {ui::SelKind::Insn, s.rip(), Reg::Rax, 0});
    }
    // 2) Control-flow graph — tier 4 anti-VM check.
    {
        AnalysisSession s(Arch::X86_64);
        load_tier(s, 4);
        render(s, dir + "/ui-shell-cfg.svg", "cfg", "registers", {}, "amber");
    }
    // 3) Time-travel — tier 5, run then step back, trace drawer, register inspector.
    {
        AnalysisSession s(Arch::X86_64);
        load_tier(s, 5);
        s.run(400);
        s.step_back(6);
        render(s, dir + "/ui-shell-timetravel.svg", "disassembly", "trace",
               {ui::SelKind::Reg, 0, Reg::Rsi, 0}, "green");
    }
    // 4) Decompiler view — tier 2.
    {
        AnalysisSession s(Arch::X86_64);
        load_tier(s, 2);
        render(s, dir + "/ui-shell-decompiler.svg", "decompiler", "console", {});
    }
    return 0;
}
