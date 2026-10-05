// SPDX-License-Identifier: Apache-2.0
//
// The bottom "quake" drawer views: Console, Trace (the event log), Registers
// (clickable -> selects a register, which the inspector follows), and Memory map.
#include "dede/session/engine.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/services.hpp"
#include "src/ui/modules/all.hpp"
#include "src/ui/modules/mod_common.hpp"

namespace dede::ui {

using mod::hx;

namespace {

void draw_console(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    float y = r.y + 16;
    auto line = [&](const std::string& t, Color c) { p.text({r.x + 14, y}, t, c, 10.5f); y += 15; };
    if (s.engine) {
        line("dede> info", th.accent);
        line("format: " + s.engine->image_format() + "   rip: 0x" + hx(s.engine->rip()) +
                 "   backend: " + s.engine->backend_name(), th.dim);
        auto ts = s.engine->timeline_stats();
        line("tick " + std::to_string(ts.now) + "/" + std::to_string(ts.max) + "   snapshots " +
                 std::to_string(ts.snapshots) + "   injected " + std::to_string(ts.injected), th.dim);
        line("dede> _", th.accent);
    }
    Rect in{r.x + 10, r.y1() - 24, r.w - 20, 16};
    p.rect(in, th.inset, 4);
    p.rect_outline(in, th.line, 4, 1);
    p.text({in.x + 6, in.cy() + 4}, "> type a command, help lists them, Tab completes", th.faint, 10);
}

void draw_trace(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) return;
    const auto& ev = s.engine->history().events();
    std::size_t start = ev.size() > 10 ? ev.size() - 10 : 0;
    float y = r.y + 16;
    for (std::size_t i = start; i < ev.size(); ++i) {
        const Event& e = ev[i];
        std::string t = "[t=" + std::to_string(e.tick) + "] " + to_string(e.kind) + " @ 0x" + hx(e.pc);
        if (e.kind == EventKind::MemRead || e.kind == EventKind::MemWrite)
            t += "  0x" + hx(e.address) + " = 0x" + hx(e.value);
        Color c = e.kind == EventKind::MemWrite ? th.orange : e.kind == EventKind::Syscall ? th.green : th.dim;
        p.text({r.x + 14, y}, t, c, 10.5f);
        y += 15;
    }
}

void draw_registers(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) return;
    float colw = (r.w - 24) / 4;  // two name+value pairs per row -> 4 columns
    for (int i = 0; i < 16; ++i) {
        float rx = r.x + 12 + (i % 2) * (colw * 2);
        float ry = r.y + 18 + (i / 2) * 16;
        Reg rg = static_cast<Reg>(i);
        Rect hit{rx - 2, ry - 12, colw * 2 - 8, 15};
        bool sel = s.ctx->selection().kind == SelKind::Reg && s.ctx->selection().reg == rg;
        if (sel) p.rect(hit, with_alpha(th.accent, 26), 3);
        p.text({rx, ry}, std::string(reg_name(rg)), th.blue, 10.5f);
        p.text({rx + 34, ry}, hx(s.engine->read_reg(rg), 16), th.text, 10.5f);
        if (p.clicked(hit)) s.ctx->select_reg(rg);
    }
    p.text({r.x + 12, r.y + 18 + 8 * 16 + 6}, "rip " + hx(s.engine->rip(), 16), th.text, 10.5f);
}

void draw_memmap(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) return;
    float y = r.y + 16;
    p.text({r.x + 14, y}, "base              size        perms", th.faint, 10);
    y += 16;
    for (const auto& m : s.engine->memory_map()) {
        char perms[4] = {char((m.perms & perm::R) ? 'r' : '-'), char((m.perms & perm::W) ? 'w' : '-'),
                         char((m.perms & perm::X) ? 'x' : '-'), 0};
        p.text({r.x + 14, y}, hx(m.base, 12) + "    " + hx(m.size, 8) + "    " + perms, th.dim, 10.5f);
        y += 15;
    }
}

}  // namespace

Manifest console_module() {
    Manifest m;
    m.id = "console";
    m.views = {
        {"console", "Console", 0, "drawer", draw_console},
        {"trace", "Trace", 0, "drawer", draw_trace},
        {"registers", "Registers", 0, "drawer", draw_registers},
        {"memmap", "Memory map", 0, "drawer", draw_memmap},
    };
    return m;
}

}  // namespace dede::ui
