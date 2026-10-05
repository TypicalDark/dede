// SPDX-License-Identifier: Apache-2.0
//
// The disassembly listing — the default centre view. Draws the linear disasm
// from rip, highlights the current instruction, marks breakpoints, and makes a
// row the current selection (which the inspector then follows).
#include "dede/session/engine.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/services.hpp"
#include "src/ui/modules/all.hpp"
#include "src/ui/modules/mod_common.hpp"

namespace dede::ui {

using mod::hx;

namespace {
void draw_disasm(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) { p.text({r.x + 14, r.y + 24}, "no session", th.dim, 12); return; }
    auto& e = *s.engine;

    // header strip
    Rect head = r; head.h = 24;
    p.rect(head, th.panel2);
    p.text({head.x + 12, head.cy() + 4}, "follow rip  \xE2\x9C\x93    goto 0x" + hx(e.rip()), th.faint, 11);
    p.line({r.x, head.y1()}, {r.x1(), head.y1()}, th.line);

    Addr rip = e.rip();
    Addr sel = s.ctx->selection().kind == SelKind::Insn ? s.ctx->selection().addr : 0;
    auto insns = e.disassemble(rip, 28);
    float y = head.y1() + 16;
    const float pitch = 17.0f;
    int after_term = -1;
    for (const auto& in : insns) {
        if (y > r.y1() - 6) break;
        std::string mnem = in.mnemonic;
        if (after_term >= 0 && ++after_term > 2) {
            p.text({r.x + 48, y}, "; \xE2\x80\xA6 (padding)", th.faint, 11);
            break;
        }
        if (after_term < 0 && (mnem == "hlt" || mnem == "ret" || mnem == "jmp")) after_term = 0;

        Rect row{r.x + 4, y - 12, r.w - 8, pitch};
        bool is_rip = in.addr == rip;
        bool is_sel = in.addr == sel;
        if (is_rip) p.rect(row, with_alpha(th.accent, 26), 3);
        if (is_sel) p.rect_outline(row, th.accent, 3, 1);
        bool is_bp = false;
        for (const auto& rp : e.run_points())
            if (rp.type == RunPointType::Address && rp.address == in.addr) is_bp = true;
        p.circle({r.x + 16, y - 3}, 3.5f, is_bp ? th.danger : th.panel2);
        if (!is_bp) p.circle_outline({r.x + 16, y - 3}, 3.5f, th.line2, 1);
        p.text({r.x + 28, y}, is_rip ? "\xE2\x96\xB6" : " ", th.green, 10);
        p.text({r.x + 46, y}, hx(in.addr, 8), th.blue, 11);
        // bytes
        std::string bytes;
        for (std::size_t i = 0; i < in.bytes.size() && i < 7; ++i) {
            char b[4]; std::snprintf(b, sizeof b, "%02x ", in.bytes[i]); bytes += b;
        }
        p.text({r.x + 110, y}, bytes, th.faint, 10);
        p.text({r.x + 228, y}, mnem, th.yellow, 11);
        p.text({r.x + 228 + p.measure(mnem, 11) + 6, y}, in.op_str, th.text, 11);
        if (p.clicked(row)) s.ctx->select_insn(in.addr);
        y += pitch;
    }
}
}  // namespace

Manifest disasm_module() {
    Manifest m;
    m.id = "disasm";
    m.views = {{"disassembly", "Disassembly", 0, "main", draw_disasm}};
    m.commands = {
        {"nav.goto", "Goto address", "Navigate", "loaded", "G",
         [](Services& s, const std::string& arg) {
             if (!arg.empty()) s.ctx->select_insn(std::stoull(arg, nullptr, 16));
         }},
        {"bp.toggle", "Toggle breakpoint at selection", "Run", "loaded", "F9",
         [](Services& s, const std::string&) {
             if (!s.engine || s.ctx->selection().kind != SelKind::Insn) return;
             Addr a = s.ctx->selection().addr;
             for (const auto& rp : s.engine->run_points())
                 if (rp.type == RunPointType::Address && rp.address == a) { s.engine->remove_run_point(rp.id); return; }
             s.engine->add_breakpoint(a, "");
         }},
    };
    return m;
}

}  // namespace dede::ui
