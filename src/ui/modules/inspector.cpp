// SPDX-License-Identifier: Apache-2.0
//
// Inspector schemas drive the right-hand "Properties follows selection" panel:
// the highest-priority schema whose match(ctx) is true renders. Here: a selected
// instruction (props + an actions grid) and a selected register. Plus the shell
// commands the chrome dispatches (open/palette/new tab).
#include "dede/session/engine.hpp"
#include "dede/ui/commands.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/services.hpp"
#include "src/ui/modules/all.hpp"
#include "src/ui/modules/mod_common.hpp"

namespace dede::ui {

using mod::Cursor;
using mod::hx;

namespace {

// A 2-column ACTIONS grid; each entry runs a command.
void actions(IPainter& p, Services& s, Rect area, float& y,
             std::initializer_list<std::pair<const char*, const char*>> items) {
    const Theme& th = *s.theme;
    p.text({area.x, y + 10}, "ACTIONS", th.text, 10);
    y += 16;
    float colw = (area.w - 4) / 2;
    int i = 0;
    for (auto& [label, cmd] : items) {
        Rect b{area.x - 2 + (i % 2) * (colw + 4), y + (i / 2) * 26, colw, 22};
        p.rect(b, th.panel2, 5);
        p.rect_outline(b, th.line2, 5, 1);
        p.text({b.x + 10, b.cy() + 4}, label, th.text, 10);
        if (p.clicked(b) && s.commands) s.commands->execute(cmd, s);
        ++i;
    }
    y += ((int(items.size()) + 1) / 2) * 26 + 8;
}

void render_insn(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) return;
    Addr a = s.ctx->selection().addr;
    auto insns = s.engine->disassemble(a, 1);
    Cursor c{p, th, r.x + 16, r.w - 30, r.y};

    // selected card
    Rect card{r.x + 14, c.y, r.w - 28, 52};
    p.rect(card, th.panel2, 6);
    p.rect_outline(card, th.line2, 6, 1);
    p.text({card.x + 12, card.y + 18}, "insn  0x" + hx(a), th.green, 11);
    std::string bytes, txt = insns.empty() ? "(unmapped)" : insns[0].text();
    if (!insns.empty()) for (std::size_t i = 0; i < insns[0].bytes.size() && i < 8; ++i) { char b[4]; std::snprintf(b, sizeof b, "%02x ", insns[0].bytes[i]); bytes += b; }
    p.text({card.x1() - 12, card.y + 18}, bytes, th.dim, 10, Align::Right);
    p.text({card.x + 12, card.y + 38}, txt, th.text, 10.5f);
    c.y = card.y1() + 12;

    if (!insns.empty()) {
        const auto& in = insns[0];
        c.field("mnemonic", in.mnemonic);
        c.field("operands", in.op_str.empty() ? "(none)" : in.op_str);
        std::string sym;
        if (auto d = s.engine->symbols().describe(a)) sym = *d;
        c.field("symbol / function", sym.empty() ? "sub_" + hx(a) : sym);
        std::string cf = in.cf.is_call ? "call" : in.cf.is_ret ? "ret" : in.cf.is_cond_branch ? "cond-branch" : in.cf.is_branch ? "branch" : "sequential";
        c.field("control flow", cf, in.cf.is_branch ? th.accent : th.text);
    }
    float y = c.y + 4;
    actions(p, s, {r.x + 16, 0, r.w - 30, 0}, y,
            {{"\xE2\x9C\x82 Set BP", "bp.toggle"}, {"\xE2\x86\x92 Run to here", "run.run"},
             {"\xE2\x8C\x98 Decompile", "view.decompiler"}, {"\xE2\x97\xB3 View CFG", "view.cfg"}});
}

void render_reg(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) return;
    Reg rg = s.ctx->selection().reg;
    Cursor c{p, th, r.x + 16, r.w - 30, r.y};
    p.text({c.x, c.y + 14}, "register  " + std::string(reg_name(rg)), th.green, 11);
    c.y += 24;
    c.field("value", "0x" + hx(s.engine->read_reg(rg), 16), th.accent);
    c.field("decimal", std::to_string((long long)s.engine->read_reg(rg)));
    c.field("as pointer", "[0x" + hx(s.engine->read_reg(rg)) + "]");
}

}  // namespace

Manifest inspector_module() {
    Manifest m;
    m.id = "inspector";
    m.schemas = {
        {"insn", "Instruction", 10,
         [](const Context& c) { return c.selection().kind == SelKind::Insn; }, render_insn},
        {"reg", "Register", 10,
         [](const Context& c) { return c.selection().kind == SelKind::Reg; }, render_reg},
    };
    m.commands = {
        {"nav.open", "Open binary\xE2\x80\xA6", "Navigate", "", "", nullptr},
        {"palette.open", "Command palette", "View", "", "Ctrl+K", nullptr},
        {"tab.new", "New tab", "View", "", "", nullptr},
        {"view.cfg", "Show CFG", "View", "", "",
         [](Services& s, const std::string&) { s.ctx->set_active_view("cfg"); }},
        {"view.decompiler", "Show decompiler", "View", "", "",
         [](Services& s, const std::string&) { s.ctx->set_active_view("decompiler"); }},
    };
    return m;
}

}  // namespace dede::ui
