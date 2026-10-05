// SPDX-License-Identifier: Apache-2.0
//
// The control-flow-graph centre view: builds the CFG of the current function
// from the live image and draws basic blocks + typed edges. Reuses the engine's
// existing (excellent) CFG — this view only renders it.
#include <map>

#include "dede/session/engine.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/services.hpp"
#include "src/ui/modules/all.hpp"
#include "src/ui/modules/mod_common.hpp"

namespace dede::ui {

using mod::hx;

namespace {
void draw_cfg(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) { p.text({r.x + 14, r.y + 24}, "no session", th.dim, 12); return; }
    Addr entry = s.ctx->selection().kind == SelKind::Insn ? s.ctx->selection().addr : s.engine->rip();
    p.text({r.x + 12, r.y + 16}, "entry 0x" + hx(entry) + "   (from rip)", th.faint, 11);
    Cfg g = s.engine->build_cfg(entry);
    auto pos = g.layout();
    const float colw = 236, rowh = 128, nodew = 196, nodeh = 104;
    float ox = r.x + 24, oy = r.y + 34;
    Addr rip = s.engine->rip();
    auto nx = [&](int col) { return ox + col * colw; };
    auto ny = [&](int row) { return oy + row * rowh; };

    for (const auto& e : g.edges) {
        if (!pos.count(e.from) || !pos.count(e.to)) continue;
        float ax = nx(pos[e.from].first) + nodew / 2, ay = ny(pos[e.from].second) + nodeh;
        float bx = nx(pos[e.to].first) + nodew / 2, by = ny(pos[e.to].second);
        Color col = e.kind == EdgeKind::Taken ? th.green : e.kind == EdgeKind::NotTaken ? th.danger : th.dim;
        p.line({ax, ay}, {bx, by}, col, 1.8f);
    }
    for (const auto& bb : g.blocks) {
        if (!pos.count(bb.start)) continue;
        float px = nx(pos[bb.start].first), py = ny(pos[bb.start].second);
        bool has_rip = rip >= bb.start && rip < bb.end;
        p.rect({px, py, nodew, nodeh}, has_rip ? with_alpha(th.accent, 30) : th.panel2, 4);
        p.rect_outline({px, py, nodew, nodeh}, has_rip ? th.accent : th.line2, 4, 1.2f);
        p.text({px + 6, py + 15}, "loc_" + hx(bb.start), th.blue, 11);
        float iy = py + 32;
        for (std::size_t i = 0; i < bb.insns.size() && i < 5; ++i) {
            p.text({px + 8, iy}, bb.insns[i].text(), th.text, 10.5f);
            iy += 14;
        }
        if (bb.insns.size() > 5) p.text({px + 8, iy}, "\xE2\x80\xA6 (+" + std::to_string(bb.insns.size() - 5) + ")", th.faint, 10.5f);
    }
    if (!g.calls.empty())
        p.text({r.x + 12, r.y1() - 10}, std::to_string(g.calls.size()) + " call ref(s) \xE2\x86\x92 separate function(s)", th.faint, 10);
}
}  // namespace

Manifest cfg_module() {
    Manifest m;
    m.id = "cfg";
    m.views = {{"cfg", "Control-Flow Graph", 0, "main", draw_cfg}};
    return m;
}

}  // namespace dede::ui
