// SPDX-License-Identifier: Apache-2.0
//
// The left sidebar: dede's execution timeline drawn as a history graph — the
// direct analog of git-tool's commit graph, since time-travel IS a history.
// Recent events are nodes on a spine (newest at top), the current tick is HEAD,
// breakpoints/snapshots/syscalls get badges. Below it: bookmarks (run points).
#include "dede/session/engine.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/services.hpp"
#include "src/ui/modules/all.hpp"
#include "src/ui/modules/mod_common.hpp"

namespace dede::ui {

using mod::hx;

namespace {

float draw_timeline(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    float y0 = r.y + 20;
    if (!s.engine) { p.text({r.x + 14, y0}, "no session", th.dim, 11); return 34; }
    auto& e = *s.engine;
    auto ts = e.timeline_stats();
    p.text({r.x + 14, y0}, "\xE2\x8E\x87 timeline @ tick " + std::to_string(ts.now), th.dim, 11);

    const auto& ev = e.history().events();
    // newest first, up to 12
    std::vector<const Event*> rows;
    for (auto it = ev.rbegin(); it != ev.rend() && rows.size() < 12; ++it) rows.push_back(&*it);

    float gx = r.x + 22, gy = y0 + 24;
    const float pitch = 28;
    if (!rows.empty())
        p.line({gx, gy - 6}, {gx, gy + (rows.size() - 1) * pitch + 6}, th.purple, 2);
    float y = gy;
    bool first = true;
    for (const Event* x : rows) {
        bool head = first; first = false;
        Rect row{r.x + 8, y - 12, r.w - 16, 24};
        if (head) { p.rect(row, th.panel2, 5); p.rect_outline(row, th.accent_dim, 5, 1); }
        p.circle({gx, y}, 4.5f, head ? th.purple : th.panel);
        p.circle_outline({gx, y}, 4.5f, th.purple, 2);
        p.text({gx + 14, y + 4}, std::to_string(x->tick), th.faint, 10);
        std::string label = std::string(to_string(x->kind)) + " 0x" + hx(x->pc);
        p.text({gx + 48, y + 4}, label, head ? th.text : th.dim, 10);
        // right-aligned badge
        const char* btxt = nullptr; Color bfg = th.dim, bbg = th.panel2;
        if (head) { btxt = "HEAD"; bfg = th.green; bbg = with_alpha(th.green, 30); }
        else if (x->kind == EventKind::MemWrite) { btxt = "wr"; bfg = th.orange; bbg = with_alpha(th.orange, 30); }
        else if (x->kind == EventKind::Syscall) { btxt = "io"; bfg = th.blue; bbg = with_alpha(th.blue, 30); }
        else if (x->kind == EventKind::Fault) { btxt = "flt"; bfg = th.danger; bbg = with_alpha(th.danger, 30); }
        if (btxt) {
            float bw = p.measure(btxt, 9) + 12;
            p.pill({r.x + r.w - 12 - bw, y - 8, bw, 15}, bbg, btxt, bfg, 9);
        }
        y += pitch;
    }
    return (y - r.y) + 8;
}

float draw_bookmarks(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    float y = r.y + 6;
    p.line({r.x + 8, y}, {r.x1() - 8, y}, th.line);
    y += 12;
    int n = s.engine ? (int)s.engine->run_points().size() : 0;
    p.text({r.x + 14, y}, "\xE2\x96\xBE BOOKMARKS / RUN POINTS", th.faint, 9.5f);
    p.text({r.x1() - 14, y}, std::to_string(n), th.faint, 9.5f, Align::Right);
    y += 16;
    if (s.engine)
        for (const auto& rp : s.engine->run_points()) {
            std::string label = std::string(to_string(rp.type));
            if (rp.type == RunPointType::Address) label += " 0x" + hx(rp.address);
            p.circle({r.x + 18, y + 6}, 3, th.danger);
            p.text({r.x + 28, y + 10}, label, th.dim, 10);
            y += 17;
        }
    return (y - r.y) + 6;
}

}  // namespace

Manifest timeline_module() {
    Manifest m;
    m.id = "timeline";
    m.sidebar = {
        {"timeline", "Timeline", 0, draw_timeline},
        {"bookmarks", "Bookmarks", 10, draw_bookmarks},
    };
    return m;
}

}  // namespace dede::ui
