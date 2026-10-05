// SPDX-License-Identifier: Apache-2.0
#include "dede/ui/shell.hpp"

#include <string>
#include <vector>

#include "dede/ui/commands.hpp"
#include "dede/ui/registry.hpp"

namespace dede::ui {

namespace {
// A small rounded "chrome" button with an optional toggled state.
void icon_button(IPainter& p, const Theme& th, Rect r, const std::string& glyph, bool on,
                 Color on_fill, Color on_fg) {
    p.rect(r, on ? on_fill : th.panel2, 5);
    p.rect_outline(r, th.line, 5, 1);
    p.text({r.cx(), r.cy() + 4}, glyph, on ? on_fg : th.dim, 12, Align::Center);
}
}  // namespace

void Shell::draw(IPainter& p, Services& s, Rect b) {
    const Theme& th = *s.theme;
    p.rect(b, th.bg);

    Rect tb = b.cut_top(m.titlebar);
    Rect ts = b.cut_top(m.tabstrip);
    Rect st = b.cut_bottom(m.statusbar);
    Rect side = b.cut_left(m.sidebar);
    Rect insp = b.cut_right(m.inspector);
    bool drawer_open = !s.ctx->flag("drawer_closed");
    Rect dr{};
    if (drawer_open) dr = b.cut_bottom(m.drawer);

    title_bar(p, s, tb);
    tab_strip(p, s, ts);
    sidebar(p, s, side);
    center(p, s, b);
    if (drawer_open) drawer(p, s, dr);
    inspector(p, s, insp);
    status_bar(p, s, st);
}

void Shell::title_bar(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    p.rect(r, th.bg);
    p.line({r.x, r.y1()}, {r.x1(), r.y1()}, th.line);

    // logo
    p.text({r.x + 14, r.cy() + 5}, "\xE2\x8E\x87", th.accent, 15);  // ⎇
    std::string title = s.ctx->str("app_title");
    if (title.empty()) title = "dede";
    p.text({r.x + 32, r.cy() + 5}, title, th.text, 14);

    // state chip
    std::string chip = s.ctx->str("state_chip");
    if (chip.empty()) chip = "no session";
    float cw = p.measure(chip, 10.5f) + 34;
    Rect chipR{r.x + 76, r.cy() - 9, cw, 18};
    p.rect(chipR, th.bg, 9);
    p.rect_outline(chipR, th.accent_dim, 9, 1);
    p.circle({chipR.x + 13, chipR.cy()}, 3, th.accent);
    p.text({chipR.x + 22, chipR.cy() + 3.5f}, chip, th.accent, 10.5f);

    // toolbar segments
    float tx = chipR.x1() + 14;
    for (const char* seg : {"nav", "exec", "view"}) {
        auto items = s.registry->toolbar(seg, *s.ctx);
        for (const ToolbarItem* it : items) {
            Rect ib{tx, r.cy() - 10, 22, 20};
            bool on = !it->checked.empty() && evaluate_when(it->checked, *s.ctx);
            icon_button(p, th, ib, it->icon, on, th.accent_dim, th.accent);
            if (p.clicked(ib) && s.commands) s.commands->execute(it->command, s);
            tx += 26;
        }
        if (!items.empty()) tx += 8;  // gap between segments
    }

    // OPEN button (far right)
    Rect openR{r.x1() - 84, r.cy() - 10, 70, 20};
    p.pill(openR, with_alpha(th.green, 36), "OPEN", th.green, 11, th.green, 1);
    if (p.clicked(openR) && s.commands) s.commands->execute("nav.open", s);

    // command search box
    Rect sr{openR.x - 330, r.cy() - 10, 318, 20};
    p.rect(sr, th.inset, 6);
    p.rect_outline(sr, th.line, 6, 1);
    p.text({sr.x + 10, sr.cy() + 4}, "\xE2\x8C\x95  commands, addresses, symbols", th.faint, 11);
    p.text({sr.x1() - 28, sr.cy() + 4}, "\xE2\x8C\x98K", th.faint, 10);
    if (p.clicked(sr) && s.commands) s.commands->execute("palette.open", s);
}

void Shell::tab_strip(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    p.rect(r, th.bg);
    p.line({r.x, r.y1()}, {r.x1(), r.y1()}, th.line);
    p.circle({r.x + 16, r.cy()}, 4, th.danger);
    p.circle({r.x + 30, r.cy()}, 4, th.green);

    float tx = r.x + 48;
    const std::string active = s.ctx->active_view();
    for (const View* v : s.registry->views_in("main")) {
        bool on = v->type == active;
        float tw = p.measure(v->title, 11.5f) + 30;
        Rect tabR{tx, r.cy() - 10, tw, 20};
        if (on) {
            p.rect(tabR, th.panel2, 6);
            p.rect_outline(tabR, th.accent_dim, 6, 1);
        }
        Color dot = v->accent ? v->accent : th.accent;
        p.circle({tabR.x + 10, tabR.cy()}, 3.5f, on ? dot : th.faint);
        p.text({tabR.x + 20, tabR.cy() + 4}, v->title, on ? th.text : th.dim, 11.5f);
        if (p.clicked(tabR)) s.ctx->set_active_view(v->type);
        tx += tw + 6;
    }
    Rect plus{tx, r.cy() - 9, 20, 18};
    icon_button(p, th, plus, "+", false, th.panel2, th.dim);

    // theme-accent ovals (the channel selector)
    float ox = r.x1() - 86;
    const char* names[] = {"cyan", "amber", "green"};
    Color cols[] = {th.cyan, th.orange, th.green};
    for (int i = 0; i < 3; ++i) {
        Vec2 c{ox + i * 20, r.cy()};
        bool cur = th.name == names[i];
        if (cur) p.circle(c, 6, cols[i]);
        else p.circle_outline(c, 6, cols[i], 1.5f);
        Rect hit{c.x - 7, c.y - 7, 14, 14};
        if (p.clicked(hit) && s.commands) s.commands->execute("theme.set", s, names[i]);
    }
}

void Shell::sidebar(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    p.rect(r, th.panel);
    p.line({r.x1(), r.y}, {r.x1(), r.y1()}, th.line);
    p.push_clip(r);
    Rect cur = r.inset(0, 0);
    float y = r.y;
    Rect footer = cur.cut_bottom(28);
    for (const SidebarSection& sec : s.registry->sidebar()) {
        if (!sec.draw) continue;
        Rect avail{r.x, y, r.w, cur.y1() - y};
        float used = sec.draw(p, s, avail);
        y += used;
    }
    // footer
    p.line({footer.x, footer.y}, {footer.x1(), footer.y}, th.line);
    Rect nt{footer.x + 10, footer.cy() - 9, 80, 18};
    p.text({nt.x, nt.cy() + 4}, "+ new tab", th.accent, 11);
    if (p.clicked(nt) && s.commands) s.commands->execute("tab.new", s);
    p.pop_clip();
}

void Shell::center(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    Rect panel = r.inset(m.pad);
    const View* v = s.registry->view(s.ctx->active_view());
    if (!v) { auto all = s.registry->views_in("main"); if (!all.empty()) v = all.front(); }
    p.rect(panel, th.panel, th.radius);
    p.rect_outline(panel, th.line2, th.radius, 1);

    // window chrome: title bar + accent underline + window controls
    Rect title = panel; title.h = 26;
    p.rect(title, th.panel2, th.radius);
    p.rect({title.x, title.cy(), title.w, title.h / 2}, th.panel2);  // square the bottom
    Color accent = v && v->accent ? v->accent : th.accent;
    p.line({title.x, title.y}, {title.x1(), title.y}, accent, 2);
    p.text({title.x + 12, title.cy() + 4}, std::string("\xE2\x96\xA0 ") + (v ? v->title : "—"),
           accent, 11.5f);
    const char* wc[] = {"\xE2\x9B\xB6", "\xE2\x97\x90", "\xE2\x96\xA1", "\xE2\x80\x94", "\xC3\x97"};
    float wx = title.x1() - 16;
    for (int i = 4; i >= 0; --i) { p.text({wx, title.cy() + 4}, wc[i], th.faint, 11, Align::Center); wx -= 20; }

    Rect body{panel.x, title.y1(), panel.w, panel.y1() - title.y1()};
    p.push_clip(body);
    if (v && v->draw) v->draw(p, s, body.inset(0));
    p.pop_clip();
}

void Shell::drawer(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    p.rect(r, th.bg);
    p.line({r.x, r.y}, {r.x1(), r.y}, th.line);
    Rect tabs = r; tabs.h = 28;
    float tx = r.x + 14;
    std::string active = s.ctx->str("drawer_view");
    auto views = s.registry->views_in("drawer");
    if (active.empty() && !views.empty()) active = views.front()->type;
    for (const View* v : views) {
        bool on = v->type == active;
        float tw = p.measure(v->title, 11) + 20;
        Rect tR{tx - 6, tabs.cy() - 9, tw, 18};
        if (on) { p.rect(tR, th.panel2, 5); p.rect_outline(tR, th.line, 5, 1); }
        p.text({tx, tabs.cy() + 4}, v->title, on ? th.text : th.dim, 11);
        if (p.clicked(tR)) s.ctx->set_str("drawer_view", v->type);
        tx += tw + 10;
    }
    p.text({r.x1() - 14, tabs.cy() + 4}, "esc drawer  `  quake", th.faint, 10, Align::Right);

    Rect body{r.x, tabs.y1(), r.w, r.y1() - tabs.y1()};
    p.push_clip(body);
    const View* v = s.registry->view(active);
    if (v && v->draw) v->draw(p, s, body);
    p.pop_clip();
}

void Shell::inspector(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    p.rect(r, th.panel);
    p.line({r.x, r.y}, {r.x, r.y1()}, th.line);
    p.text({r.x + 16, r.y + 20}, "PROPERTIES", th.text, 11.5f);
    p.text({r.x1() - 16, r.y + 20}, "follows selection", th.faint, 9.5f, Align::Right);

    // tabs
    const char* tabs[] = {"props", "actions", "flow", "ops"};
    std::string at = s.ctx->str("insp_tab");
    if (at.empty()) at = "props";
    float tx = r.x + 16;
    for (const char* t : tabs) {
        bool on = at == t;
        float tw = p.measure(t, 10.5f) + 16;
        Rect tR{tx - 6, r.y + 30, tw, 18};
        if (on) { p.rect(tR, th.panel2, 5); p.rect_outline(tR, th.accent_dim, 5, 1); }
        p.text({tx, r.y + 43}, t, on ? th.text : th.dim, 10.5f);
        if (p.clicked(tR)) s.ctx->set_str("insp_tab", t);
        tx += tw + 10;
    }

    Rect body{r.x, r.y + 54, r.w, r.y1() - (r.y + 54)};
    p.push_clip(body);
    const InspectorSchema* sch = s.registry->pick_schema(*s.ctx);
    if (sch && sch->render) sch->render(p, s, body.inset(0, 8));
    else p.text({body.x + 16, body.y + 24}, "no selection", th.dim, 11);
    p.pop_clip();
}

void Shell::status_bar(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    p.rect(r, th.bg);
    p.line({r.x, r.y}, {r.x1(), r.y}, th.line);
    float x = r.x + 12;
    for (const StatusItem& it : s.registry->status()) {
        if (!it.text) continue;
        std::string t = it.text(s);
        if (t.empty()) continue;
        Color c = it.color ? it.color(s) : th.dim;
        p.text({x, r.cy() + 4}, t, c, 10.5f);
        x += p.measure(t, 10.5f) + 16;
    }
    std::string hints = s.ctx->str("status_hints");
    if (hints.empty())
        hints = "step F7 \xC2\xB7 back \xE2\x87\xA7" "F7 \xC2\xB7 palette \xE2\x8C\x98K \xC2\xB7 console `";
    p.text({r.x1() - 14, r.cy() + 4}, hints, th.faint, 10, Align::Right);
}

}  // namespace dede::ui
