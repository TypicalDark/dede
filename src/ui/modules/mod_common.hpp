// SPDX-License-Identifier: Apache-2.0
//
// Shared helpers for the UI feature modules: hex formatting and a couple of
// immediate-mode layout helpers (a labelled field, a section header, a vertical
// cursor) so each module stays short.
#pragma once

#include <cstdio>
#include <string>

#include "dede/ui/painter.hpp"
#include "dede/ui/services.hpp"

namespace dede::ui::mod {

inline std::string hx(u64 v, int w = 0) {
    char b[32];
    if (w) std::snprintf(b, sizeof b, "%0*llx", w, (unsigned long long)v);
    else   std::snprintf(b, sizeof b, "%llx", (unsigned long long)v);
    return b;
}
inline std::string hx0(u64 v) { return "0x" + hx(v); }

// A top-down cursor over a column; modules draw rows and advance `y`.
struct Cursor {
    IPainter& p;
    const Theme& th;
    float x, w, y;

    void text(const std::string& s, Color c, float size = 0) {
        p.text({x, y + (size ? size : th.font)}, s, c, size ? size : th.font);
    }
    void row_gap(float h) { y += h; }

    // A labelled, boxed read-only field (inspector style).
    void field(const std::string& label, const std::string& value, Color value_col = 0) {
        p.text({x, y + 10}, label, th.faint, 9.5f);
        Rect box{x - 2, y + 16, w, 20};
        p.rect(box, th.inset, 4);
        p.rect_outline(box, th.line, 4, 1);
        p.text({x + 8, y + 30}, value, value_col ? value_col : th.text, 10.5f);
        y += 40;
    }

    // A faint uppercase section header with an optional right-aligned count.
    void header(const std::string& title, const std::string& right = "") {
        p.text({x, y + 10}, title, th.faint, 9.5f);
        if (!right.empty()) p.text({x + w, y + 10}, right, th.faint, 9.5f, Align::Right);
        y += 18;
    }
};

}  // namespace dede::ui::mod
