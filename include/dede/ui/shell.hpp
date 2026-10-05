// SPDX-License-Identifier: Apache-2.0
//
// The Shell draws the whole git-tool-style chrome from the Registry, through an
// IPainter: title bar (logo + state chip + toolbar + command search + OPEN), the
// workspace tab strip, the left history/sidebar, the active centre view with its
// window chrome, the right "Properties follows selection" inspector, the bottom
// quake drawer, and the status bar. It owns no feature logic — everything it
// shows is a registered contribution — so it never changes as modules are added.
#pragma once

#include "dede/ui/painter.hpp"
#include "dede/ui/services.hpp"

namespace dede::ui {

class Shell {
public:
    // Draw one frame of the entire application into `bounds`.
    void draw(IPainter& p, Services& s, Rect bounds);

    // Region heights/widths (tunable; the ImGui and SVG backends share them).
    struct Metrics {
        float titlebar = 34, tabstrip = 32, statusbar = 26;
        float sidebar = 248, inspector = 346, drawer = 210;
        float pad = 10;
    } m;

private:
    void title_bar(IPainter&, Services&, Rect);
    void tab_strip(IPainter&, Services&, Rect);
    void sidebar(IPainter&, Services&, Rect);
    void center(IPainter&, Services&, Rect);
    void drawer(IPainter&, Services&, Rect);
    void inspector(IPainter&, Services&, Rect);
    void status_bar(IPainter&, Services&, Rect);
};

}  // namespace dede::ui
