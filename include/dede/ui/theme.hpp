// SPDX-License-Identifier: Apache-2.0
//
// The design-system tokens. Every colour the shell and panels draw comes from
// here, so re-skinning the whole UI is a matter of swapping a Theme (exactly the
// git-tool model, where the frontend is driven by CSS custom properties). The
// default palette mirrors git-tool's tokens; `accent`/`accent_dim` are what the
// channel selector (cyan/amber/green ovals) swaps.
#pragma once

#include <string>

#include "dede/ui/geom.hpp"

namespace dede::ui {

struct Theme {
    // surfaces
    Color bg        = hexc(0x0a0e14);  // --bg
    Color bg2       = hexc(0x0f1420);  // --bg-2
    Color panel     = hexc(0x121826);  // --panel
    Color panel2    = hexc(0x182136);  // --panel-2
    Color inset     = hexc(0x090c12);  // input wells / recessed
    Color line      = hexc(0x1f2b42);  // --line
    Color line2     = hexc(0x2a3a58);  // brighter divider / borders

    // text
    Color text      = hexc(0xd9e2ee);  // --text
    Color dim       = hexc(0x8296b0);  // --text-dim
    Color faint     = hexc(0x586274);

    // semantic / status
    Color green     = hexc(0x39ff14);  // --neon
    Color cyan      = hexc(0x00e5ff);  // --neon-2
    Color danger    = hexc(0xff5555);  // --danger
    Color warn      = hexc(0xffe600);  // --warn
    Color purple    = hexc(0x7c5cff);
    Color blue      = hexc(0x4aa3ff);
    Color orange    = hexc(0xff9d3c);
    Color yellow    = hexc(0xffd24a);

    // the live accent (channel) — swapped by the theme selector
    Color accent    = hexc(0x00e5ff);  // cyan by default
    Color accent_dim= hexc(0x0a6b78);

    float radius = 8.0f;
    float font = 12.5f;       // default panel text size
    float font_sm = 11.0f;
    float char_w = 7.25f;     // monospace advance at `font` (for SVG layout)

    std::string name = "cyan";

    // The channel selector (the cyan/amber/green ovals) swaps the accent only.
    static Theme preset(const std::string& which) {
        Theme t;
        if (which == "amber") { t.name = "amber"; t.accent = t.orange; t.accent_dim = hexc(0x6b4310); }
        else if (which == "green") { t.name = "green"; t.accent = t.green; t.accent_dim = hexc(0x1c6b10); }
        else { t.name = "cyan"; t.accent = t.cyan; t.accent_dim = hexc(0x0a6b78); }
        return t;
    }
};

}  // namespace dede::ui
