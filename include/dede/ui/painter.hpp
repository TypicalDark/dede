// SPDX-License-Identifier: Apache-2.0
//
// IPainter is the one surface the shell and every panel draw through, so the UI
// is backend-agnostic: an SVG painter renders it headlessly (for dede-shot and
// tests, with no GPU), and an ImGui painter renders the live desktop GUI over the
// exact same panel code. Drawing is immediate-mode; input queries return neutral
// values on a draw-only backend (the SVG one), so panels render identically.
#pragma once

#include <string>

#include "dede/ui/geom.hpp"

namespace dede::ui {

enum class Align { Left, Center, Right };

// A few convenience glyphs panels use (the backend maps them to text).
namespace glyph {
constexpr const char* dot = "\xE2\x97\x8F";       // ●
constexpr const char* circle = "\xE2\x97\x8B";    // ○
constexpr const char* play = "\xE2\x96\xB6";      // ▶
constexpr const char* arrow = "\xE2\x86\x92";     // →
constexpr const char* chevron_r = "\xE2\x80\xBA"; // ›
constexpr const char* chevron_l = "\xE2\x80\xB9"; // ‹
constexpr const char* times = "\xC3\x97";          // ×
constexpr const char* check = "\xE2\x9C\x93";     // ✓
}  // namespace glyph

class IPainter {
public:
    virtual ~IPainter() = default;

    // --- drawing ------------------------------------------------------------
    virtual void rect(Rect r, Color fill, float round = 0) = 0;
    virtual void rect_outline(Rect r, Color col, float round = 0, float thickness = 1) = 0;
    virtual void line(Vec2 a, Vec2 b, Color col, float thickness = 1) = 0;
    virtual void circle(Vec2 c, float radius, Color fill) = 0;
    virtual void circle_outline(Vec2 c, float radius, Color col, float thickness = 1) = 0;
    virtual void text(Vec2 pos, const std::string& s, Color col, float size, Align a = Align::Left) = 0;

    // Width of `s` at `size` in pixels (monospace metric by default).
    virtual float measure(const std::string& s, float size) const = 0;
    virtual float line_height(float size) const { return size * 1.5f; }

    // Clip stack: panels push their content rect so overflow is hidden.
    virtual void push_clip(Rect r) = 0;
    virtual void pop_clip() = 0;

    // --- input (draw-only backends return neutral values) -------------------
    virtual Vec2 mouse() const { return {-1, -1}; }
    virtual bool mouse_down() const { return false; }
    virtual bool clicked(Rect /*r*/) { return false; }      // left-click inside r this frame
    virtual bool hovered(Rect r) const { return r.contains(mouse()); }
    virtual float scroll_y() { return 0; }                   // wheel delta for the hovered region

    // --- convenience (default-implemented on top of the primitives) ---------
    void pill(Rect r, Color fill, const std::string& label, Color text_col, float size,
              Color border = 0, float border_w = 1) {
        rect(r, fill, r.h / 2);
        if (border) rect_outline(r, border, r.h / 2, border_w);
        text({r.cx(), r.cy() + size * 0.34f}, label, text_col, size, Align::Center);
    }
};

}  // namespace dede::ui
