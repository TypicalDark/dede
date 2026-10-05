// SPDX-License-Identifier: Apache-2.0
//
// Geometry + colour primitives for the backend-agnostic UI. Colours are packed
// 0xRRGGBBAA so a theme is plain data and the SVG and ImGui painters share one
// representation.
#pragma once

#include <cstdint>

namespace dede::ui {

struct Vec2 {
    float x = 0, y = 0;
};

struct Rect {
    float x = 0, y = 0, w = 0, h = 0;
    float x1() const { return x + w; }
    float y1() const { return y + h; }
    float cx() const { return x + w / 2; }
    float cy() const { return y + h / 2; }
    bool contains(Vec2 p) const { return p.x >= x && p.x < x + w && p.y >= y && p.y < y + h; }
    Rect inset(float d) const { return {x + d, y + d, w - 2 * d, h - 2 * d}; }
    Rect inset(float dx, float dy) const { return {x + dx, y + dy, w - 2 * dx, h - 2 * dy}; }
    // Slice `amount` off an edge, returning the slice; the Rect shrinks by it.
    Rect cut_top(float a) { Rect r{x, y, w, a}; y += a; h -= a; return r; }
    Rect cut_bottom(float a) { Rect r{x, y1() - a, w, a}; h -= a; return r; }
    Rect cut_left(float a) { Rect r{x, y, a, h}; x += a; w -= a; return r; }
    Rect cut_right(float a) { Rect r{x1() - a, y, a, h}; w -= a; return r; }
};

using Color = std::uint32_t;  // 0xRRGGBBAA

constexpr Color rgba(std::uint8_t r, std::uint8_t g, std::uint8_t b, std::uint8_t a = 0xff) {
    return (Color(r) << 24) | (Color(g) << 16) | (Color(b) << 8) | Color(a);
}
// From a 0xRRGGBB literal (matches CSS hex tokens), optional alpha.
constexpr Color hexc(std::uint32_t rgb24, std::uint8_t a = 0xff) {
    return (rgb24 << 8) | Color(a);
}
constexpr std::uint8_t red(Color c) { return (c >> 24) & 0xff; }
constexpr std::uint8_t grn(Color c) { return (c >> 16) & 0xff; }
constexpr std::uint8_t blu(Color c) { return (c >> 8) & 0xff; }
constexpr std::uint8_t alpha(Color c) { return c & 0xff; }

// Linear blend a->b by t in [0,1] (ignores alpha, keeps a's).
inline Color mix(Color a, Color b, float t) {
    auto L = [&](std::uint8_t x, std::uint8_t y) {
        return std::uint8_t(x + (int(y) - int(x)) * t);
    };
    return rgba(L(red(a), red(b)), L(grn(a), grn(b)), L(blu(a), blu(b)), alpha(a));
}
constexpr Color with_alpha(Color c, std::uint8_t a) { return (c & 0xffffff00u) | a; }

}  // namespace dede::ui
