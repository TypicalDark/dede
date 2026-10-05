// SPDX-License-Identifier: Apache-2.0
//
// The ImGui IPainter backend: renders the shell through a Dear ImGui draw list
// and reads input from ImGui's IO. The desktop GUI runs the exact same Shell and
// panel code as the headless SVG render — only this painter differs. It is built
// only under DEDE_WITH_GUI. Measurement uses the same monospace metric as the SVG
// backend so layouts are pixel-identical across backends (load a mono UI font).
#pragma once

#include "dede/ui/painter.hpp"

struct ImDrawList;
struct ImFont;

namespace dede::ui {

class ImGuiPainter final : public IPainter {
public:
    // `font` may be null -> the current ImGui font is used at draw time.
    ImGuiPainter(ImDrawList* dl, ImFont* font = nullptr) : dl_(dl), font_(font) {}

    void rect(Rect r, Color fill, float round = 0) override;
    void rect_outline(Rect r, Color col, float round = 0, float thickness = 1) override;
    void line(Vec2 a, Vec2 b, Color col, float thickness = 1) override;
    void circle(Vec2 c, float radius, Color fill) override;
    void circle_outline(Vec2 c, float radius, Color col, float thickness = 1) override;
    void text(Vec2 pos, const std::string& s, Color col, float size, Align a = Align::Left) override;
    float measure(const std::string& s, float size) const override;
    float line_height(float size) const override { return size * 1.5f; }
    void push_clip(Rect r) override;
    void pop_clip() override;

    Vec2 mouse() const override;
    bool mouse_down() const override;
    bool clicked(Rect r) override;
    float scroll_y() override;

private:
    ImDrawList* dl_;
    ImFont* font_;
};

}  // namespace dede::ui
