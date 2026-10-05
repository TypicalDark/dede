// SPDX-License-Identifier: Apache-2.0
#include "dede/ui/backends/imgui_painter.hpp"

#include "imgui.h"

namespace dede::ui {

namespace {
ImU32 conv(Color c) { return IM_COL32(red(c), grn(c), blu(c), alpha(c)); }
}  // namespace

void ImGuiPainter::rect(Rect r, Color fill, float round) {
    if (alpha(fill) == 0) return;
    dl_->AddRectFilled({r.x, r.y}, {r.x1(), r.y1()}, conv(fill), round);
}

void ImGuiPainter::rect_outline(Rect r, Color col, float round, float thickness) {
    dl_->AddRect({r.x, r.y}, {r.x1(), r.y1()}, conv(col), round, 0, thickness);
}

void ImGuiPainter::line(Vec2 a, Vec2 b, Color col, float thickness) {
    dl_->AddLine({a.x, a.y}, {b.x, b.y}, conv(col), thickness);
}

void ImGuiPainter::circle(Vec2 c, float radius, Color fill) {
    dl_->AddCircleFilled({c.x, c.y}, radius, conv(fill));
}

void ImGuiPainter::circle_outline(Vec2 c, float radius, Color col, float thickness) {
    dl_->AddCircle({c.x, c.y}, radius, conv(col), 0, thickness);
}

void ImGuiPainter::text(Vec2 pos, const std::string& s, Color col, float size, Align a) {
    ImFont* f = font_ ? font_ : ImGui::GetFont();
    float x = pos.x;
    if (a != Align::Left) {
        float w = measure(s, size);
        x -= (a == Align::Center) ? w * 0.5f : w;
    }
    // Our y is the text baseline; ImGui positions by the top-left.
    dl_->AddText(f, size, {x, pos.y - size * 0.80f}, conv(col), s.c_str());
}

float ImGuiPainter::measure(const std::string& s, float size) const {
    // Same monospace metric as the SVG backend so layouts match across backends.
    return static_cast<float>(s.size()) * size * 0.585f;
}

void ImGuiPainter::push_clip(Rect r) {
    dl_->PushClipRect({r.x, r.y}, {r.x1(), r.y1()}, true);
}

void ImGuiPainter::pop_clip() { dl_->PopClipRect(); }

Vec2 ImGuiPainter::mouse() const {
    ImVec2 m = ImGui::GetIO().MousePos;
    return {m.x, m.y};
}
bool ImGuiPainter::mouse_down() const { return ImGui::IsMouseDown(ImGuiMouseButton_Left); }
bool ImGuiPainter::clicked(Rect r) {
    return ImGui::IsMouseClicked(ImGuiMouseButton_Left) && r.contains(mouse());
}
float ImGuiPainter::scroll_y() { return ImGui::GetIO().MouseWheel; }

}  // namespace dede::ui
