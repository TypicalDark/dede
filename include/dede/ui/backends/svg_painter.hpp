// SPDX-License-Identifier: Apache-2.0
//
// A draw-only IPainter that emits SVG — the headless backend. It lets dede-shot
// and tests render the entire shell (every panel, drawn through the same code
// the desktop GUI uses) with no GPU or display. Input queries return neutral
// values, so a render is a faithful snapshot of a given Context/selection state.
#pragma once

#include <sstream>
#include <string>
#include <vector>

#include "dede/ui/painter.hpp"

namespace dede::ui {

class SvgPainter final : public IPainter {
public:
    SvgPainter(float w, float h, Color background);

    // drawing
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

    // Finish and return the complete SVG document.
    std::string finish();

private:
    std::ostringstream o_;
    float w_, h_;
    int clip_id_ = 0;
    std::vector<int> clip_stack_;
    bool done_ = false;
};

}  // namespace dede::ui
