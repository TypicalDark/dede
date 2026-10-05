// SPDX-License-Identifier: Apache-2.0
#include "dede/ui/backends/svg_painter.hpp"

#include <cstdio>

namespace dede::ui {

namespace {
std::string color_hex(Color c) {
    char b[8];
    std::snprintf(b, sizeof b, "#%02x%02x%02x", red(c), grn(c), blu(c));
    return b;
}
std::string esc(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '&': o += "&amp;"; break;
            case '<': o += "&lt;"; break;
            case '>': o += "&gt;"; break;
            case '"': o += "&quot;"; break;
            default: o += c;
        }
    }
    return o;
}
// Opacity attribute string for a colour's alpha, or empty when fully opaque.
std::string op_attr(const char* which, Color c) {
    if (alpha(c) == 0xff) return {};
    char b[48];
    std::snprintf(b, sizeof b, " %s=\"%.3f\"", which, alpha(c) / 255.0);
    return b;
}
}  // namespace

SvgPainter::SvgPainter(float w, float h, Color background) : w_(w), h_(h) {
    o_ << "<svg xmlns='http://www.w3.org/2000/svg' width='" << w << "' height='" << h
       << "' viewBox='0 0 " << w << ' ' << h
       << "' font-family='ui-monospace,SFMono-Regular,Menlo,Consolas,monospace'>\n";
    rect({0, 0, w, h}, background, 0);
}

void SvgPainter::rect(Rect r, Color fill, float round) {
    if (alpha(fill) == 0) return;
    o_ << "<rect x='" << r.x << "' y='" << r.y << "' width='" << r.w << "' height='" << r.h
       << "' rx='" << round << "' fill='" << color_hex(fill) << "'" << op_attr("fill-opacity", fill)
       << "/>\n";
}

void SvgPainter::rect_outline(Rect r, Color col, float round, float thickness) {
    o_ << "<rect x='" << r.x << "' y='" << r.y << "' width='" << r.w << "' height='" << r.h
       << "' rx='" << round << "' fill='none' stroke='" << color_hex(col) << "' stroke-width='"
       << thickness << "'" << op_attr("stroke-opacity", col) << "/>\n";
}

void SvgPainter::line(Vec2 a, Vec2 b, Color col, float thickness) {
    o_ << "<line x1='" << a.x << "' y1='" << a.y << "' x2='" << b.x << "' y2='" << b.y
       << "' stroke='" << color_hex(col) << "' stroke-width='" << thickness << "'"
       << op_attr("stroke-opacity", col) << "/>\n";
}

void SvgPainter::circle(Vec2 c, float radius, Color fill) {
    o_ << "<circle cx='" << c.x << "' cy='" << c.y << "' r='" << radius << "' fill='"
       << color_hex(fill) << "'" << op_attr("fill-opacity", fill) << "/>\n";
}

void SvgPainter::circle_outline(Vec2 c, float radius, Color col, float thickness) {
    o_ << "<circle cx='" << c.x << "' cy='" << c.y << "' r='" << radius << "' fill='none' stroke='"
       << color_hex(col) << "' stroke-width='" << thickness << "'/>\n";
}

void SvgPainter::text(Vec2 pos, const std::string& s, Color col, float size, Align a) {
    const char* anchor = a == Align::Center ? "middle" : a == Align::Right ? "end" : "start";
    o_ << "<text x='" << pos.x << "' y='" << pos.y << "' fill='" << color_hex(col)
       << "' font-size='" << size << "' text-anchor='" << anchor << "'"
       << op_attr("fill-opacity", col) << ">" << esc(s) << "</text>\n";
}

float SvgPainter::measure(const std::string& s, float size) const {
    // Monospace advance; good enough for layout and matches the mono font above.
    return static_cast<float>(s.size()) * size * 0.585f;
}

void SvgPainter::push_clip(Rect r) {
    int id = ++clip_id_;
    clip_stack_.push_back(id);
    o_ << "<clipPath id='c" << id << "'><rect x='" << r.x << "' y='" << r.y << "' width='" << r.w
       << "' height='" << r.h << "'/></clipPath>\n<g clip-path='url(#c" << id << ")'>\n";
}

void SvgPainter::pop_clip() {
    if (clip_stack_.empty()) return;
    clip_stack_.pop_back();
    o_ << "</g>\n";
}

std::string SvgPainter::finish() {
    if (!done_) {
        while (!clip_stack_.empty()) pop_clip();
        o_ << "</svg>\n";
        done_ = true;
    }
    return o_.str();
}

}  // namespace dede::ui
