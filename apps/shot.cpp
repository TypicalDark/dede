// SPDX-License-Identifier: Apache-2.0
//
// dede-shot — render the GUI workspace to SVG from LIVE engine data.
//
// The Vulkan/ImGui GUI needs a display + GPU, which a headless CI container does
// not have, so we cannot screen-capture it. Instead this tool binds a real
// AnalysisSession (exactly as the GUI does, through IAnalysisEngine), runs a
// tutorial sample, then draws the same docked workspace — menu bar, Disassembly,
// Registers, Stack, Console, Control-Flow Graph, Trace, Timeline, status bar —
// as SVG. Every value shown (register contents, disassembly, CFG blocks/edges,
// stack telescope, trace events, tick counts) is pulled from the engine at draw
// time, with the GUI's own colour palette. The result is a faithful picture of
// what the GUI renders, not a mock-up.
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "dede/analysis/cfg.hpp"
#include "dede/samples/tiers.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {

// ---- GUI palette (mirrors src/gui/workspace.cpp) ---------------------------
constexpr const char* kWindowBg   = "#1c1f24";  // 0.11,0.12,0.14
constexpr const char* kTitleBg    = "#2b3342";  // 0.17,0.20,0.26 title active
constexpr const char* kTabActive  = "#33415c";  // header 0.20,0.24,0.32
constexpr const char* kTabIdle    = "#20242c";
constexpr const char* kPanelBg    = "#15181d";
constexpr const char* kMenuBg     = "#23282f";
constexpr const char* kText       = "#dcdcdc";
constexpr const char* kTextDim    = "#8a8f98";
constexpr const char* kAddr       = "#7896c8";  // kColAddr 120,150,200
constexpr const char* kMnem       = "#dcdcaa";  // kColMnem 220,220,170
constexpr const char* kRegName    = "#8c99cc";  // 0.55,0.6,0.8
constexpr const char* kChanged    = "#e6783c";  // kColChanged 230,120,60
constexpr const char* kRipGreen   = "#80e666";  // => marker 0.5,0.9,0.4
constexpr const char* kFlagOn     = "#66e666";
constexpr const char* kFlagOff    = "#666666";
constexpr const char* kEdgeTaken  = "#5ac85a";  // kColEdgeTaken
constexpr const char* kEdgeNot    = "#c85a5a";  // kColEdgeNot
constexpr const char* kEdgeJmp    = "#b4b4b4";  // kColEdgeJmp
constexpr const char* kNode       = "#282c34";  // kColNode
constexpr const char* kNodeRip    = "#374627";  // kColNodeRip
constexpr const char* kNodeBorder = "#5a5f69";  // kColNodeBorder
constexpr const char* kBp         = "#c84646";  // kColBp
constexpr const char* kAccent     = "#4a90d9";

constexpr double kFont = 12.5;   // panel text
constexpr double kCh   = 7.25;   // monospace advance at kFont

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

std::string hx(u64 v, int w = 0) {
    char b[32];
    if (w) std::snprintf(b, sizeof b, "%0*llx", w, (unsigned long long)v);
    else   std::snprintf(b, sizeof b, "%llx", (unsigned long long)v);
    return b;
}

// A tiny SVG sink.
struct Svg {
    std::ostringstream o;
    double w, h;
    Svg(double W, double H) : w(W), h(H) {
        o << "<svg xmlns='http://www.w3.org/2000/svg' width='" << W << "' height='" << H
          << "' viewBox='0 0 " << W << ' ' << H << "' font-family='ui-monospace,SFMono-Regular,"
             "Menlo,Consolas,monospace'>\n";
    }
    void rect(double x, double y, double w_, double h_, const char* fill,
              double r = 0, const char* stroke = nullptr, double sw = 1) {
        o << "<rect x='" << x << "' y='" << y << "' width='" << w_ << "' height='" << h_
          << "' rx='" << r << "' fill='" << fill << "'";
        if (stroke) o << " stroke='" << stroke << "' stroke-width='" << sw << "'";
        o << "/>\n";
    }
    void line(double x1, double y1, double x2, double y2, const char* col, double w_ = 1.5) {
        o << "<line x1='" << x1 << "' y1='" << y1 << "' x2='" << x2 << "' y2='" << y2
          << "' stroke='" << col << "' stroke-width='" << w_ << "'/>\n";
    }
    void poly(const std::string& pts, const char* fill) {
        o << "<polygon points='" << pts << "' fill='" << fill << "'/>\n";
    }
    void text(double x, double y, const std::string& s, const char* fill = kText,
              double size = kFont, const char* weight = nullptr) {
        o << "<text x='" << x << "' y='" << y << "' fill='" << fill << "' font-size='" << size << "'";
        if (weight) o << " font-weight='" << weight << "'";
        o << ">" << esc(s) << "</text>\n";
    }
    std::string done() { o << "</svg>\n"; return o.str(); }
};

// A panel frame with a tab strip; returns the inner content top-left y.
double panel(Svg& g, double x, double y, double w, double h,
             const std::vector<std::string>& tabs, int active) {
    g.rect(x, y, w, h, kPanelBg, 4, "#2a2f38", 1);
    // tab strip
    double tx = x;
    const double th = 22;
    for (int i = 0; i < (int)tabs.size(); ++i) {
        double tw = tabs[i].size() * kCh + 18;
        g.rect(tx, y, tw, th, i == active ? kTabActive : kTabIdle, 3);
        g.text(tx + 9, y + 15, tabs[i], i == active ? kText : kTextDim, 11.5);
        tx += tw + 2;
    }
    return y + th;
}

// ---- engine setup ----------------------------------------------------------
void load_tier(AnalysisSession& s, int n) {
    auto t = samples::make_tier(n);
    s.map(0x1000, 0x10000, perm::RWX);
    s.map(0x70000, 0x10000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x78000);
    s.load(0x1000, t.image, perm::RWX);
    s.set_entry(t.entry);
}

// ---- panels ----------------------------------------------------------------
void draw_menu(Svg& g, IAnalysisEngine& e, double w) {
    g.rect(0, 0, w, 28, kMenuBg);
    const char* btns[] = {"Run", "Step", "Step Over", "Step Back", "|< Start", "End >|"};
    double x = 8;
    for (auto* b : btns) {
        double bw = std::string(b).size() * kCh + 14;
        g.rect(x, 4, bw, 20, "#2f3742", 3);
        g.text(x + 7, 18, b, "#c8ccd4", 11.5);
        x += bw + 6;
    }
    x += 6;
    // Transparency checkbox
    bool tr = e.transparency_enabled();
    g.rect(x, 7, 14, 14, tr ? kAccent : "#2f3742", 2, "#4a505c", 1);
    if (tr) g.text(x + 2.5, 18, "x", "#ffffff", 11.5);
    g.text(x + 20, 18, "Transparency", "#c8ccd4", 11.5);
}

void draw_status(Svg& g, IAnalysisEngine& e, double w, double h) {
    double y = h - 24;
    g.rect(0, y, w, 24, kMenuBg);
    auto ts = e.timeline_stats();
    std::ostringstream s;
    s << e.phase_name() << " | " << e.backend_name() << " | rip=0x" << hx(e.rip())
      << " | tick " << ts.now << "/" << ts.max << " | ring " << ts.ring << " snap "
      << ts.snapshots << " inj " << ts.injected << " | "
      << (e.transparency_enabled() ? "transparent" : "raw");
    g.text(10, y + 16, s.str(), kTextDim, 11.5);
}

void draw_registers(Svg& g, IAnalysisEngine& e, double x, double y, double w, double h,
                    const std::map<int, u64>& prev) {
    double cy = panel(g, x, y, w, h, {"Registers"}, 0) + 16;
    const char* names[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                             "r8","r9","r10","r11","r12","r13","r14","r15"};
    double colw = (w - 16) / 2;
    for (int i = 0; i < 16; ++i) {
        double rx = x + 10 + (i % 2) * colw;
        double ry = cy + (i / 2) * 18;
        u64 v = e.read_reg(static_cast<Reg>(i));
        bool chg = prev.count(i) && prev.at(i) != v;
        g.text(rx, ry, names[i], kRegName, 11.5);
        g.text(rx + 34, ry, hx(v, 16), chg ? kChanged : kText, 11.5);
    }
    double fy = cy + 8 * 18 + 8;
    g.line(x + 8, fy - 10, x + w - 8, fy - 10, "#2a2f38", 1);
    g.text(x + 10, fy, "rip " + hx(e.rip(), 16), kText, 11.5);
    u64 fl = e.rflags();
    struct F { const char* n; u64 m; } fs[] = {
        {"CF", flags::CF}, {"PF", flags::PF}, {"ZF", flags::ZF},
        {"SF", flags::SF}, {"OF", flags::OF}};
    double flx = x + 10;
    g.text(flx, fy + 18, "flags", kTextDim, 11.5);
    flx += 44;
    for (auto& f : fs) {
        g.text(flx, fy + 18, f.n, (fl & f.m) ? kFlagOn : kFlagOff, 11.5);
        flx += 26;
    }
}

void draw_disassembly(Svg& g, IAnalysisEngine& e, double x, double y, double w, double h) {
    double cy = panel(g, x, y, w, h, {"Disassembly", "Control-Flow Graph", "Decompiler"}, 0) + 8;
    g.text(x + 10, cy + 8, "[x] follow rip    goto: " + hx(e.rip()), kTextDim, 11);
    cy += 24;
    g.line(x + 8, cy - 6, x + w - 8, cy - 6, "#2a2f38", 1);
    auto insns = e.disassemble(e.rip(), 28);
    double ly = cy + 10;
    Addr rip = e.rip();
    int after_term = -1;  // >=0 once we pass a hlt/ret/unconditional jmp
    for (const auto& in : insns) {
        if (ly > y + h - 10) break;
        // Keep the view purposeful: once the function ends (hlt/ret/jmp away),
        // show a couple of trailing (padding/uninitialised) lines then stop.
        std::string m0 = in.text().substr(0, in.text().find(' '));
        if (after_term >= 0 && ++after_term > 2) {
            g.text(x + 48, ly, "; ... (uninitialised / padding)", kTextDim, 11);
            break;
        }
        if (after_term < 0 && (m0 == "hlt" || m0 == "ret" || m0 == "jmp"))
            after_term = 0;
        bool is_rip = in.addr == rip;
        bool is_bp = false;
        for (const auto& rp : e.run_points())
            if (rp.type == RunPointType::Address && rp.address == in.addr) is_bp = true;
        if (is_rip) g.rect(x + 6, ly - 11, w - 12, 16, "#243018", 2);
        g.text(x + 12, ly, is_bp ? "●" : "○", is_bp ? kBp : "#555b66", 11);
        g.text(x + 28, ly, is_rip ? "=>" : "  ", kRipGreen, 11.5);
        g.text(x + 48, ly, hx(in.addr, 8), kAddr, 11.5);
        // split mnemonic / operands by first space for colour
        std::string t = in.text();
        std::string mnem = t, rest;
        auto sp = t.find(' ');
        if (sp != std::string::npos) { mnem = t.substr(0, sp); rest = t.substr(sp); }
        g.text(x + 48 + 9 * kCh, ly, mnem, kMnem, 11.5);
        if (!rest.empty())
            g.text(x + 48 + 9 * kCh + (mnem.size()) * kCh, ly, rest, kText, 11.5);
        ly += 16;
    }
}

void draw_stack(Svg& g, IAnalysisEngine& e, double x, double y, double w, double h) {
    double cy = panel(g, x, y, w, h, {"Stack", "Memory"}, 0) + 16;
    u64 sp = e.read_reg(Reg::Rsp);
    for (int i = 0; i < 14; ++i) {
        double ly = cy + i * 17;
        if (ly > y + h - 8) break;
        Addr at = sp + i * 8;
        auto v = e.read_mem(at, 8);
        std::string row = (i == 0 ? "rsp " : "    ") + hx(at, 16) + " : " +
                          (v ? hx(v.value(), 16) : std::string("????????????????"));
        g.text(x + 10, ly, row, i == 0 ? kAccent : kText, 11.5);
    }
}

void draw_console(Svg& g, double x, double y, double w, double h, const std::string& log) {
    double cy = panel(g, x, y, w, h,
                      {"Console", "Trace", "Run Points", "Timeline", "Memory Map", "Architecture"}, 0) + 14;
    std::istringstream ss(log);
    std::string line;
    double ly = cy;
    while (std::getline(ss, line)) {
        if (ly > y + h - 24) break;
        bool prompt = line.rfind("dede>", 0) == 0;
        g.text(x + 10, ly, line, prompt ? kAccent : kText, 11);
        ly += 15;
    }
    // input box
    g.rect(x + 8, y + h - 20, w - 16, 15, "#0e1013", 2, "#2a2f38", 1);
    g.text(x + 12, y + h - 9, "_", kTextDim, 11);
}

void draw_cfg(Svg& g, IAnalysisEngine& e, double x, double y, double w, double h, Addr entry) {
    double cy = panel(g, x, y, w, h, {"Disassembly", "Control-Flow Graph", "Decompiler"}, 1) + 8;
    g.text(x + 10, cy + 8, "entry 0x" + hx(entry) + "   [rebuild from rip]", kTextDim, 11);
    cy += 20;
    Cfg cfg = e.build_cfg(entry);
    auto pos = cfg.layout();
    const double colw = 236, rowh = 128, nodew = 196, nodeh = 104;
    double ox = x + 24, oy = cy + 14;
    Addr rip = e.rip();
    auto nx = [&](int col) { return ox + col * colw; };
    auto ny = [&](int row) { return oy + row * rowh; };
    // edges
    for (const auto& ed : cfg.edges) {
        if (!pos.count(ed.from) || !pos.count(ed.to)) continue;
        double ax = nx(pos[ed.from].first) + nodew / 2, ay = ny(pos[ed.from].second) + nodeh;
        double bx = nx(pos[ed.to].first) + nodew / 2, by = ny(pos[ed.to].second);
        const char* col = ed.kind == EdgeKind::Taken ? kEdgeTaken
                        : ed.kind == EdgeKind::NotTaken ? kEdgeNot : kEdgeJmp;
        g.line(ax, ay, bx, by, col, 1.8);
        // arrowhead
        g.poly(std::to_string(bx) + "," + std::to_string(by) + " " +
               std::to_string(bx - 4) + "," + std::to_string(by - 7) + " " +
               std::to_string(bx + 4) + "," + std::to_string(by - 7), col);
    }
    // nodes
    for (const auto& bb : cfg.blocks) {
        if (!pos.count(bb.start)) continue;
        double px = nx(pos[bb.start].first), py = ny(pos[bb.start].second);
        bool has_rip = rip >= bb.start && rip < bb.end;
        g.rect(px, py, nodew, nodeh, has_rip ? kNodeRip : kNode, 4, kNodeBorder, 1.2);
        g.text(px + 6, py + 15, "loc_" + hx(bb.start), kAddr, 11, "bold");
        double iy = py + 32;
        for (std::size_t i = 0; i < bb.insns.size() && i < 5; ++i) {
            g.text(px + 8, iy, bb.insns[i].text(), "#c8c8c8", 10.5);
            iy += 14;
        }
        if (bb.insns.size() > 5)
            g.text(px + 8, iy, "... (+" + std::to_string(bb.insns.size() - 5) + ")", kTextDim, 10.5);
    }
}

void draw_trace(Svg& g, IAnalysisEngine& e, double x, double y, double w, double h) {
    double cy = panel(g, x, y, w, h,
                      {"Console", "Trace", "Run Points", "Timeline", "Memory Map", "Architecture"}, 1) + 14;
    const auto& ev = e.history().events();
    std::size_t start = ev.size() > 16 ? ev.size() - 16 : 0;
    double ly = cy;
    for (std::size_t i = start; i < ev.size(); ++i) {
        if (ly > y + h - 8) break;
        const Event& x2 = ev[i];
        std::ostringstream s;
        s << "[t=" << x2.tick << "] " << to_string(x2.kind) << " @ 0x" << hx(x2.pc);
        if (x2.kind == EventKind::MemRead || x2.kind == EventKind::MemWrite)
            s << "  0x" << hx(x2.address) << " = 0x" << hx(x2.value);
        const char* col = x2.kind == EventKind::MemWrite ? kChanged
                        : x2.kind == EventKind::Syscall ? kRipGreen : kText;
        g.text(x + 10, ly, s.str(), col, 11);
        ly += 15;
    }
}

void draw_timeline_strip(Svg& g, IAnalysisEngine& e, double x, double y, double w) {
    auto ts = e.timeline_stats();
    g.text(x + 10, y + 14, "Timeline   tick " + std::to_string(ts.now) + " / " +
           std::to_string(ts.max), kText, 11.5);
    double bx = x + 10, bw = w - 20, by = y + 24;
    g.rect(bx, by, bw, 10, "#0e1013", 4, "#2a2f38", 1);
    double frac = ts.max ? (double)ts.now / ts.max : 0;
    g.rect(bx, by, bw * frac, 10, kAccent, 4);
    g.rect(bx + bw * frac - 3, by - 2, 6, 14, "#cfe4ff", 3);
    g.text(x + 10, y + 50, "[<< -10]  [< -1]  [+1 >]", kTextDim, 11);
}

// ---- full workspace --------------------------------------------------------
std::string render_workspace(IAnalysisEngine& e, int active_bottom, Addr cfg_entry,
                             const std::string& console_log, bool cfg_tab,
                             const std::map<int, u64>& prev_regs) {
    const double W = 1360, H = 840;
    Svg g(W, H);
    g.rect(0, 0, W, H, kWindowBg);
    draw_menu(g, e, W);

    const double top = 30, bot = H - 26;
    const double rightw = 360, rightx = W - rightw;
    const double bottomh = 232, bottomy = bot - bottomh;

    // left/center big panel (disasm or cfg)
    if (cfg_tab) draw_cfg(g, e, 4, top, rightx - 8, bottomy - top - 4, cfg_entry);
    else         draw_disassembly(g, e, 4, top, rightx - 8, bottomy - top - 4);

    // right column: Registers (top) + Stack (bottom)
    double regh = (bot - top) * 0.55;
    draw_registers(g, e, rightx, top, rightw - 4, regh - 4, prev_regs);
    draw_stack(g, e, rightx, top + regh, rightw - 4, (bot - top) - regh - 4);

    // bottom strip: console / trace / timeline
    double bw = rightx - 8;
    if (active_bottom == 1) draw_trace(g, e, 4, bottomy, bw, bottomh);
    else if (active_bottom == 3) {
        panel(g, 4, bottomy, bw, bottomh,
              {"Console", "Trace", "Run Points", "Timeline", "Memory Map", "Architecture"}, 3);
        draw_timeline_strip(g, e, 4, bottomy + 30, bw);
    } else draw_console(g, 4, bottomy, bw, bottomh, console_log);

    // the timeline mini-strip also lives under the right column's bottom in every view
    draw_status(g, e, W, H);
    return g.done();
}

void write_file(const std::string& path, const std::string& data) {
    std::ofstream f(path);
    f << data;
    std::printf("wrote %s (%zu bytes)\n", path.c_str(), data.size());
}

}  // namespace

int main(int argc, char** argv) {
    std::string dir = argc >= 2 ? argv[1] : "docs/img";

    // --- Shot 1: overview — tier 1 arithmetic loop, stepped a few times -------
    {
        AnalysisSession s(Arch::X86_64);
        load_tier(s, 1);
        std::map<int, u64> prev;
        for (int i = 0; i < 16; ++i) prev[i] = s.read_reg(static_cast<Reg>(i));
        for (int i = 0; i < 5; ++i) s.step();  // run into the loop body
        std::string log =
            "dede> open tier1.bin\n"
            "opened tier1.bin [flat] entry=0x1000\n"
            "dede> info\n"
            "format: flat   entry/rip: 0x1000   arch: x86-64\n"
            "dede> step 5\n"
            "dede> where\n"
            "0x" + hx(s.rip()) + "   (tick " + std::to_string(s.now()) + ")\n";
        write_file(dir + "/dede-ui-overview.svg",
                   render_workspace(s, 0, 0x1000, log, false, prev));
    }

    // --- Shot 2: control-flow graph — tier 4 (branches) -----------------------
    {
        AnalysisSession s(Arch::X86_64);
        load_tier(s, 4);
        write_file(dir + "/dede-ui-cfg.svg",
                   render_workspace(s, 4, 0x1000, "", true, {}));
    }

    // --- Shot 3: time-travel — tier 5 self-modifying, run then step back -------
    {
        AnalysisSession s(Arch::X86_64);
        load_tier(s, 5);
        std::map<int, u64> prev;
        for (int i = 0; i < 16; ++i) prev[i] = s.read_reg(static_cast<Reg>(i));
        s.run(400);                 // let it decrypt/mutate and hit the syscall/hlt
        s.step_back(6);             // travel backwards
        write_file(dir + "/dede-ui-timetravel.svg",
                   render_workspace(s, 3, 0x1000, "", false, prev));
        // and a trace-focused variant from the same session
        write_file(dir + "/dede-ui-trace.svg",
                   render_workspace(s, 1, 0x1000, "", false, prev));
    }

    return 0;
}
