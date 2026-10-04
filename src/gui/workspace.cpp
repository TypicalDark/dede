// SPDX-License-Identifier: Apache-2.0
#include "dede/gui/workspace.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "imgui.h"
#include "imgui_internal.h"  // DockBuilder

#include "dede/analysis/arch_view.hpp"

namespace dede::gui {
namespace {

constexpr ImU32 kColAddr = IM_COL32(120, 150, 200, 255);
constexpr ImU32 kColMnem = IM_COL32(220, 220, 170, 255);
constexpr ImU32 kColRip = IM_COL32(60, 90, 40, 255);
constexpr ImU32 kColBp = IM_COL32(200, 70, 70, 255);
constexpr ImU32 kColChanged = IM_COL32(230, 120, 60, 255);
constexpr ImU32 kColEdgeTaken = IM_COL32(90, 200, 90, 255);
constexpr ImU32 kColEdgeNot = IM_COL32(200, 90, 90, 255);
constexpr ImU32 kColEdgeJmp = IM_COL32(180, 180, 180, 255);
constexpr ImU32 kColNode = IM_COL32(40, 44, 52, 255);
constexpr ImU32 kColNodeRip = IM_COL32(55, 70, 45, 255);
constexpr ImU32 kColNodeBorder = IM_COL32(90, 95, 105, 255);

std::string hx(u64 v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    return b;
}

void apply_theme() {
    ImGui::StyleColorsDark();
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 4.0f;
    s.FrameRounding = 3.0f;
    s.GrabRounding = 3.0f;
    s.ScrollbarRounding = 3.0f;
    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg] = ImVec4(0.11f, 0.12f, 0.14f, 1.0f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.17f, 0.20f, 0.26f, 1.0f);
    c[ImGuiCol_Header] = ImVec4(0.20f, 0.24f, 0.32f, 1.0f);
}

}  // namespace

Workspace::Workspace(IAnalysisEngine& engine, IScriptEngine& script)
    : e_(engine), script_(script) {
    shell_ = std::make_unique<Shell>(e_, script_, console_out_);
}
Workspace::~Workspace() = default;

void Workspace::attach() { e_.subscribe(&trace_); }
void Workspace::detach() { e_.unsubscribe(&trace_); }

void Workspace::draw() {
    if (first_frame_) { apply_theme(); first_frame_ = false; }
    model_.refresh(e_);
    if (dis_follow_rip_) dis_addr_ = model_.rip;

    ImGuiID dock = ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
    if (!layout_built_) { build_default_layout(dock); layout_built_ = true; }

    draw_menu_and_toolbar();
    draw_registers();
    draw_disassembly();
    draw_hex();
    draw_stack();
    draw_run_points();
    draw_trace();
    draw_console();
    draw_decompiler();
    draw_timeline();
    draw_cfg();
    draw_memory_map();
    draw_architecture();
    draw_status_bar();
}

void Workspace::build_default_layout(unsigned dock_id) {
    ImGuiID root = dock_id;
    ImGui::DockBuilderRemoveNode(root);
    ImGui::DockBuilderAddNode(root, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(root, ImGui::GetMainViewport()->Size);

    ImGuiID right = ImGui::DockBuilderSplitNode(root, ImGuiDir_Right, 0.28f, nullptr, &root);
    ImGuiID bottom = ImGui::DockBuilderSplitNode(root, ImGuiDir_Down, 0.30f, nullptr, &root);
    ImGuiID right_bottom = ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.45f, nullptr, &right);

    ImGui::DockBuilderDockWindow("Disassembly", root);
    ImGui::DockBuilderDockWindow("Control-Flow Graph", root);
    ImGui::DockBuilderDockWindow("Decompiler", root);
    ImGui::DockBuilderDockWindow("Registers", right);
    ImGui::DockBuilderDockWindow("Stack", right_bottom);
    ImGui::DockBuilderDockWindow("Memory", right_bottom);
    ImGui::DockBuilderDockWindow("Console", bottom);
    ImGui::DockBuilderDockWindow("Trace", bottom);
    ImGui::DockBuilderDockWindow("Run Points", bottom);
    ImGui::DockBuilderDockWindow("Timeline", bottom);
    ImGui::DockBuilderDockWindow("Memory Map", bottom);
    ImGui::DockBuilderDockWindow("Architecture", bottom);
    ImGui::DockBuilderFinish(dock_id);
}

void Workspace::draw_menu_and_toolbar() {
    if (ImGui::BeginMainMenuBar()) {
        bool can = e_.phase() == Phase::Paused;
        if (ImGui::Button("Run") && can) e_.run();
        ImGui::SameLine();
        if (ImGui::Button("Step") && can) e_.step();
        ImGui::SameLine();
        if (ImGui::Button("Step Over") && can) {
            auto ins = e_.disassemble(model_.rip, 1);
            if (!ins.empty()) e_.run_to(model_.rip + ins[0].size);
        }
        ImGui::SameLine();
        if (ImGui::Button("Step Back") && can) e_.step_back(1);
        ImGui::SameLine();
        if (ImGui::Button("|< Start")) e_.seek(0);
        ImGui::SameLine();
        if (ImGui::Button("End >|")) e_.seek(e_.timeline_stats().max);
        ImGui::SameLine();
        ImGui::Separator();
        ImGui::SameLine();
        bool tr = model_.transparency;
        if (ImGui::Checkbox("Transparency", &tr)) {
            if (tr) e_.enable_transparency(); else e_.disable_transparency();
        }
        ImGui::EndMainMenuBar();
    }
}

void Workspace::draw_status_bar() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    if (ImGui::BeginViewportSideBar("##status", vp, ImGuiDir_Down, ImGui::GetFrameHeight(),
                                    ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings)) {
        if (ImGui::BeginMenuBar()) {
            ImGui::Text("%s | %s | rip=%s | tick %llu/%llu | ring %zu snap %zu inj %zu | %s",
                        model_.phase.c_str(), model_.backend.c_str(), hx(model_.rip).c_str(),
                        (unsigned long long)model_.timeline.now, (unsigned long long)model_.timeline.max,
                        model_.timeline.ring, model_.timeline.snapshots, model_.timeline.injected,
                        model_.transparency ? "transparent" : "raw");
            ImGui::EndMenuBar();
        }
        ImGui::End();
    }
}

void Workspace::draw_registers() {
    if (ImGui::Begin("Registers")) {
        if (ImGui::BeginTable("regs", 2, ImGuiTableFlags_SizingFixedFit)) {
            for (int i = 0; i < 16; ++i) {
                Reg r = static_cast<Reg>(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(0.55f, 0.6f, 0.8f, 1), "%-3s", std::string(reg_name(r)).c_str());
                ImGui::TableNextColumn();
                ImU32 col = model_.reg_changed(r) ? kColChanged : IM_COL32(220, 220, 220, 255);
                char buf[20];
                std::snprintf(buf, sizeof buf, "%016llx", (unsigned long long)model_.regs[i]);
                ImGui::PushStyleColor(ImGuiCol_Text, col);
                if (ImGui::Selectable(buf, false, ImGuiSelectableFlags_AllowDoubleClick) &&
                    ImGui::IsMouseDoubleClicked(0)) {
                    hex_addr_ = model_.regs[i];  // follow value into memory view
                }
                ImGui::PopStyleColor();
            }
            ImGui::EndTable();
        }
        ImGui::Separator();
        ImGui::Text("rip %016llx", (unsigned long long)model_.rip);
        u64 fl = model_.rflags;
        auto chip = [&](const char* n, u64 mask) {
            bool on = fl & mask;
            ImGui::SameLine();
            ImGui::TextColored(on ? ImVec4(0.4f, 0.9f, 0.4f, 1) : ImVec4(0.4f, 0.4f, 0.4f, 1), "%s", n);
        };
        ImGui::Text("flags");
        chip("CF", flags::CF); chip("PF", flags::PF); chip("ZF", flags::ZF);
        chip("SF", flags::SF); chip("OF", flags::OF);
    }
    ImGui::End();
}

void Workspace::draw_disassembly() {
    if (ImGui::Begin("Disassembly")) {
        ImGui::Checkbox("follow rip", &dis_follow_rip_);
        ImGui::SameLine();
        char g[20];
        std::snprintf(g, sizeof g, "%llx", (unsigned long long)dis_addr_);
        ImGui::SetNextItemWidth(160);
        if (ImGui::InputText("goto", g, sizeof g, ImGuiInputTextFlags_EnterReturnsTrue)) {
            dis_addr_ = std::strtoull(g, nullptr, 16);
            dis_follow_rip_ = false;
        }
        ImGui::Separator();
        auto insns = e_.disassemble(dis_addr_, 64);
        ImGui::BeginChild("dis_list");
        for (const auto& in : insns) {
            bool is_bp = false, is_rip = (in.addr == model_.rip);
            for (const auto& rp : e_.run_points())
                if (rp.type == RunPointType::Address && rp.address == in.addr) is_bp = true;
            ImGui::PushID((int)in.addr);
            if (ImGui::SmallButton(is_bp ? "●" : "○")) {
                if (is_bp) {
                    for (const auto& rp : e_.run_points())
                        if (rp.type == RunPointType::Address && rp.address == in.addr)
                            e_.remove_run_point(rp.id);
                } else {
                    e_.add_breakpoint(in.addr, "");
                }
            }
            ImGui::SameLine();
            if (is_rip) ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.4f, 1), "=>"); else ImGui::TextUnformatted("  ");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.47f, 0.6f, 0.8f, 1), "%08llx", (unsigned long long)in.addr);
            ImGui::SameLine();
            auto sym = e_.symbols().describe(in.addr);
            std::string label = in.text();
            if (sym) label = "<" + *sym + "> " + label;
            if (ImGui::Selectable(label.c_str(), is_rip, ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0) && !in.operands.empty() &&
                    in.operands[0].kind == OpKind::Imm && in.cf.is_branch) {
                    dis_addr_ = static_cast<Addr>(in.operands[0].imm);
                    dis_follow_rip_ = false;
                }
            }
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("Run to here")) e_.run_to(in.addr);
                if (ImGui::MenuItem("Toggle breakpoint")) {
                    if (is_bp) { for (const auto& rp : e_.run_points())
                        if (rp.type == RunPointType::Address && rp.address == in.addr) e_.remove_run_point(rp.id);
                    } else e_.add_breakpoint(in.addr, "");
                }
                if (ImGui::MenuItem("View CFG from here")) { cfg_entry_ = in.addr; cfg_valid_ = false; }
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    ImGui::End();
}

void Workspace::draw_hex() {
    if (ImGui::Begin("Memory")) {
        char g[20];
        std::snprintf(g, sizeof g, "%llx", (unsigned long long)hex_addr_);
        ImGui::SetNextItemWidth(160);
        if (ImGui::InputText("addr", g, sizeof g, ImGuiInputTextFlags_EnterReturnsTrue))
            hex_addr_ = std::strtoull(g, nullptr, 16);
        ImGui::Separator();
        ImGui::BeginChild("hexview");
        for (int row = 0; row < 32; ++row) {
            Addr base = hex_addr_ + row * 16;
            std::string line, ascii;
            char ab[20];
            std::snprintf(ab, sizeof ab, "%012llx", (unsigned long long)base);
            for (int col = 0; col < 16; ++col) {
                auto b = e_.read_mem(base + col, 1);
                char h[4];
                if (b) { std::snprintf(h, sizeof h, "%02x ", (unsigned)b.value()); ascii += (b.value() >= 32 && b.value() < 127) ? (char)b.value() : '.'; }
                else { std::snprintf(h, sizeof h, "?? "); ascii += '.'; }
                line += h;
            }
            ImGui::Text("%s  %s  %s", ab, line.c_str(), ascii.c_str());
        }
        ImGui::EndChild();
    }
    ImGui::End();
}

void Workspace::draw_stack() {
    if (ImGui::Begin("Stack")) {
        u64 sp = model_.regs[static_cast<int>(Reg::Rsp)];
        for (int i = 0; i < 16; ++i) {
            Addr at = sp + i * 8;
            auto v = e_.read_mem(at, 8);
            std::string ann;
            if (v) if (auto s = e_.symbols().describe(v.value())) ann = " <" + *s + ">";
            ImGui::Text("%s%016llx : %s%s", i == 0 ? "rsp " : "    ", (unsigned long long)at,
                        v ? hx(v.value()).c_str() : "????", ann.c_str());
        }
    }
    ImGui::End();
}

void Workspace::draw_run_points() {
    if (ImGui::Begin("Run Points")) {
        for (const auto& rp : e_.run_points()) {
            ImGui::PushID((int)rp.id);
            bool en = rp.enabled;
            if (ImGui::Checkbox("##en", &en)) e_.enable_run_point(rp.id, en);
            ImGui::SameLine();
            ImGui::Text("#%llu %s %s%s hits=%llu", (unsigned long long)rp.id, to_string(rp.type),
                        rp.type == RunPointType::Address ? hx(rp.address).c_str() : "",
                        rp.macro ? " [macro]" : (rp.pause ? " [break]" : ""),
                        (unsigned long long)rp.hit_count);
            ImGui::SameLine();
            if (ImGui::SmallButton("x")) e_.remove_run_point(rp.id);
            ImGui::PopID();
        }
    }
    ImGui::End();
}

void Workspace::draw_trace() {
    if (ImGui::Begin("Trace")) {
        const auto& ev = trace_.events();
        ImGuiListClipper clip;
        clip.Begin((int)ev.size());
        while (clip.Step())
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const Event& e = ev[(size_t)i];
                ImGui::Text("[t=%llu] %-16s @ %s %s", (unsigned long long)e.tick, to_string(e.kind),
                            hx(e.pc).c_str(),
                            (e.kind == EventKind::MemRead || e.kind == EventKind::MemWrite)
                                ? hx(e.address).c_str() : "");
            }
    }
    ImGui::End();
}

void Workspace::draw_console() {
    if (ImGui::Begin("Console")) {
        ImGui::BeginChild("log", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
        ImGui::TextUnformatted(console_log_.c_str());
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();
        char buf[256];
        std::snprintf(buf, sizeof buf, "%s", console_input_.c_str());
        ImGui::SetNextItemWidth(-1);
        if (ImGui::InputText("##cin", buf, sizeof buf, ImGuiInputTextFlags_EnterReturnsTrue)) {
            console_log_ += "dede> ";
            console_log_ += buf;
            console_log_ += "\n";
            console_out_.str("");
            shell_->execute(buf);
            console_log_ += console_out_.str();
            console_input_.clear();
            ImGui::SetKeyboardFocusHere(-1);
        }
    }
    ImGui::End();
}

void Workspace::draw_decompiler() {
    if (ImGui::Begin("Decompiler")) {
        static std::string text;
        if (ImGui::Button("Decompile function at rip")) {
            auto r = e_.decompile(model_.rip, 128);
            text = r ? r.value() : ("// error: " + r.message());
        }
        ImGui::Separator();
        ImGui::TextUnformatted(text.c_str());
    }
    ImGui::End();
}

void Workspace::draw_timeline() {
    if (ImGui::Begin("Timeline")) {
        u64 now = model_.timeline.now, maxt = model_.timeline.max, lo = 0;
        ImGui::Text("tick %llu / %llu", (unsigned long long)now, (unsigned long long)maxt);
        ImGui::SetNextItemWidth(-1);
        u64 target = now;
        if (ImGui::SliderScalar("##tl", ImGuiDataType_U64, &target, &lo, &maxt) && target != now)
            e_.seek(target);
        if (ImGui::Button("<< -10")) e_.step_back(now >= 10 ? 10 : now);
        ImGui::SameLine();
        if (ImGui::Button("< -1")) e_.step_back(now ? 1 : 0);
        ImGui::SameLine();
        if (ImGui::Button("+1 >")) e_.step();
    }
    ImGui::End();
}

void Workspace::draw_cfg() {
    if (ImGui::Begin("Control-Flow Graph")) {
        if (!cfg_entry_) cfg_entry_ = model_.rip;
        ImGui::Text("entry %s", hx(cfg_entry_).c_str());
        ImGui::SameLine();
        if (ImGui::Button("rebuild from rip")) { cfg_entry_ = model_.rip; cfg_valid_ = false; }
        if (!cfg_valid_) { cfg_ = e_.build_cfg(cfg_entry_); cfg_valid_ = true; }

        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 origin = ImGui::GetCursorScreenPos();
        ImGui::InvisibleButton("cfg_canvas", ImVec2(ImGui::GetContentRegionAvail().x,
                                                    std::max(200.0f, ImGui::GetContentRegionAvail().y)));
        bool hov = ImGui::IsItemHovered();
        ImGuiIO& io = ImGui::GetIO();
        if (hov && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
            cfg_cam_.pan_x += io.MouseDelta.x;
            cfg_cam_.pan_y += io.MouseDelta.y;
        }
        if (hov && io.MouseWheel != 0.0f)
            cfg_cam_.zoom = std::clamp(cfg_cam_.zoom * (io.MouseWheel > 0 ? 1.1f : 0.9f), 0.2f, 3.0f);

        auto pos = cfg_.layout();
        const float colw = 240.0f, rowh = 120.0f;
        auto world = [&](int col, int row, float dx, float dy) {
            return ImVec2(origin.x + cfg_cam_.pan_x + (col * colw + dx) * cfg_cam_.zoom,
                          origin.y + cfg_cam_.pan_y + (row * rowh + dy) * cfg_cam_.zoom);
        };
        // edges first
        for (const auto& e : cfg_.edges) {
            if (!pos.count(e.from) || !pos.count(e.to)) continue;
            ImVec2 a = world(pos[e.from].first, pos[e.from].second, 90, 80);
            ImVec2 b = world(pos[e.to].first, pos[e.to].second, 90, 0);
            ImU32 col = e.kind == EdgeKind::Taken ? kColEdgeTaken
                      : e.kind == EdgeKind::NotTaken ? kColEdgeNot : kColEdgeJmp;
            dl->AddLine(a, b, col, 1.5f);
        }
        // nodes
        for (const auto& bb : cfg_.blocks) {
            if (!pos.count(bb.start)) continue;
            ImVec2 p = world(pos[bb.start].first, pos[bb.start].second, 0, 0);
            float w = 180 * cfg_cam_.zoom, h = 90 * cfg_cam_.zoom;
            bool has_rip = model_.rip >= bb.start && model_.rip < bb.end;
            dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), has_rip ? kColNodeRip : kColNode, 4.0f);
            dl->AddRect(p, ImVec2(p.x + w, p.y + h), kColNodeBorder, 4.0f);
            if (cfg_cam_.zoom > 0.4f) {
                std::string head = "loc_" + hx(bb.start).substr(2);
                dl->AddText(ImVec2(p.x + 4, p.y + 2), kColAddr, head.c_str());
                float y = p.y + 18;
                for (std::size_t i = 0; i < bb.insns.size() && i < 5; ++i) {
                    dl->AddText(ImVec2(p.x + 4, y), IM_COL32(200, 200, 200, 255), bb.insns[i].text().c_str());
                    y += 14;
                }
            }
        }
    }
    ImGui::End();
}

void Workspace::draw_memory_map() {
    if (ImGui::Begin("Memory Map")) {
        if (ImGui::BeginTable("mmap", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("base"); ImGui::TableSetupColumn("size");
            ImGui::TableSetupColumn("perms"); ImGui::TableSetupColumn("");
            ImGui::TableHeadersRow();
            for (const auto& r : e_.memory_map()) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(hx(r.base).c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(hx(r.size).c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%c%c%c", (r.perms & perm::R) ? 'r' : '-',
                            (r.perms & perm::W) ? 'w' : '-', (r.perms & perm::X) ? 'x' : '-');
                ImGui::TableNextColumn();
                ImGui::PushID((int)r.base);
                if (ImGui::SmallButton("view")) hex_addr_ = r.base;
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

void Workspace::draw_architecture() {
    if (ImGui::Begin("Architecture")) {
        ImGui::TextWrapped("dede subsystems and the design patterns each carries:");
        ImGui::Separator();
        for (const auto& s : architecture()) {
            if (ImGui::TreeNode(s.name.c_str())) {
                for (const auto& p : s.patterns) ImGui::BulletText("%s", p.c_str());
                if (!s.depends_on.empty()) {
                    std::string deps;
                    for (const auto& d : s.depends_on) deps += (deps.empty() ? "" : ", ") + d;
                    ImGui::TextDisabled("depends on: %s", deps.c_str());
                }
                ImGui::TreePop();
            }
        }
    }
    ImGui::End();
}

}  // namespace dede::gui
