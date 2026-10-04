// SPDX-License-Identifier: Apache-2.0
//
// The dockable workspace: owns the UiModel and draws every panel. It binds to the
// engine ONLY through IAnalysisEngine (the Bridge between UI and core), plus the
// Shell for the embedded console. The host app (apps/dede_gui.cpp) owns Vulkan and
// GLFW and calls draw() once per frame; this class pulls in no windowing or Vulkan
// headers, so it can be unit-reasoned and ported to another backend.
#pragma once

#include <memory>
#include <sstream>
#include <string>

#include "dede/analysis/cfg.hpp"
#include "dede/gui/ui_model.hpp"
#include "dede/script/script_engine.hpp"
#include "dede/session/engine.hpp"
#include "dede/shell/shell.hpp"

namespace dede::gui {

// Plain 2D camera for the graph canvas (no ImGui types in the header).
struct Camera2D {
    float pan_x = 40.0f, pan_y = 40.0f;
    float zoom = 1.0f;
};

class Workspace {
public:
    Workspace(IAnalysisEngine& engine, IScriptEngine& script);
    ~Workspace();

    // Draw the whole UI for this frame (call between NewFrame and Render).
    void draw();

    // Subscribe/unsubscribe the trace ring (host calls these around the session).
    void attach();
    void detach();

private:
    void draw_menu_and_toolbar();
    void draw_status_bar();
    void draw_registers();
    void draw_disassembly();
    void draw_hex();
    void draw_stack();
    void draw_run_points();
    void draw_trace();
    void draw_console();
    void draw_decompiler();
    void draw_timeline();
    void draw_cfg();
    void draw_memory_map();
    void draw_architecture();
    void build_default_layout(unsigned dock_id);

    IAnalysisEngine& e_;
    IScriptEngine& script_;
    UiModel model_;
    TraceRing trace_;

    // Embedded console: the Shell writes into this buffer, which the console panel
    // displays. Reuses the exact command grammar of the terminal shell.
    std::ostringstream console_out_;
    std::unique_ptr<Shell> shell_;
    std::string console_input_;
    std::string console_log_;

    // View state.
    Addr dis_addr_ = 0;
    bool dis_follow_rip_ = true;
    Addr hex_addr_ = 0;
    Addr cfg_entry_ = 0;
    Camera2D cfg_cam_;
    Cfg cfg_;
    bool cfg_valid_ = false;
    bool layout_built_ = false;
    bool first_frame_ = true;
};

}  // namespace dede::gui
