// SPDX-License-Identifier: Apache-2.0
//
// The desktop GUI driver: builds the modular UI kernel (Registry + feature
// modules + Context + Theme + CommandBus) once, and each frame renders the Shell
// through the ImGui painter and dispatches keybindings. It replaces the old
// monolithic Workspace — all panels now live in dede_ui_modules, so this class is
// a thin host. The app (apps/dede_gui.cpp) owns Vulkan/GLFW and calls draw()
// between ImGui::NewFrame() and ImGui::Render().
#pragma once

#include <memory>

#include "dede/ui/commands.hpp"
#include "dede/ui/context.hpp"
#include "dede/ui/registry.hpp"
#include "dede/ui/services.hpp"
#include "dede/ui/shell.hpp"
#include "dede/ui/theme.hpp"

namespace dede {
class IAnalysisEngine;
class IScriptEngine;
}  // namespace dede

namespace dede::gui {

class ShellApp {
public:
    ShellApp(IAnalysisEngine& engine, IScriptEngine& script);

    void draw();     // one frame; call between NewFrame and Render
    void attach() {}  // history is recorded by the session; kept for host symmetry
    void detach() {}

private:
    void handle_keys();

    IAnalysisEngine& engine_;
    IScriptEngine& script_;
    ui::Registry reg_;
    ui::Context ctx_;
    ui::Theme theme_;
    std::unique_ptr<ui::CommandBus> bus_;
    ui::Services svc_;
    ui::Shell shell_;
};

}  // namespace dede::gui
