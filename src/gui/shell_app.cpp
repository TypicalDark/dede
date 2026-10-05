// SPDX-License-Identifier: Apache-2.0
#include "dede/gui/shell_app.hpp"

#include <string>
#include <vector>

#include "imgui.h"

#include "dede/ui/backends/imgui_painter.hpp"
#include "dede/ui/modules.hpp"

namespace dede::gui {

ShellApp::ShellApp(IAnalysisEngine& engine, IScriptEngine& script)
    : engine_(engine), script_(script) {
    ui::register_modules(reg_);
    theme_ = ui::Theme::preset("cyan");
    bus_ = std::make_unique<ui::CommandBus>(reg_);
    svc_.engine = &engine_;
    svc_.script = &script_;
    svc_.ctx = &ctx_;
    svc_.registry = &reg_;
    svc_.commands = bus_.get();
    svc_.theme = &theme_;
}

void ShellApp::draw() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->Pos);
    ImGui::SetNextWindowSize(vp->Size);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBringToFrontOnFocus |
                             ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoSavedSettings;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##dede_shell", nullptr, flags);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ui::ImGuiPainter p(dl);
    ui::sync_context(svc_);
    shell_.draw(p, svc_, {vp->Pos.x, vp->Pos.y, vp->Size.x, vp->Size.y});
    handle_keys();

    ImGui::End();
    ImGui::PopStyleVar();
}

void ShellApp::handle_keys() {
    ImGuiIO& io = ImGui::GetIO();
    if (io.WantTextInput) return;  // don't steal keys from a focused text field
    auto key_of = [](const std::string& name) -> ImGuiKey {
        if (name == "F5") return ImGuiKey_F5;
        if (name == "F7") return ImGuiKey_F7;
        if (name == "F9") return ImGuiKey_F9;
        if (name == "G") return ImGuiKey_G;
        if (name == "K") return ImGuiKey_K;
        return ImGuiKey_None;
    };
    for (const auto& kb : reg_.keybindings()) {
        // chord: optional "Shift+"/"Ctrl+" prefix + a key name
        std::string chord = kb.key;
        bool want_shift = chord.find("Shift+") != std::string::npos;
        bool want_ctrl = chord.find("Ctrl+") != std::string::npos;
        auto plus = chord.rfind('+');
        std::string base = plus == std::string::npos ? chord : chord.substr(plus + 1);
        ImGuiKey k = key_of(base);
        if (k == ImGuiKey_None) continue;
        if (ImGui::IsKeyPressed(k, false) && io.KeyShift == want_shift && io.KeyCtrl == want_ctrl)
            bus_->execute(kb.command, svc_);
    }
}

}  // namespace dede::gui
