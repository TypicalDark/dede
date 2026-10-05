// SPDX-License-Identifier: Apache-2.0
//
// The execution module: the time-travel toolbar (back/step/run/restart), the
// transparency toggle, the status-bar readouts, and the per-frame context sync
// that feeds the title-bar state chip and `when` flags. This is the module that
// makes the chrome reflect the live session.
#include "dede/session/engine.hpp"
#include "dede/ui/commands.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/services.hpp"
#include "src/ui/modules/all.hpp"
#include "src/ui/modules/mod_common.hpp"

namespace dede::ui {

using mod::hx;

void sync_context(Services& s) {
    if (!s.ctx) return;
    s.ctx->set_str("app_title", "dede");
    if (!s.engine) { s.ctx->set_flag("loaded", false); return; }
    auto& e = *s.engine;
    bool paused = e.phase() == Phase::Paused;
    s.ctx->set_flag("loaded", true);
    s.ctx->set_flag("paused", paused);
    s.ctx->set_flag("running", e.phase() == Phase::Running);
    s.ctx->set_flag("transparency", e.transparency_enabled());
    s.ctx->set_str("state_chip", std::string(e.phase_name()) + "  0x" + hx(e.rip()));
}

Manifest exec_module() {
    Manifest m;
    m.id = "exec";

    m.commands = {
        {"run.step", "Step", "Run", "paused", "F7",
         [](Services& s, const std::string&) { if (s.engine) s.engine->step(); }},
        {"run.back", "Step back", "Run", "paused", "Shift+F7",
         [](Services& s, const std::string&) { if (s.engine) s.engine->step_back(1); }},
        {"run.back10", "Step back 10", "Run", "paused", "",
         [](Services& s, const std::string&) { if (s.engine) s.engine->step_back(10); }},
        {"run.run", "Run", "Run", "paused", "F5",
         [](Services& s, const std::string&) { if (s.engine) s.engine->run(); }},
        {"run.restart", "Restart (seek 0)", "Run", "loaded", "",
         [](Services& s, const std::string&) { if (s.engine) s.engine->seek(0); }},
        {"transparency.toggle", "Toggle transparency", "Analysis", "loaded", "",
         [](Services& s, const std::string&) {
             if (!s.engine) return;
             if (s.engine->transparency_enabled()) s.engine->disable_transparency();
             else s.engine->enable_transparency();
         }},
        {"theme.set", "Set theme", "View", "", "",
         [](Services& s, const std::string& which) { if (s.theme) *s.theme = Theme::preset(which); }},
    };

    m.toolbar = {
        {"run.back10", "nav", "\xC2\xAB", "", "", 0},
        {"run.back",   "nav", "\xE2\x80\xB9", "", "", 1},
        {"run.step",   "exec", "\xE2\x80\xBA", "", "", 0},
        {"run.run",    "exec", "\xE2\x96\xB6", "", "", 1},
        {"run.restart","exec", "\xE2\x9F\xB2", "", "", 2},
        {"transparency.toggle", "view", "\xE2\x9C\xA6", "", "transparency", 0},
    };

    m.keybindings = {
        {"F7", "run.step", "paused"},
        {"Shift+F7", "run.back", "paused"},
        {"F5", "run.run", "paused"},
    };

    auto dim = [](Services& s) { return s.theme->dim; };
    m.status = {
        {"backend", 0, [](Services& s) { return s.engine ? "\xE2\x97\x8F " + s.engine->backend_name() : std::string("no session"); },
         [](Services& s) { return s.engine ? s.theme->green : s.theme->faint; }},
        {"phase", 1, [](Services& s) { return s.engine ? std::string(s.engine->phase_name()) + " rip=0x" + hx(s.engine->rip()) : std::string(); }, dim},
        {"tick", 2, [](Services& s) {
             if (!s.engine) return std::string();
             auto t = s.engine->timeline_stats();
             return "tick " + std::to_string(t.now) + "/" + std::to_string(t.max);
         }, dim},
        {"snap", 3, [](Services& s) {
             if (!s.engine) return std::string();
             return "snap " + std::to_string(s.engine->timeline_stats().snapshots);
         }, dim},
        {"transparency", 4, [](Services& s) {
             if (!s.engine) return std::string();
             return std::string("transparent: ") + (s.engine->transparency_enabled() ? "on" : "off");
         }, [](Services& s) { return s.engine && s.engine->transparency_enabled() ? s.theme->accent : s.theme->dim; }},
        {"theme", 5, [](Services& s) { return "\xE2\x97\x8F " + s.theme->name; },
         [](Services& s) { return s.theme->accent; }},
    };

    return m;
}

}  // namespace dede::ui
