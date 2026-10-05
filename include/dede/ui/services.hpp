// SPDX-License-Identifier: Apache-2.0
//
// Services is the bundle handed to every command handler and panel draw — the
// engine it drives plus the UI kernel (context, registry, command bus, theme).
// It holds pointers, assembled by whoever hosts the shell (the ImGui app, the
// SVG renderer, or a test), so the kernel is testable with a null engine.
#pragma once

#include "dede/ui/context.hpp"
#include "dede/ui/registry.hpp"
#include "dede/ui/theme.hpp"

namespace dede {
class IAnalysisEngine;
class IScriptEngine;
}  // namespace dede

namespace dede::ui {

class CommandBus;

struct Services {
    IAnalysisEngine* engine = nullptr;
    IScriptEngine* script = nullptr;
    Context* ctx = nullptr;
    Registry* registry = nullptr;
    CommandBus* commands = nullptr;
    Theme* theme = nullptr;
};

}  // namespace dede::ui
