// SPDX-License-Identifier: Apache-2.0
// Internal: each module file defines one of these; modules.cpp registers them.
#pragma once
#include "dede/ui/registry.hpp"
namespace dede::ui {
Manifest exec_module();
Manifest disasm_module();
Manifest cfg_module();
Manifest decompiler_module();
Manifest timeline_module();
Manifest console_module();
Manifest inspector_module();
}  // namespace dede::ui
