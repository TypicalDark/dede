// SPDX-License-Identifier: Apache-2.0
#include "dede/ui/modules.hpp"

#include "dede/ui/registry.hpp"
#include "src/ui/modules/all.hpp"

namespace dede::ui {

void register_modules(Registry& reg) {
    reg.register_module(exec_module());
    reg.register_module(disasm_module());
    reg.register_module(cfg_module());
    reg.register_module(decompiler_module());
    reg.register_module(timeline_module());
    reg.register_module(console_module());
    reg.register_module(inspector_module());
}

}  // namespace dede::ui
