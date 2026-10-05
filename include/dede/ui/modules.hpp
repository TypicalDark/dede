// SPDX-License-Identifier: Apache-2.0
//
// Feature modules register their contributions (views, commands, toolbar, status,
// sidebar sections, inspector schemas) into the Registry. Each module is a single
// self-contained file; adding a panel is adding one module and one line here.
#pragma once

namespace dede::ui {

class Registry;
struct Services;

// Register every built-in dede module into `reg`.
void register_modules(Registry& reg);

// Push live engine state into Context strings (state chip, flags, hints) so the
// shell chrome and `when` clauses reflect the current session. Call once per
// frame before Shell::draw.
void sync_context(Services& s);

}  // namespace dede::ui
