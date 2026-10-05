// SPDX-License-Identifier: Apache-2.0
//
// The decompiler centre view: renders the engine's pseudocode for the current
// function. (The native decompiler/type-system backend is a separate work
// stream; this view shows whatever IDecompiler the session was built with.)
#include <sstream>

#include "dede/session/engine.hpp"
#include "dede/ui/modules.hpp"
#include "dede/ui/services.hpp"
#include "src/ui/modules/all.hpp"
#include "src/ui/modules/mod_common.hpp"

namespace dede::ui {

using mod::hx;

namespace {
void draw_decompiler(IPainter& p, Services& s, Rect r) {
    const Theme& th = *s.theme;
    if (!s.engine) { p.text({r.x + 14, r.y + 24}, "no session", th.dim, 12); return; }
    Addr a = s.ctx->selection().kind == SelKind::Insn ? s.ctx->selection().addr : s.engine->rip();
    p.text({r.x + 12, r.y + 16}, "pseudocode of 0x" + hx(a), th.faint, 11);
    auto res = s.engine->decompile(a, 160);
    std::string text = res ? res.value() : ("// " + res.message());
    std::istringstream ss(text);
    std::string ln;
    float y = r.y + 36;
    while (std::getline(ss, ln)) {
        if (y > r.y1() - 6) break;
        // crude keyword tint
        Color c = th.text;
        if (ln.find("//") != std::string::npos) c = th.faint;
        else if (ln.find("goto") != std::string::npos || ln.find("return") != std::string::npos ||
                 ln.find("if (") != std::string::npos) c = th.purple;
        else if (ln.find("void ") != std::string::npos || ln.find("sub_") != std::string::npos) c = th.yellow;
        p.text({r.x + 14, y}, ln, c, 11);
        y += 15;
    }
}
}  // namespace

Manifest decompiler_module() {
    Manifest m;
    m.id = "decompiler";
    m.views = {{"decompiler", "Decompiler", 0, "main", draw_decompiler}};
    return m;
}

}  // namespace dede::ui
