<!-- SPDX-License-Identifier: Apache-2.0 -->
# dede UI architecture — a modular, backend-agnostic shell

dede's front end is built the way the *git-tool* history explorer is built: a tiny
**kernel** of contribution points, a **shell** that renders purely from what is
registered, self-contained feature **modules**, and interchangeable **painter
backends**. Adding a panel is one file; re-skinning the whole app is swapping a
theme; and because nothing is tied to a GPU, the exact same UI renders headlessly
to SVG (for `dede-shot` and tests) and live through Dear ImGui on the desktop.

```
             ┌──────────────── dede_ui (kernel, no GPU) ────────────────┐
             │  Theme     design tokens (colours, radius, accent)        │
             │  Context   reactive selection + flags ("follows selection")│
             │  Registry  contribution points (views/commands/toolbar/…) │
             │  CommandBus enablement-checked dispatch + history          │
             │  IPainter  the one immediate-mode draw + input surface     │
             │  Shell     draws the whole chrome from the Registry        │
             └───────────────────────────────────────────────────────────┘
                 ▲ registers manifests              ▲ draws through
   dede_ui_modules (feature modules)        painter backends
   exec · disasm · cfg · decompiler         SvgPainter  (headless → dede-shot, tests)
   timeline · console · inspector           ImGuiPainter (desktop GUI, dede-gui)
```

## The layers

- **Theme** (`ui/theme.hpp`) — every colour the UI draws is a token. The default
  palette mirrors git-tool (`--bg #0a0e14`, neon green `#39ff14`, cyan `#00e5ff`).
  `Theme::preset("cyan"|"amber"|"green")` swaps the accent (the channel ovals).
- **Context** (`ui/context.hpp`) — the reactive state: what is selected (an
  instruction, register, block, function, or timeline tick) plus a bag of boolean
  flags. It is the single source the inspector "follows" and that `when` clauses
  read. A pared-down `evaluate_when()` supports `flag`, `!flag`, `&&`, `||`.
- **Registry** (`ui/registry.hpp`) — the contribution system. A module registers a
  `Manifest` of **commands, views, toolbar items, status items, sidebar sections,
  inspector schemas, keybindings**. The shell asks the registry what to draw; it
  has no feature knowledge of its own.
- **CommandBus** (`ui/commands.hpp`) — runs a command's handler after checking its
  `when` enablement, and records a history. Toolbar clicks, keybindings, and the
  command palette all dispatch through it.
- **IPainter** (`ui/painter.hpp`) — a minimal immediate-mode drawing + input API
  (`rect`, `line`, `circle`, `text`, `pill`, clip stack; `mouse`, `clicked`,
  `scroll`). Draw-only backends return neutral input, so a render is a faithful
  snapshot of a given Context.
- **Shell** (`ui/shell.hpp`) — lays out and draws the seven regions from the
  registry: title bar (logo + state chip + toolbar + command search + OPEN), the
  workspace tab strip + theme ovals, the left sidebar, the centre view with window
  chrome, the right "Properties follows selection" inspector, the bottom quake
  drawer, and the status bar. **It never changes as modules are added.**

## Backends

| Backend | File | Used by | Input |
|---|---|---|---|
| **SVG** | `ui/backends/svg_painter.*` | `dede-shot`, tests (headless, no GPU) | none (static snapshot) |
| **ImGui** | `ui/backends/imgui_painter.*` | `dede-gui` (Vulkan/GLFW desktop) | live mouse/keys |

Both implement `IPainter` with the **same monospace metric**, so layouts are
pixel-identical. `dede-shot` renders the real `Shell` + modules from a live
`AnalysisSession` — the same code the desktop GUI runs — which is how the UI is
verified without a display.

## How to extend it

**Add a panel** — write one module file and register it:
```cpp
// src/ui/modules/mything.cpp
Manifest mything_module() {
    Manifest m; m.id = "mything";
    m.views = {{"mything", "My Thing", 0, "main",  // or "drawer"
                [](IPainter& p, Services& s, Rect r) {
                    p.text({r.x + 12, r.y + 20}, "hello from a panel", s.theme->text, 12);
                }}};
    return m;
}
```
then one line in `src/ui/modules/modules.cpp`: `reg.register_module(mything_module());`.

**Add a command + toolbar button + keybinding:**
```cpp
m.commands = {{"mything.do", "Do the thing", "Mine", "loaded", "F8",
               [](Services& s, const std::string&) { /* uses s.engine */ }}};
m.toolbar  = {{"mything.do", "exec", "✦", "", "", 9}};        // glyph, segment, order
m.keybindings = {{"F8", "mything.do", "loaded"}};
```

**Add an inspector that follows a selection:**
```cpp
m.schemas = {{"mykind", "My Inspector", 20,
              [](const Context& c){ return c.selection().kind == SelKind::Block; },
              [](IPainter& p, Services& s, Rect r){ /* draw fields + actions */ }}};
```

**Add a status readout:** push a `StatusItem{ id, order, text(Services&), color(Services&) }`.

**Re-skin:** change tokens in `Theme`, or add a preset; nothing else changes.

## File map

```
include/dede/ui/           geom, theme, painter, context, registry, commands,
                           services, shell, modules + backends/{svg,imgui}_painter
src/ui/                    context, registry, commands, shell, backends/svg_painter
src/ui/modules/            exec, disasm, cfg, decompiler, timeline, console,
                           inspector (+ modules.cpp registrar, mod_common.hpp)
include/dede/gui/          shell_app.hpp          (desktop host over the Shell)
src/gui/shell_app.cpp      builds the kernel + registers modules + per-frame draw
apps/shot.cpp              dede-shot: headless SVG render of the real Shell
apps/dede_gui.cpp          Vulkan/GLFW host; calls ShellApp::draw() each frame
tests/test_ui.cpp          kernel unit tests (when-eval, registry, commands, ctx)
```

See [GUI.md](GUI.md) for a visual tour of the rendered shell.
