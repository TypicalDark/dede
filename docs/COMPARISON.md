<!-- SPDX-License-Identifier: Apache-2.0 -->
# How dede compares — Ghidra · IDA Pro · Binary Ninja · x64dbg

This is an **honest** feature comparison, not marketing. dede is a *dynamic,
deterministic, time-travel analysis engine* for a documented **flat x86-64
subset**. Ghidra, IDA Pro and Binary Ninja are mature, multi-architecture static
RE platforms with production decompilers; x64dbg is a mature Windows ring-3
debugger. They solve a broader problem than dede does, and on that broad problem
they win. dede's bet is a different one: make **reversible execution** and
**anti-anti-analysis transparency** first-class and built-in, around a clean
engine that any front end can drive.

So read the matrix two ways: breadth of *categories covered* (where dede is
deliberately competitive), and depth *within* each category (where the
established tools, built over 10–25 years, are far ahead on the things outside
dede's scope).

> Capability data for the other tools reflects their publicly documented features
> as of early 2026. Where a tool reaches a capability through an add-on (a plugin,
> an external trace format) rather than natively, the matrix says so.

## Legend

`✅` first-class / built-in  ·  `◐` partial, basic, or via add-on  ·  `⬚` not offered

## Capability matrix

| Capability | dede | Ghidra | IDA Pro | Binary Ninja | x64dbg |
|---|:--:|:--:|:--:|:--:|:--:|
| **Disassembly** (x86-64) | ✅ (Capstone) | ✅ | ✅ | ✅ | ✅ (Zydis) |
| Multi-architecture | ⬚ x86-64 only | ✅ 20+ | ✅ 60+ | ✅ many | ⬚ x86/x64 |
| **Decompiler / pseudo-C** | ◐ basic fallback | ✅ excellent | ✅ best-in-class | ✅ multi-level IL | ◐ via plugin |
| Static CFG / code-flow graph | ✅ | ✅ | ✅ | ✅ | ◐ |
| Call graph | ✅ | ✅ | ✅ | ✅ | ◐ |
| Strings / entropy / opcode stats | ✅ | ✅ | ◐ | ◐ | ◐ |
| Cyclomatic complexity / dead-code / recursion | ✅ | ◐ | ◐ | ◐ | ⬚ |
| Region hashing (CRC-32 / FNV-1a) | ✅ | ◐ | ◐ | ◐ | ◐ |
| JSON / machine-readable export | ✅ | ◐ | ◐ | ✅ | ⬚ |
| Binary diffing | ◐ byte-diff | ◐ (BSim) | ◐ (BinDiff) | ◐ | ⬚ |
| **Live debugging** (step/bp/watch) | ✅ | ✅ (10.x) | ✅ | ✅ (3.0+) | ✅ |
| **Reversible / time-travel exec** | ✅ **native, deterministic** | ◐ trace nav | ◐ via WinDbg TTD | ◐ via WinDbg TTD | ◐ run-trace nav |
| CPU emulation | ✅ (primary engine) | ✅ (P-code emu) | ◐ (Bochs/appcall) | ◐ (plugin) | ⬚ |
| "Who last wrote this?" data query | ✅ | ⬚ | ⬚ | ⬚ | ◐ |
| **Anti-anti-analysis transparency** | ✅ **built-in forging** | ⬚ | ⬚ | ⬚ | ◐ (ScyllaHide) |
| Self-modifying-code-aware views | ✅ (live-image CFG) | ◐ | ◐ | ◐ | ✅ (runtime) |
| Syscall/API capture + MITM | ✅ | ⬚ | ◐ (tracing) | ◐ | ◐ (conditional bp) |
| **Scripting / automation** | ✅ (Luau + macros + cmds) | ✅ (Java/Python) | ✅ (IDAPython) | ✅ (Python) | ◐ (own script) |
| Record/replay macros | ✅ | ⬚ | ⬚ | ⬚ | ◐ |
| Type libraries / signatures (FLIRT-like) | ⬚ | ✅ | ✅ | ✅ | ⬚ |
| Multi-user collaboration | ⬚ | ✅ (server) | ◐ (Lumina/Teams) | ✅ (Enterprise) | ⬚ |
| GUI | ◐ Vulkan/ImGui | ✅ | ✅ | ✅ | ✅ |
| Loader coverage | ◐ ELF64/PE64/flat | ✅ huge | ✅ huge | ✅ large | ◐ PE (runtime) |
| Deterministic / reproducible runs | ✅ **by design** | ◐ | ◐ | ◐ | ⬚ |
| Self-scoring effectiveness harness | ✅ (`dede-eval`) | ⬚ | ⬚ | ⬚ | ⬚ |
| Licence | Apache-2.0 core | Apache-2.0 | Commercial | Commercial | GPLv3 |

## Where dede genuinely leads

These are built-in and first-class in dede, whereas the established tools either
lack them or reach them through an external component:

1. **Deterministic, native time-travel.** Step backward through *any* executed
   instruction with exact state — not re-simulated from the start, but restored
   from snapshots plus an injected-event log. The big static suites navigate
   *traces* (Ghidra's trace model; IDA and Binary Ninja replaying Windows TTD
   `.run` files) rather than offering reversible execution of a live target;
   x64dbg's run-trace is browse-only. dede's model is the rr / WinDbg-TTD idea,
   built into the core rather than bolted on — and reproducible: `seek(0)` then
   replay reproduces a session bit-for-bit, injected MITM edits included.

2. **Transparency as a core layer.** Forging `cpuid`, `rdtsc`, `sidt/sgdt/sldt`,
   `smsw`, I/O and MSR reads, plus W^X detection, is a Chain-of-Responsibility in
   the engine. On the other tools this is an external project (ScyllaHide /
   TitanHide for x64dbg/IDA); Ghidra and Binary Ninja have no equivalent because
   they debug through a separate stub. See [TRANSPARENCY.md](TRANSPARENCY.md).

3. **Self-modifying / packed code as the default case.** The CFG, disassembly and
   memory views are built from the *live* (post-mutation) image, and the event
   trace captures a program rewriting its own bytes as data
   ([GUI.md](GUI.md) shows the decrypt loop caught in the act). This is the
   scenario dede is designed around, not an edge case.

4. **Capture + MITM of the guest's external interactions** (the Wireshark/Charles
   analog) as replay-safe injected events — see [NETWORK_CAPTURE.md](NETWORK_CAPTURE.md).

5. **Reproducibility and honest self-measurement.** Runs are deterministic by
   construction, and `dede-eval` scores the tool against a 150-point RE-effectiveness
   suite and writes [EFFECTIVENESS_REPORT.md](EFFECTIVENESS_REPORT.md). No other
   tool here ships its own graded scorecard.

6. **A swappable engine.** Every front end (CLI, GUI, a future TUI/web view) talks
   only to `IAnalysisEngine`; the UI holds no analysis logic. The design-pattern
   spine is documented in [PATTERNS.md](PATTERNS.md).

## Where dede is honestly behind (and why)

No spin — these are real gaps, most of them inherent to dede's scope:

- **Decompiler quality.** dede's pseudo-C is a readable fallback. Hex-Rays,
  Ghidra's decompiler and Binary Ninja's HLIL are the products of many
  engineer-years and are far better. If you need production decompilation, use
  those.
- **One architecture.** dede is x86-64 only, over a *documented subset* of the
  ISA. Ghidra/IDA cover dozens of processor families. Instructions outside the
  interpreter's subset decode (Capstone) but may not execute.
- **Loader & format ecosystem.** ELF64, PE64 and flat blobs load today. The big
  tools parse a vast catalogue of formats, debug info, and runtime layouts, with
  deep symbol/type recovery.
- **Type systems & signatures.** No FLIRT-style library identification, no type
  libraries, no demangling/propagation of rich types. These are major IDA/Ghidra
  strengths.
- **Collaboration & plugin ecosystems.** No multi-user server, no large
  third-party plugin marketplace.
- **GUI maturity.** The Vulkan/ImGui workspace is functional and covers the core
  panels, but it is young next to UIs refined over a decade.

## Feature-count framing (the "same amount if not more" question)

Counting *capability categories* in the matrix above, dede covers a breadth
comparable to a general-purpose RE tool — and in the dynamic / reversible /
anti-analysis columns it covers categories the others don't offer natively. But
breadth of categories is not the same as depth, and on the categories outside its
scope (decompilation, multi-arch, formats, type recovery) the established tools
are decisively ahead. The honest summary:

- **Use Ghidra / IDA / Binary Ninja** for broad, multi-architecture static
  analysis and high-quality decompilation of real-world binaries.
- **Use x64dbg** for live ring-3 debugging of Windows x86/x64 processes.
- **Use dede** when you want deterministic time-travel, built-in transparency,
  and self-modifying-code analysis over x86-64, with a scriptable engine you can
  embed and a reproducible record of exactly what happened.

## Roadmap toward closing the gaps

Tracked so the "more features" goal stays concrete and honest:

- Broaden the interpreter's instruction subset (SSE/AVX paths, more string ops).
- A second architecture behind the existing `Arch` seam (the Abstract-Factory
  hook is already in place).
- Richer decompiler passes (the Visitor pipeline exists; add type inference).
- FLIRT-style signature matching and a minimal type library.
- Import/export of WinDbg TTD and `rr` traces, so dede can *also* navigate
  externally-recorded sessions (interoperability both directions).
- A dynamic plugin loader on top of the existing `IDetector` / backend / decompiler
  factories.
