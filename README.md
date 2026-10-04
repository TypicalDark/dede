<!-- SPDX-License-Identifier: Apache-2.0 -->
# dede — transparent time-travel analysis shell

A modern C++20 reverse-engineering / malware-analysis core in the lineage of
x64dbg, Ghidra, ScyllaHide, and time-travel debuggers (rr, WinDbg TTD). It
executes real x86-64 machine code under a deterministic interpreter, records a
full timeline so you can step **backwards**, stays **invisible** to the sample it
is analysing, and automates analysis with **macros** bound to run points in the
target's execution.

It is built on a deliberate design-pattern spine — a **Facade** over the
subsystems, **Memento** for step-back, **Command + Observer** for macros,
**Strategy** for the pluggable execution backend, **Chain of Responsibility** for
the transparency layer — so subsystems stay decoupled enough to test and swap. See
[docs/PATTERNS.md](docs/PATTERNS.md) for the full catalogue (23 implemented, with
the growth path and the patterns deliberately avoided).

> **Scope.** This is a defensive security / reverse-engineering tool for analysing
> samples in a controlled environment. The "transparency" layer is anti-*anti*-
> analysis — it hides the analyst's instrumentation from a sample that tries to
> detect it, the same job ScyllaHide does.

## What works today

Everything below runs and is covered by tests — build it and try the demo.

- **Deterministic x86-64 interpreter** over a documented instruction subset,
  decoding through the same Capstone adapter the rest of the tool uses, so
  disassembly and execution always agree.
- **Time travel** — snapshot/step-back via Memento, plus far step-back and
  arbitrary `goto <tick>` by restoring the nearest snapshot and replaying forward
  deterministically.
- **Macros & run points** — breakpoints, memory watch points, instruction-count,
  condition predicates, and W^X ("written then executed") triggers; macros that
  observe or mutate, with mutations logged for exact replay.
- **Transparency** — cpuid/rdtsc/sidt/msr/io interceptors that forge a clean
  bare-metal environment (no hypervisor bit, smooth deterministic TSC, …).
- **Decompiler** — a linear-pseudocode fallback (Ghidra-native slots in behind a
  build option); **disassembler** and **assembler** for viewing and patching.
- **Static analysis** — control-flow graph (`cfg`), program call graph, Shannon
  entropy, opcode-frequency anomalies, string extraction, cyclomatic complexity,
  and a pluggable protection detector (`scan`: anti-vm / anti-debug / timing /
  crypto).
- **Capture / MITM** — a Wireshark/Charles analog for an emulated target: capture
  and dissect the guest's syscalls/probes (`capture`), and rewrite a syscall's
  args/return via a run point + macro, replay-safe ([docs/NETWORK_CAPTURE.md](docs/NETWORK_CAPTURE.md)).
- **QoL** — symbols, memory search, stack telescope, watchpoints, who-last-wrote
  (time-travel data query), session save/load, command history, aliases.
- **Shell** — an interactive REPL driving everything through one engine interface.
- **GUI** — an optional Vulkan + Dear ImGui desktop workspace (same engine
  interface), with a CFG graph view, timeline scrubber, and embedded console.
- **Self-scoring** — `dede-eval` runs dede against a 150-point RE-tool
  effectiveness suite and writes [docs/EFFECTIVENESS_REPORT.md](docs/EFFECTIVENESS_REPORT.md).

## The scenario it is built around

`dede-decrypt-demo` runs the whole design end to end: a self-decrypting stub
reveals an encrypted "stage 2", a run point fires as the real code appears, a
*mutating* macro patches it, we decompile the revealed code, then time-travel back
and forward — and the patch is reproduced from the injected-event log **without
re-running the macro**.

```
[1] Before execution, stage 2 is encrypted garbage:
      2000:  adc bl, byte ptr [rbp - 0x655a4b66]   ...
[2] Running the self-decrypting stub...
    halted: hlt at tick 53 ; W^X run point hit 1 time(s)
[3] Stage 2 is now decrypted and the macro patched it:
      2000:  mov rax, 0xd00d
      2007:  hlt
    rax = 0xd00d  (the mutating macro took effect)
[4] Time-travel back to tick 0:  stage2 is encrypted again, rax = 0x0
[5] Replay forward (from a sparse anchor, re-applying the injected patch —
    the macro is NOT re-run):  rax = 0xd00d
== replay REPRODUCED the run exactly ✓ ==
```

Nothing here writes an `int3` or touches a debug register, so the change is
invisible to the sample.

## Build

Only **Capstone** (BSD) is required; everything else is in-tree. The heavy /
copyleft backends (Unicorn, Ghidra-native, Luau, asmjit, LibVMI) are build
options, default `OFF` — see [docs/LICENSING.md](docs/LICENSING.md) for why.

```sh
./build.sh deps        # apt-get the dependencies (add --with-gui for the Vulkan UI)
./build.sh test        # configure, build, and run the test suite
# or by hand: cmake -S . -B build -G Ninja && ninja -C build && ctest --test-dir build
```

Then:

```sh
./build/dede-forge /tmp          # write the 5 tutorial samples (see docs/TUTORIAL.md)
./build/dede /tmp/tier1.bin      # interactive shell; `help` lists commands
./build/dede-decrypt-demo        # the end-to-end showcase
./build/dede-eval                # score against the 150-point effectiveness suite
./build/dede-bench               # hot-path micro-benchmark
./build.sh gui /tmp/tier5.bin    # the Vulkan desktop UI (needs a display)
```

New here? Start with **[docs/TUTORIAL.md](docs/TUTORIAL.md)** — five tiers from a
plain loop to a self-decrypting, anti-analysis, syscall-making sample.

A quick shell session:

```
dede> dis 0x1000 5
dede> bp 0x100e            # breakpoint
dede> run                  # runs until the breakpoint
dede> step 3
dede> back 2               # time-travel: step backwards
dede> rp cond rax == 0x40  # conditional run point
dede> transparency on      # forge a clean environment
dede> timeline             # ring/snapshot/injected stats
```

## Layout

```
include/dede/<lib>/   public headers, one folder per subsystem
src/<lib>/            implementations (common, disasm, core, replay, transparency,
                      macro, analysis, decompiler, introspection, session, script,
                      shell, samples, gui, emu_host)
apps/                 dede (REPL), dede-decrypt-demo, dede-eval, dede-bench,
                      dede-forge, dede-gui
tests/                a dependency-free harness; 14 suites + the effectiveness run
docs/                 ARCHITECTURE · PATTERNS · TRANSPARENCY · NETWORK_CAPTURE ·
                      DESIGN_REVIEW · EFFECTIVENESS_REPORT · LICENSING · TUTORIAL
```

## Status

The design (companion doc) describes a six-phase build; this tree delivers the
first three phases end to end — core + shell, time travel, and macros/run points —
plus the transparency layer, static analysis (CFG/call-graph/scan), a
capture/MITM layer, an optional Vulkan GUI, and a decompiler fallback, with every
heavy external library (Unicorn, Ghidra-native, Luau, asmjit, LibVMI) behind a
clean adapter ready to switch on. The two hardest pieces the design calls out —
**deterministic replay** and the **transparency layer** — are proven on small
samples. `dede-eval` scores the tool honestly against a 150-point RE-effectiveness
suite and names the in-scope gaps (a decompiler backend, a fault-delivery channel,
richer capture dissection) as the forward roadmap.

## License

Apache-2.0 for this project's own code. See [docs/LICENSING.md](docs/LICENSING.md)
for how the copyleft dependencies are contained.
