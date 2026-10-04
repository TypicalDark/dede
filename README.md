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
- **Shell** — an interactive REPL driving everything through one engine interface.

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
# Debian/Ubuntu: sudo apt-get install libcapstone-dev cmake ninja-build clang
cmake -S . -B build -G Ninja
ninja -C build
ctest --test-dir build --output-on-failure
```

Then:

```sh
./build/dede-decrypt-demo        # the end-to-end showcase
./build/dede [flat-code-file]    # interactive shell; `help` lists commands
```

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
src/<lib>/            implementations (common, disasm, core, replay,
                      transparency, macro, decompiler, introspection,
                      session, script, shell, emu_host)
apps/                 dede (REPL) and dede-decrypt-demo
tests/                a dependency-free harness; 30 cases across 7 suites
docs/                 ARCHITECTURE.md, PATTERNS.md, LICENSING.md
```

## Status

~5k lines of C++20. The design (companion doc) describes a six-phase build;
this tree delivers the first three phases working end to end — core + shell, time
travel, and macros/run points — plus the transparency layer and a decompiler
fallback, with every external library (Unicorn, Ghidra-native, Luau, asmjit,
LibVMI) behind a clean adapter ready to be switched on. The two hardest pieces the
design calls out — **deterministic replay** and the **transparency layer** — are
proven on small samples, as recommended.

## License

Apache-2.0 for this project's own code. See [docs/LICENSING.md](docs/LICENSING.md)
for how the copyleft dependencies are contained.
