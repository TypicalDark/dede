<!-- SPDX-License-Identifier: Apache-2.0 -->
# Architecture

`dede` is a transparent, time-travel reverse-engineering / malware-analysis shell.
The shell and scripts both go through one object — the `AnalysisSession` Facade —
which coordinates the subsystems and the execution core. Keeping the Facade as the
only entry point is what lets the subsystems and the backend be tested and swapped
independently, and it is the single surface a UI or the script engine binds onto.

## Module layout (one library per subsystem)

The dependency edges form a strict DAG rooted at `common`, so the layering stays
honest and the copyleft stays where [LICENSING.md](LICENSING.md) puts it.

```
          shell ────────────┐
            │               │
          script ───────────┤         (UI binds to IAnalysisEngine only)
            │               │
          session (Facade, State, IAnalysisEngine)
   ┌────────┼──────────┬────────────┬──────────────┐
 replay  transparency  macro     decompiler   introspection
   │         │          │            │             │
   └─────── core ───────┘          disasm          │
              │                      │              │
            disasm ─────────────────┘              │
              │                                     │
            common ───────────────────────────────┘
```

| Library | Contents |
|---|---|
| `common` | Value types, x86-64 `CpuState` (width-aware), copy-on-write paged `GuestMemory`. |
| `disasm` | Capstone **Adapter** (text + structured operands), **Flyweight** decode cache, in-tree assembler (asmjit behind an option). |
| `core` | `ExecutionCore`, the `IExecutionBackend` **Strategy** (built-in x86-64 interpreter; Unicorn/KVM behind the same seam), guest-memory **Proxy**, `StateMemento`, event sink. |
| `replay` | `TimelineManager` **Caretaker**, injected-event log, deterministic step-back. |
| `transparency` | **Chain-of-Responsibility** interceptors (cpuid/rdtsc/sidt/msr/io) over a `ForgedEnvironment`. |
| `macro` | `ICommand` (**Command**, with **Composite**/**Prototype**), `EventBus` (**Observer**), run-point registry, condition **Interpreter**, `MacroEngine`. |
| `decompiler` | `IDecompiler` **Adapter** (Ghidra-native behind an option) + linear-pseudocode fallback using a **Visitor**. |
| `introspection` | `IIntrospector` (LibVMI behind an option) + stub. |
| `session` | `AnalysisSession` **Facade**, `IAnalysisEngine` UI contract, session **State** machine. |
| `script` | `IScriptEngine` seam; Luau behind an option, Null-Object fallback. |
| `shell` | The command-line **Interpreter** front end. |
| `emu-host` | The separate GPL emulator process + IPC — kept apart for the license reason. |

See [PATTERNS.md](PATTERNS.md) for the full pattern catalogue.

## The UI/engine boundary

A user interface binds only to the `IAnalysisEngine` interface (the Facade's public
contract). It never reaches into `core()`, `timeline()`, or the event bus directly.
That keeps the front end swappable — the CLI shell today, a TUI or web view
tomorrow — and lets the engine be mocked in tests.

## Headline feature 1 — time travel (Memento + deterministic replay)

Step-back is the **Memento** pattern applied to the whole machine, with the three
roles kept strict:

- **Originator** — `ExecutionCore`, the only thing that produces/restores its own
  state.
- **`StateMemento`** — an opaque snapshot: the register file plus a copy-on-write
  memory image plus the retired-instruction count. Copy-on-write pages make a
  capture O(resident pages) pointer bumps, not a full memory copy.
- **Caretaker** — `TimelineManager`, which owns history: a ring buffer of
  fine-grained per-step mementos for the recent past, and a sparse set of full
  snapshots as replay anchors. It never inspects a memento; it only stores one and
  hands it back.

A step-back resolves two ways:

- **A few steps back** → restore a fine-grained memento from the ring. Near-instant,
  no replay.
- **Far back, or a jump to an arbitrary instruction number** → restore the nearest
  earlier snapshot anchor, then replay the deterministic core forward to one past
  the target, re-applying injected events from the log, landing exactly.

**Determinism is the contract that makes replay exact.** The interpreter is
deterministic given state + memory + injected events; even `rdtsc` is a function of
the instruction count, so it replays identically. The only things that are *not*
reproduced by re-execution — non-deterministic inputs and mutating-macro edits —
are recorded as **injected events** keyed by tick and re-applied on replay.

## Headline feature 2 — macros and run points (Command + Observer)

A **run point** is a trigger bound to a place or condition in execution (an address,
an instruction count, a memory access, a condition, or a page written then
executed). Run points are built on the breakpoint and **Observer** machinery: the
`ExecutionCore` emits events to an `EventBus`; the `MacroEngine` subscribes. To keep
macros from seeing mid-instruction state, matches are *queued* during the step and
the Facade *fires* them afterwards.

A **macro** is an action bound to a run point — a recorded list of `Command`s or an
authored callback. Because every debugger action is already a `Command` with
`execute`/`undo`, a recorded macro and a hand-written one are the same kind of thing.

Two kinds, and the distinction is a correctness rule:

- **Observing macros** only read state or annotate; pure, safe on every replay.
- **Mutating macros** change guest registers or memory. Because that alters
  execution, a mutating macro's edits are captured as **injected events**, exactly
  like any other non-deterministic input, or replay would diverge. This is the rule
  that keeps macros and time-travel consistent — and it is exercised end to end by
  the decrypt demo and `test_integration`.

## The step pipeline

```
AnalysisSession::step():
  core.step()            // decode (Capstone) + interpret one insn; emit events
  macros.fire_pending()  // run matched run points; mutating macros inject
  timeline.record()      // memento now reflects any macro mutation
```

Replay (`seek` backwards / to an explored tick) runs silently: observers are muted,
macros are *not* re-run, and injected events are re-applied — so the recorded run is
reproduced from the log, not by side effects.

## Transparency (anti-anti-analysis)

When the guest executes an anti-analysis probe (`cpuid`, `rdtsc`, …), the core turns
it into a `ProbeRequest` and asks the `ITransparency` chain. Each interceptor in the
**Chain of Responsibility** either answers with a forged, bare-metal value (clean
vendor string, cleared hypervisor bit, smooth deterministic TSC, believable IDT
base, silent VMware backdoor) or passes it along. Nothing writes an `int3` or
touches a debug register, so instrumentation stays invisible to the sample. The
default is a **Null Object** chain, so a bare core behaves as an ordinary CPU.
