<!-- SPDX-License-Identifier: Apache-2.0 -->
# dede — Capabilities, Gap Analysis & Roadmap

_What dede can do today, how it stacks up against IDA Pro/Hex-Rays, Ghidra, x64dbg and
x32dbg, which of the "out-of-scope" rows are actually reachable, and a batched, criteria-driven
plan to close the gaps. Scored against the 150-point `dede-eval` suite: **PASS 58 · PARTIAL 33
· FAIL 0 · N/A 59** (81% of in-scope capability)._

dede is a **deterministic, time-travel x86-64 emulator for reverse engineering** — not a
ring-3 live debugger, not multi-arch, not an OS/process model. Everything below is framed by
that charter: gaps that fit it are roadmap items; gaps that contradict it are called out as
out-of-scope.

---

## Part 1 — What dede can do today (feature inventory)

### Execution & time-travel (the core differentiator)
- **Deterministic x86-64 interpreter** over COW paged memory. Models the common integer ISA
  incl. `div`/`idiv` + `cdq`/`cqo`/`cbw` family; CPU faults (`#DE`, bad memory, bad fetch)
  raise a catchable Fault.
- **Reversible execution / time-travel**: Memento snapshots + an injected-event log give
  `step_back`, `seek(tick)`, and bit-identical **record & replay**. → *Walk any executed
  instruction forward or backward with exact state; reproduce a session (MITM edits included).*
- **Break-on-exception, conditional breakpoints, memory watchpoints, step-until-condition** via
  a run-point/macro engine. → *Stop on a divide-by-zero, a write to an address, or a predicate.*
- **Snapshot/checkpoint + save/load session.**

### Transparency (anti-anti-analysis, built in)
- Forge `cpuid`/`rdtsc`/`sidt`/`sgdt`/`smsw`/MSR/port-IO; W^X (self-modifying-code) detection.
  → *Run malware that checks for a hypervisor/debugger and watch it decide it's on bare metal.*

### Capture / MITM
- **Syscall interception + logging**, **API/function hooking + argument modification**. → *See
  and rewrite what the guest asks the outside world (the Wireshark/Charles analog).*

### Static analysis
- CFG builder with **switch/jump-table recovery** (read from the live image), call graph,
  cyclomatic complexity, dead-code, recursion, opcode histogram + anomaly, Shannon entropy,
  string extraction, region hashing (CRC-32/FNV-1a), byte-diff, JSON + Graphviz DOT export.
  → *Map control flow, find loops/recursion, spot high-entropy (packed) regions, diff two builds.*

### Native decompiler (→ typed C)
- IR lifter (P-code-flavored, differentially validated against the interpreter) → expression
  trees with **constant folding** + **cmp/jcc re-fusion** → **variable recovery** (stack+reg →
  named locals) → **TIE-style type inference** (width/sign/pointer + **struct/array aggregates**
  rendered `ptr->field_N`) → **Phoenix-style structuring** (if/else, while, do-while, switch;
  goto-minimized) → **bitfield reconstruction** (`BITFIELD` intrinsic). Ghidra's decompiler can
  be linked behind `DEDE_WITH_GHIDRA` as a differential oracle.

### Protection / malware detection (pluggable `IDetector` + structural scans)
- anti-VM, timing (rdtsc), anti-debug (int3/int2d/flags/MSR), crypto (xor-imm/rotate/AES),
  VM-dispatch (indirect jmp), pointer-encryption (TLS cookie / guard rotate), exception-handler
  (SEH `fs:[0]` / `ud2` / `int 0x29`), lazy-init (double-checked), **anti-disassembly**
  (overlap / opaque conditional pair / push-imm;ret), control-flow-obfuscation, polymorphic/SMC.

### Debugging introspection
- **Time-travel-correct call-stack unwinder** (rbp-chain) + a best-effort return-address
  (call-preceded) check + `bt` shell command; register snapshot/compare; stack telescope;
  memory dump+search; performance profiling; execution-path coverage; `who_wrote` (time-travel
  "who last wrote this address?").

### Loader, UI, automation
- **ELF64 + PE64 + flat** loader (imports/sections/symbols), symbol table.
- Modular **Shell** (contribution-registry UI like "git-tool"): headless SVG painter + desktop
  ImGui painter; exec/disasm/cfg/decompiler/timeline/console/inspector panels.
- Shell REPL + recorded macros + **Luau** scripting (behind a build flag); batch/CLI; the
  `dede-eval` self-scoring harness.

---

## Part 2 — Gap analysis vs IDA / Ghidra / x64dbg / x32dbg

Deduplicated across the four tools (many gaps recur). **Feasible** = fits dede's charter:
`bounded` (days) · `large` (a milestone/subsystem) · `out-of-scope` (contradicts the design).

### High-value, in charter
| Gap | dede today | Tools | Feasible | Flips |
|---|---|---|---|---|
| **SSA + cross-statement data-flow** (const/copy prop, CSE, DCE) in the decompiler | per-block, sequential | IDA, Ghidra | large | #11 #21 #25 → PASS; deepen #16 #18 |
| **Cross-reference (xref) database** — code + data + string xrefs, both directions | none (only dynamic `who_wrote`) | IDA, Ghidra, x64dbg, x32dbg | bounded | #2 → PASS |
| **Whole-binary function auto-discovery** (prologue sigs + recursive + non-returning + tail-call) | entry-reachable only | IDA, Ghidra | bounded | #7 → PASS |
| **Library-function signatures** (FLIRT/FunctionID): auto-name libc/CRT | none | IDA, Ghidra | large | #84; multiplies decompiler value |
| **Type libraries** (TIL/GDT): libc/Win32 prototypes + cross-function type propagation | per-function TIE lattice only | IDA, Ghidra | large | deepen #17 #23 #84 |
| **Persisted analysis DB**: names/comments/types/xrefs survive reopen | save/load session only | IDA, Ghidra, x64dbg, x32dbg | large | #81 #82 |
| **Full ISA**: SSE/SSE2/AVX + x87 FPU | integer subset | x64dbg | large | deepen #89; more real binaries run |
| **Patch manager + patch-to-disk** | in-memory edits only | x64dbg, x32dbg | bounded | tooling |
| **Expression engine**: conditional + logging (non-breaking) breakpoints, watch expressions | predicate run-points | x64dbg | bounded | deepen #71 #73 |
| **Wildcard/mask pattern search + find-all strings/intermodular-calls** | plain byte search | x64dbg, x32dbg | bounded | tooling |
| **Debug-info (DWARF/PDB) import** | ELF symbols only | IDA, Ghidra, x64dbg | large | deepen #77 #84 |
| **Symbol demangling** (Itanium C++, then MSVC/Rust) | none | IDA, Ghidra | bounded | deepen #77 |
| **Calling-convention detection** (SysV/Win64; stdcall/fastcall/thiscall) | SysV assumed | IDA | bounded | correctness of #23 |
| **C++ class recovery** (vtable + RTTI + virtual-method resolution) | none | IDA, Ghidra | bounded→large | #26 → PARTIAL+ |
| **Rich scripting/plugin API** (expose functions/xrefs/types/DB/decompiler) + dynamic plugin loader | Luau + C++ factories | IDA, Ghidra, x64dbg | bounded→large | deepen #71 #73 #91 |
| **Structural/function-level binary diffing** (BinDiff/BSim-grade) | byte diff | IDA, Ghidra | large | deepen #76 |
| **Deep PE parsing** (.rsrc, .pdata/SEH, TLS callbacks, rich header) | section headers only | IDA, x64dbg | bounded | #19 #79 |
| **Scylla-style unpack-and-ship** (dump image + rebuild IAT to a runnable file) | SMC reveal only | x64dbg, x32dbg | large | workflow |

### Out-of-scope (contradicts the deterministic-emulator charter)
- **Multi-architecture** (ARM/MIPS/PPC/RISC-V; IDA's 60+, Ghidra SLEIGH). The `Arch` factory
  seam exists, but a processor-spec layer + per-arch interpreter is a different project.
- **Live / remote debugging of real processes** (x64dbg's core; IDA's gdb/WinDbg stubs). dede
  *is* the CPU — it emulates, it doesn't attach to a kernel-scheduled process.
- **Multi-threaded debugging** — single-threaded deterministic core by design.
- **Windows user-mode OS environment** at ScyllaHide breadth (PEB/TEB, real DLLs, Nt* APIs) —
  partial forging is in charter; a full OS shim is not.
- **Collaboration server / community / LTS** (#92 #95) — project-maturity metrics, not code.

---

## Part 3 — N/A triage (are the 59 "out of scope" rows really out of scope?)

| Row | Verdict | Note |
|---|---|---|
| **44 Memory-allocation tracking** | **achievable-bounded** | dede already observes every alloc syscall/trace; → **PASS** (Batch 3) |
| **79 Resource extraction (.rsrc)** | **achievable-bounded** | PE loader already has the section bytes; → **PASS** (Batch 2) |
| **19 Exception-handler visualization** | **achievable-bounded** | static `.pdata`/`.xdata` tables + existing SEH detector; → **PARTIAL** (Batch 2). Live SEH dispatch stays out-of-scope |
| **51 Packer/protector ID** | **achievable-bounded** | entropy + section names + EP stub + W^X; → **PARTIAL/PASS** (Batch 3) |
| **69 Template/macro *obfuscation* detection** | **achievable-bounded** | detect the emitted obfuscation (stack-string xor, opaque predicates), not the source; → **PARTIAL** (Batch 4) |
| **26 Virtual-method resolution** | **achievable-large** | static vtable scan + **dynamic** observed-target resolution (dede can beat static tools here); → **PASS** (Batch 4, static vtable + Itanium name + observed slot target) |
| **22 Inline-function detection** | **achievable-large** | clone detection via normalized-hash clustering; → **PARTIAL** (Batch 4) |
| **80 Cross-tool DB import** | **achievable-large** | a JSON interchange + IDAPython/BN exporter snippets (BNDB=SQLite later; IDB research); → **PARTIAL** (Batch 7) |
| 14 Macro expansion · 27 Lambda/closure · 28 Macro-param subst. | **out-of-scope** | erased by the preprocessor/front-end before codegen; no residue in machine code |
| **45 Multi-threaded debugging** | **achievable-large** | now planned via **Batch 9** deterministic multi-context scheduling (rr-style); → PARTIAL+ (threads + processes debuggable under a recorded schedule) |
| 92 Community · 95 Update/LTS | **out-of-scope** | adoption/process metrics, not engine code |
| **101–130, 135–149 (45 rows) Legacy PE/Windows/DRM** | **out-of-scope (theme)** | one duplicated OS/format-specific-static-tooling theme; Batch 2 picks up the generic PE depth, the DRM-wrapper specifics stay out |

Net reachable from N/A: **~8 rows** (44, 79 → PASS; 19, 51, 69, 22, 26, 80 → PARTIAL+).

---

## Part 4 — The plan (batches · tasks · completion criteria)

Ordered by value-per-effort. Each batch is independently shippable, lands with tests under
`-Wall -Wextra -Werror`, keeps `ctest` green and FAIL=0, and updates `dede-eval` + this file.
A shared enabler used by several batches is an **AnalysisDB / Blackboard fact store** (already
specified in `docs/PATTERNS.md`): an address-keyed store for xrefs, names, comments, types.

### Batch 1 — Static knowledge layer *(HIGH · bounded)* — ✅ shipped
Build the AnalysisDB, then populate it.
- **T1.1 Xref database** — linear-sweep decode of executable ranges; record code xrefs
  (call/jmp targets) + data xrefs (rip-rel/absolute mem operands, `lea`/imm address-taking);
  key by address; `xref <addr>` shell cmd + JSON; match string addresses for string xrefs.
  _Done:_ `xref` lists every static referrer with kind+source; string referrers listed; a
  hand-built expected set passes in a test; JSON round-trips; **#2 → PASS**.
- **T1.2 Whole-binary function discovery** — seed entries from loader symbols + prologue
  signatures (`push rbp;mov rbp,rsp`, `endbr64`, `sub rsp,imm`) + xref call targets; build_cfg
  each; track non-returning functions; treat `jmp` into another entry as a tail-call edge.
  _Done:_ on a 3-function image where only one is entry-reachable, all three are discovered;
  a non-returning callee doesn't mis-split; negative test (prologue-shaped data not flagged);
  **#7 → PASS**.

### Batch 2 — PE format depth *(bounded)* — ✅ shipped
- **T2.1 PE data-directory parsing** — read optional-header `NumberOfRvaAndSizes` + directory
  array in `load_pe64` (shared enabler for T2.2/T2.3).
- **T2.2 Resource extraction (.rsrc)** — walk the 3-level resource tree; `resources` list +
  `resource dump <id> <path>`. _Done:_ PE64 fixture's `{type,id,size}` parsed and leaf bytes
  extracted exactly; **#79 → PASS**.
- **T2.3 Exception-table + SEH view** — parse `.pdata` RUNTIME_FUNCTION + `.xdata` UNWIND_INFO;
  `seh`/`exceptions` cmd; fold in the existing `fs:[0]` detector; annotate covered ranges.
  _Done:_ fixture ranges+handler RVA parsed; `fs:[0]` chains still reported; **#19 → PARTIAL**.

### Batch 3 — Dynamic observers *(bounded)* — ✅ shipped
- **T3.1 Allocation tracker** — `IEventObserver` over syscall + malloc/free/realloc run-points;
  live map {base,size,alloc_tick,free_tick}; `allocs`, `leaks`, double-free/unknown-free flags;
  replay-safe. _Done:_ two mmaps/one munmap → one live+one freed with correct ticks; stepping
  back shows both live (time-travel); double-free detected; **#44 → PASS**.
- **T3.2 Packer/protector detector** — section-level scan: signature table (section-name sets,
  EP stub patterns) + per-section entropy; W^X run-point upgrades "suspected"→"confirmed".
  _Done:_ UPX0/UPX1 + high-entropy fixture named "UPX (heuristic)"; clean control silent;
  **#51 → PARTIAL** (PASS when sig+entropy+W^X agree).

### Batch 4 — Obfuscation + C++ recovery *(bounded → large)* — ✅ shipped
Code in `analysis/recover.{hpp,cpp}` (static) + `session/vcall_tracker.hpp` (dynamic); shell
`stackstrings`/`obf`, `clones`, `vtables`; tested in `test_cfg.cpp`.
- **T4.1 Stack-string / compile-time-obfuscation detector** — recognize the xor-decrypt-loop
  idiom; compose with crypto + opaque-predicate findings. _Done:_ `scan_stack_strings` fires on
  the in-place decrypt loop and names the target buffer; a plain counting loop stays silent;
  **#69 → PARTIAL** (reworded, no source-attribution claim). ✅
- **T4.2 Inline/clone detection** — operand-normalized (mnemonic + operand-kind) token streams,
  seed-and-extend maximal common runs across functions. _Done:_ a 6-insn helper inlined at 2
  sites (different registers) + a decoy → exactly one cluster covering the 2 sites, decoy
  excluded; **#22 → PARTIAL**. ✅
- **T4.3 vtable/RTTI + virtual-call resolution** — `scan_vtables` finds runs of code pointers in
  a read-only region → `Vtable{addr,slots}` + Itanium type_info class name; `VirtualCallResolver`
  hooks indirect calls and records the observed slot target (time-travel-correct). _Done:_
  fixture vtable (3 slots) found statically with name "Foo", slot1 target `sub_1006` observed
  dynamically; **#26 → PASS** (static vtable + Itanium name + dynamic target). ✅

### Batch 5 — Decompiler data-flow *(HIGH · large)* — tasks #22/#23 — ✅ shipped
Code in `ir/ssa.{hpp,cpp}` (dominators + phi) and `ir/opt.{hpp,cpp}` (data-flow),
tested in `test_opt.cpp` + `test_decompiler.cpp`.
- **T5.1 SSA** — `dominator_tree` (Cooper-Harvey-Kennedy), `dominance_frontier`, and Cytron
  `place_phis` over an abstract CFG. _Done:_ diamond + loop CFGs give the textbook idom /
  dominance-frontier / phi-placement results in tests; the dominator tree now backs the
  decompiler's own loop-header and if/else-join structuring (replacing the old O(N²) set-based
  `compute_dom`). ✅ Full Vn-versioned rename across joins (phi materialization in the emitted
  IR) is the documented next step; the join-free (per-basic-block) case is what T5.2 consumes.
- **T5.2 Propagation/CSE/DCE** — `simplify_block`: constant folding + constant/copy propagation,
  a few algebraic identities, optional CSE, and dead-code elimination, all over one basic block.
  _Done:_ every transform is differentially validated (the optimized block evaluates
  bit-identically to the original across seeded states, `test_opt.cpp`); wired into the native
  decompiler before expression building so copy chains collapse (`mov rax,rdi; add rax,rsi` =>
  `rax = rdi + rsi`) and constant arithmetic folds (`2+3` => `5`). The forward is **sound under
  the mutable-register emitter**: a value is never propagated past a redefinition of a source
  register it names (guarded, with a regression test). CSE is disabled in the decompiler path so
  a flag-feeding sub/and is never merged before cmp/jcc re-fusion. **#11 #18 #21 → PASS**; #16
  stays PASS and visibly cleaner; **#25 stays PARTIAL** (full implicit-cast detection is
  type-driven — deferred to Batch 6's SSA-value-typed prototype DB, honest rather than forced).

### Batch 6 — Type & symbol knowledge *(large)* — depends on Batch 5 — ✅ shipped
Code in `symbols/{demangle,protodb,siglib}.{hpp,cpp}` (new `dede_symbols` library),
tested in `test_symbols.cpp`; shell `demangle` / `proto`.
- **T6.1 FLIRT-style signatures** — `siglib`: masked byte-pattern signatures (`Signature{pattern,
  care}`), `make_signature` with wildcard ranges, `match_at` / `identify`, and a starter set.
  _Done:_ a routine's signature (rel32 displacement wildcarded) matches the same function at a
  different link address and does NOT match unrelated code (zero FP); **deepens #84**. ✅ The
  signature *generator* from real `.o`/`.a` files is the documented extension; the matcher +
  format ship now.
- **T6.2 Type library + conventions** — `protodb`: a curated libc/POSIX/Win32 prototype database
  (62 entries, ≥50) keyed by name with return + parameter C types, decoration stripping, and
  SysV/Win64 argument-register binding. _Done:_ `strlen`/`memcpy`/`recv` resolve to typed
  prototypes; ≥50 loaded; **#84 → PASS**. ✅ Seeding `FuncTypes` at a *decompiled* call site from
  the target symbol (so a caller renders typed args) is the remaining decompiler-side integration.
- **T6.3 Demangling + calling convention** — a self-contained Itanium demangler (nested names,
  ctor/dtor, builtin + pointer/ref/const types, parameter lists, `std::` abbreviations, operators,
  a template + substitution subset) and a minimal MSVC decoder, plus SysV/Win64 detection from
  argument-register usage. _Done:_ representative mangled symbols demangle in tests, a Win64 arg
  order is recovered, unparseable names return unchanged (never garbage); C++ symbols are now
  demangled on load; **deepens #77 #23**. ✅

### Batch 7 — Persistence, interop & interactive UX *(bounded → large)*
- **T7.1 Persisted analysis DB** — serialize AnalysisDB (names/comments/types/xrefs) per binary,
  auto-load on reopen. _Done:_ annotate → close → reopen restores everything; **#81 #82 deepen**.
- **T7.2 JSON interchange import** — schema {symbols,comments,functions,structs} + importer +
  IDAPython/BN exporter snippets in docs; round-trip vs dede's own JSON export. _Done:_
  export→reimport round-trips names/comments/bounds; **#80 → PARTIAL**.
- **T7.3 Patch manager + patch-to-disk**; **T7.4 expression-engine breakpoints** (conditional +
  logging/non-breaking + watch expressions); **T7.5 wildcard/mask pattern search + find-all**.
  _Done:_ patched binary exports and re-runs; a logging breakpoint records without stopping; a
  masked pattern finds the planted sites; **deepen #71 #73 #91**.

### Batch 8 — ISA breadth *(large)*
- **T8.1 SSE/SSE2/AVX + x87 subset** in the interpreter, differentially tested. _Done:_ vector
  + FPU test vectors evaluate bit-identically; a float-using sample runs; **deepen #89**.
- **T8.2 (stretch) IA-32 mode** — 32-bit decode/semantics + PE32/IAT + `fs`/`gs` segment access
  + SEH chain. _Done:_ a 32-bit sample runs and unwinds its SEH chain. _(Large; nearest the
  out-of-scope line — gated behind explicit demand.)_

### Batch 9 — OS user-mode environment / emulation sandbox *(large · the behavioral-analysis milestone)*
Execute **Windows and Linux** user-mode binaries (notably malware) by modeling the OS API/
syscall surface — the Qiling/Speakeasy/Unicorn-sandbox approach, built on dede's existing
**capture/MITM** (API hooking + syscall interception), **transparency** (structure forging),
**loader** (imports/symbols), and **Batch 3** allocation tracker. dede's edge over a live
sandbox: it stays **deterministic + time-travel + record/replay**, so you can run malware,
watch it unpack/stage, step *backward* to see how, and replay bit-for-bit while feeding fake
inputs via MITM. This makes generic **user-mode** Windows/Linux analysis in-charter (distinct
from the ring-0/DRM legacy theme, which stays out).

**Shared foundation**
- **T9.1 Segment bases (`fs`/`gs`) in the interpreter** — needed by both OSes (Win PEB/TEB,
  Linux TLS + stack canary). Shared with Batch 8. _Done:_ `fs`/`gs`-relative loads/stores
  resolve against a settable base; `arch_prctl(ARCH_SET_FS)` and a forged TEB both read back.
- **T9.2 Loaded-module + import-binding model** — a synthetic module address space so imports
  (PE IAT / ELF PLT-GOT) bind to shim handlers; `GetProcAddress`/`dlsym`-style resolution.
  _Done:_ a sample's import thunks dispatch to registered handlers, not into unmapped memory.
- **T9.3 Pluggable OS-environment dispatcher (Strategy)** — an `IOsEnvironment` that handles an
  intercepted API/syscall, mutates regs/memory, returns a result, and emits a time-travel-
  visible behavioral event. Reuses the capture layer. _Done:_ one interface, two backends
  (Win/Linux), selected by the loaded image's format.

**Windows track** (PE64; PE32 via Batch 8 T8.2)
- **T9.W1 Win32 module map** (synthetic kernel32/ntdll/user32 bases) + IAT binding.
- **T9.W2 Forged PEB/TEB** (`BeingDebugged`, `NtGlobalFlag`, TLS) via `fs`/`gs` — extends the
  transparency layer's forging.
- **T9.W3 Core API shim set** — memory (`VirtualAlloc`/`VirtualProtect`/`HeapAlloc`), file
  (`CreateFileW`/`ReadFile`/`WriteFile`), module (`LoadLibrary`/`GetProcAddress`/
  `GetModuleHandle`), process (`GetCurrentProcess`/`GetProcAddress`), plus a few `Nt*` direct
  syscalls — each returns a plausible result and logs the call; unknowns log + return a safe
  default. **T9.W4 (stretch) SEH dispatch** into a registered `__except`.
  _Done:_ a PE64 that `VirtualAlloc`s, writes a payload, and "injects" runs to its exit under
  the shim; the Batch-3 alloc tracker shows the regions; an anti-debug `PEB.BeingDebugged`/
  `NtGlobalFlag` check reads "not debugged"; MITM can substitute a `ReadFile`/registry/C2 value;
  stepping back across the run restores exact state; the API call log is a replayable event
  stream. A hand-built PE64 fixture test asserts the shimmed APIs + behavioral log.

**Linux track** (ELF64; leverages the most existing infrastructure — `syscall` already
intercepted, ELF already parsed)
- **T9.L1 Linux syscall ABI** (`rax`=nr, `rdi/rsi/rdx/r10/r8/r9`) with a core set: `mmap`/
  `mprotect`/`munmap`/`brk`, `openat`/`read`/`write`/`writev`/`close`, `arch_prctl`, `exit`/
  `exit_group`, `getpid`, `nanosleep` — most routing through the existing syscall interception.
- **T9.L2 TLS + stack canary** — `arch_prctl(ARCH_SET_FS)` sets the `fs` base; `fs:[0x28]`
  canary readable so glibc-compiled binaries don't fault on entry.
- **T9.L3 (dynamic ELF) minimal PLT/GOT + `ld.so` resolution** binding libc imports to shim
  handlers; statically-linked ELF needs only the syscall set.
  _Done:_ a statically-linked ELF that `mmap`s, writes, reads, and `exit`s runs to completion
  under the shim; a `write(1,...)` syscall's bytes are MITM-capturable (observable "stdout");
  the alloc tracker shows `mmap` regions; time-travel + replay work; a fixture test asserts the
  syscall results + behavioral log; a glibc `hello`-style ELF reaches its `write`.

**Concurrency & multi-process — deterministic scheduling** (the rr / WinDbg-TTD model: run one
context at a time under a *deterministic* scheduler and record the schedule, so replay is
bit-identical — concurrency without giving up determinism or time-travel). This extends the
core's state model from one register file + one address space to **N contexts**.
- **T9.5 Multi-context core + deterministic scheduler** — generalize the core to hold a set of
  execution contexts (each its own `CpuState` + per-thread stack/TLS; one COW address space per
  process, shared by its threads). A cooperative scheduler steps one runnable context at a time,
  switching at deterministic points (blocking syscall, a fixed instruction quantum, or an
  explicit yield) and **records the chosen schedule into the timeline** so `seek`/replay
  reproduce the exact interleaving. Snapshots capture *all* contexts so time-travel restores the
  whole world. _Done:_ two cooperatively-scheduled contexts run to completion under a recorded
  schedule; `seek(tick)` + replay reproduce the identical interleaving bit-for-bit; stepping
  back crosses a context switch correctly.
- **T9.6 Thread creation + lifecycle** — model `CreateThread`/`NtCreateThreadEx` (Win) and
  `clone`/`pthread_create` (Linux, via the T9.L1 syscall set) as spawning a new thread context
  in the current address space with its own stack + TLS base; handle thread exit/join; expose a
  `threads` view (id, state, rip, call stack per thread via the Batch-1/Batch-5 unwinder).
  _Done:_ a sample that spawns 2 worker threads touching shared memory runs deterministically;
  `threads` lists all three with correct per-thread call stacks; a different (still
  deterministic) schedule can be selected to surface an order-dependent bug, then replayed.
- **T9.7 Process creation + IPC** — model `CreateProcessW`/`fork`+`execve` as spawning a new
  **process context** (fresh address space; `fork` = COW-clone of the parent's space), tracked
  with a pid/handle; model inherited handles and the common IPC channels the OS-env shim already
  mediates (pipes, shared sections/`mmap`, stdio) so parent↔child data flow is observable and
  MITM-able. _Done:_ a parent that spawns a child which writes to an inherited pipe runs to
  completion; both processes appear in a `processes` view with their own memory maps; the
  cross-process write is captured on the behavioral trace; time-travel restores both processes.

**Shared completion / out of this batch's scope:** the behavioral trace (API/syscall log, thread
switches, process spawns) is a time-travel-visible event stream and MITM can feed fake file/
registry/network responses, all deterministically replayable. Concurrency is modeled by
deterministic *serialized* scheduling (dede explores and reproduces specific interleavings — it
does not run contexts in true parallel on host cores, which is what keeps replay exact). **Out
of scope within Batch 9:** true parallel/preemptive execution on multiple host cores, faithful
reproduction of a *specific real-hardware* race timing (dede picks and records a deterministic
schedule instead), ring-0/kernel-driver execution, a GUI subsystem, and real external side
effects (forged/MITM'd, never actually touching the host FS/registry/network).

### Explicitly out of scope (documented, not planned)
Multi-architecture beyond x86-64 · live/remote attach to real processes · **true parallel /
preemptive execution on multiple host cores** (dede models multi-thread + multi-process via a
*deterministic serialized scheduler* in Batch 9 — exact reproduction of a specific real-hardware
race timing is what stays out) · **ring-0 / kernel-driver execution** (the real blocker in the
legacy PE/DRM theme) · a GUI/windowing subsystem · real host side effects (dede forges/MITMs
them) · collaboration server · source-only constructs (#14 macros, #27 lambdas, #28
macro-params) · the vendor-specific commercial-DRM-wrapper specifics of the 45-row legacy theme.
(Note: generic PE depth is covered by Batch 2; generic **user-mode** Windows/Linux execution —
*including deterministic multithreading and process creation* — is now **Batch 9**; only the
ring-0/DRM
tail stays out.)

---

## Suggested sequence
**Batch 1 → 2 → 3** are high-value and bounded (xrefs, PE depth, dynamic observers) and flip the
quick N/A/PARTIAL wins. **Batch 5** (SSA data-flow) is the single biggest quality lever and
unblocks **Batch 6** (types/signatures). **Batch 4** can land alongside 1–3. **Batch 7** (UX/
persistence) and **Batch 8** (ISA breadth) follow. **Batch 9** (OS user-mode sandbox) is the
largest and most product-defining: it turns dede into a **deterministic time-travel sandbox**
for real Windows *and* Linux user-mode malware — build it after Batch 3 (its alloc tracker) and
T9.1/Batch 8 (`fs`/`gs`), with the Linux track first (most existing infrastructure) then
Windows. Each batch keeps FAIL=0 and raises the `dede-eval` applicable score; projected end
state after Batches 1–6: **~72 PASS**, with the decompiler approaching Ghidra-grade output on
frame-pointer-based x86-64 binaries, and Batch 9 adding behavioral execution of real binaries.
