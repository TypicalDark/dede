<!-- SPDX-License-Identifier: Apache-2.0 -->
# Transparency: defeating anti-analysis

A sample under analysis actively tries to (a) **detect** that it is emulated,
virtualised, or debugged, or (b) **escape** the interpreter into undefined
behaviour so analysis diverges. dede's transparency layer (a
Chain-of-Responsibility of interceptors over a `ForgedEnvironment`) and its
interpreter are built to defeat both, without ever writing an `int3` or touching a
debug register — nothing the sample can observe.

This matrix is grounded in a survey of real techniques (al-khaser, pafish,
ScyllaHide, the Red Pill / No Pill family) and is honest about what is and is not
yet covered. Each **Defeated** row is backed by a test in `tests/test_antidetect.cpp`
or `tests/test_transparency.cpp`.

## Defeated today

| Technique | What the sample does | How dede defeats it | Test |
|---|---|---|---|
| Hypervisor-present bit | `cpuid.1:ECX[31]` | forced clear | ✓ |
| Hypervisor vendor leaf | `cpuid 0x40000000..` | leaf range hidden (zeros) | ✓ |
| Vendor string | `cpuid 0` | forged "GenuineIntel" | ✓ |
| Red Pill | `sidt` → IDT base | forged bare-metal base/limit | ✓ |
| No Pill | `sgdt` → GDT base | forged bare-metal base/limit | ✓ |
| SMSW | CR0 machine-status word | forged CR0 (PE set, …) | ✓ |
| STR / SLDT | task / LDT selector | plausible user selectors | ✓ |
| VMware backdoor | `in eax, dx` port 0x5658 | port silenced | ✓ |
| RDTSC timing | delta around work | smooth, low, deterministic + jitter | ✓ |
| RDTSC zero-variance | constant delta = tell | per-tick jitter (still monotonic & replay-exact) | ✓ |
| RDTSCP | `rdtscp` aux/clock | handled; aux = CPU 0 | ✓ |
| Segment-register check | `mov ax, cs` etc. | modelled selectors (cs=0x33, …) | ✓ |
| INT3 self-scan / CRC | checksum own code | our breakpoints never patch guest bytes | ✓ |
| Self-modifying code | decrypt & run, overlap | decode cache versioned by bytes; W^X detected | ✓ |

Determinism is a feature here, not a liability: because the forged clock is a pure
function of the retired-instruction count, time-travel replays a timing check
identically — a real debugger's single-step gap can never appear.

## Roadmap (from the anti-analysis research, prioritised)

The single highest-leverage addition is a **guest exception-delivery channel**
(`#PF`/`#GP`/`#UD`/`#DB`): synthesize the machine frame, consult the forged IDT,
and dispatch to the sample's own handler (SEH / sigaction). It is the enabler for
~8 other checks, so it is the next major piece of work.

**Must (depend on or extend the above):**
- Exception delivery channel (`#PF`/`#GP`/`#UD`/`#DB`) — the master mechanism.
- Synthetic/reserved MSR must `#GP`, not return 0 (needs the fault channel).
- Per-opcode timing cost model (cpuid ≈ 200cyc, serialized > non-serialized) — the
  current tick-based clock with jitter is a strong first approximation; a cost
  table is the full fix.
- Full CPUID leaf space: brand string (0x80000002-4), `EBX` fields, freq leaves
  (0x15/0x16), extended leaves, and a documented default for every leaf.
- FS/GS base + forged TEB/PEB (`gs:[0x60]` → `BeingDebugged = 0`); segment-override
  memory operands (today they degrade cleanly to Unsupported, not a crash).
- Two-clock consistency (TSC vs `clock_gettime`/QPC) — requires modelling the time
  syscalls against the same virtual clock.
- Hardware debug registers DR0–DR7; Trap Flag (TF) and ICEBP (`0xF1`) single-step
  traps — all ride the fault channel.
- x87 FPU last-instruction pointer and SSE/XMM state.

**Should:** VMX-capability MSR consistency, WRMSR write-path symmetry, APERF/MPERF
ratio, INT 2D byte-skip, popf/pushf reserved-bit fidelity, SIDT/SGDT register-form
`#UD`, unmapped-page-straddling instructions, over-length/illegal-prefix faults,
`LAR`/`LSL`/`VERR`/`VERW`, MMIO/firmware reads.

## Escape resistance

The interpreter never trusts the sample: an unmodelled instruction or operand, an
unmapped fetch, or any internal mismatch degrades to a clean `Unsupported`/`Fault`
outcome (the dispatch is wrapped so a decode/operand surprise can never crash the
tool), and self-modifying code is handled by versioning the decode cache on the
instruction bytes. The remaining escape vectors in the roadmap above (page-straddle,
prefix abuse, FPU state) are enumerated so they are closed deliberately, not
discovered in the field.
