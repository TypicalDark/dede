<!-- SPDX-License-Identifier: Apache-2.0 -->
# Licensing reality and strategy

> I am not a lawyer, and the conclusions here should be checked with one before
> any release. This document records the strategy the architecture is built
> around; it is engineering guidance, not legal advice.

The dependencies split into two camps, and the copyleft camp decides what the
whole linked binary can be.

## Permissive (usable under almost any project license)

| Dependency | Role | License |
|---|---|---|
| Ghidra decompiler + SLEIGH (ghidra-native) | Decompiler, P-code lifter | Apache-2.0 |
| Capstone | Disassembly | BSD-3 |
| asmjit | Assembly / patching | Zlib |
| Luau | Scripting and macros | MIT |
| Intel XED (optional) | Decode | Apache-2.0 |

## Copyleft (pulls the linked binary toward its license)

| Dependency | Role | License |
|---|---|---|
| Unicorn | CPU emulation | GPLv2 (no "or later") |
| QEMU | Full-system emulation | GPLv2 |
| Keystone | Assembly | GPLv2 / paid commercial |
| x64dbg, Scylla | Debugger / import rec. | GPLv3 |
| LibVMI | Introspection | LGPLv3 |

## The traps, in order of how much they bite

1. **Linking any GPL library** (Unicorn, QEMU, Keystone, x64dbg) into one binary
   makes that binary GPL. Static linking has no way around it.
2. **GPLv2-only and GPLv3 cannot be combined.** Unicorn and Keystone are GPLv2
   without the or-later clause, so they cannot legally share a binary with GPLv3
   code such as x64dbg or Scylla.
3. **Apache-2.0 is compatible with GPLv3 but not GPLv2.** So Ghidra's Apache-2.0
   decompiler cannot be cleanly static-linked with GPLv2-only Unicorn in a single
   binary either.

## The recommended path (which also matches the architecture)

- **Put the emulator in a separate process.** The execution core (Unicorn or
  QEMU) runs as its own program (`emu-host`) and talks to the rest over IPC. That
  contains the GPL in one process. The design already keeps the core behind the
  `IExecutionBackend` Strategy and the instrumentation outside the guest, so the
  boundary is natural. *Separate programs exchanging data are generally treated as
  separate works — the precise point to confirm with a lawyer.*
- **Use the KVM fast path where you can.** KVM is reached through kernel `ioctl`s,
  a syscall ABI, so it carries no linking obligation and the hardware-assisted
  core stays license-clean.
- **Prefer permissive alternatives for anything linked directly.** Use **asmjit**
  (Zlib) rather than Keystone (GPL) for assembly, and **Capstone** (BSD) for
  disassembly. Keep the **decompiler** (Apache-2.0) and **Luau** (MIT) in the main
  binary.
- **Do not copy x64dbg or Scylla source** unless you intend to ship as GPLv3.
  Reuse their design instead.
- **LibVMI is LGPLv3**, so dynamic linking keeps its obligations off the rest of
  the code.

## How this repository encodes the strategy

- The permissively-licensed **main binary** holds the decompiler, shell, Luau, and
  the pattern spine. Every source file is `SPDX-License-Identifier: Apache-2.0`.
- Only **Capstone** (BSD) is a hard, directly-linked dependency today.
- The GPL and heavy backends are **build options, default `OFF`**
  (`DEDE_WITH_UNICORN`, `DEDE_WITH_GHIDRA`, `DEDE_WITH_LUAU`, `DEDE_WITH_ASMJIT`,
  `DEDE_WITH_LIBVMI`), each behind a clean adapter interface.
- `DEDE_WITH_UNICORN` is wired to the **`emu-host` separate process**, never into
  the main binary — the boundary the licensing requires is the same boundary the
  architecture already draws.

The clean outcome: a permissively-licensed main binary, a separate GPL emulator
process, and the hardware path going straight to KVM. That contains the copyleft
and leaves our own code's license free.
