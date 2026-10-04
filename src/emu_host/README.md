<!-- SPDX-License-Identifier: Apache-2.0 -->
# emu-host — the separate (GPL) emulator process

This directory is the home of the out-of-process execution backend. When
`DEDE_WITH_UNICORN` (or a QEMU backend) is enabled, the emulator runs here as its
**own program**, not linked into the main `dede` binary, and the two communicate
over the IPC protocol in [`include/dede/emu_host/ipc.hpp`](../../include/dede/emu_host/ipc.hpp).

Why a separate process rather than a linked library: Unicorn and QEMU are GPLv2,
and linking them into one binary would make that whole binary GPL (and could not
even coexist with the GPLv2-only / Apache-2.0 mix). Running the emulator as a
separate program that merely exchanges data keeps the copyleft contained in one
process and leaves the main binary's license free. See
[docs/LICENSING.md](../../docs/LICENSING.md).

This is also the architecture's natural seam: the core already drives execution
through the `IExecutionBackend` **Strategy**. A `UnicornBackend` in the main binary
would implement that interface by marshalling the `ipc.hpp` messages to this child
process — so from the core's point of view the out-of-process emulator is just
another backend, selected at construction time (Dependency Injection).

The host side (a `UnicornBackend` implementing `IExecutionBackend`) and the child
`main()` are the remaining work for build phase 6; the protocol and the boundary
are defined here so the rest of the system can be written against them.
