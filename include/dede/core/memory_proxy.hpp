// SPDX-License-Identifier: Apache-2.0
//
// Proxy (GoF) over guest memory: every guest data access goes through here so it
// can be observed (MemRead/MemWrite events) and so W^X — a page written as data
// and then executed — is detected. The interpreter never touches GuestMemory
// directly for data; it goes through the proxy.
#pragma once

#include <set>

#include "dede/common/memory.hpp"
#include "dede/core/event.hpp"
#include "dede/core/exec_context.hpp"

namespace dede {

class MemoryProxy {
public:
    // `sink` is bound by reference-to-pointer so the proxy always emits through
    // the core's current sink, even after set_event_sink() swaps it.
    MemoryProxy(GuestMemory& mem, IEventSink*& sink, const ExecContext& ctx)
        : mem_(mem), sink_(sink), ctx_(ctx) {}

    GuestMemory& backing() noexcept { return mem_; }
    const GuestMemory& backing() const noexcept { return mem_; }

    // Observed data access (emits MemRead / MemWrite).
    Result<u64> read(Addr a, unsigned bytes);
    Result<void> write(Addr a, unsigned bytes, u64 v);

    // Instruction fetch into a caller-provided buffer (no per-instruction heap
    // allocation on the hot path). Returns the number of bytes read. Does not emit
    // a data event, but detects W^X: if the fetched page was written since it was
    // last executed, emits ExecWrittenPage (re-arming only after the next write).
    Result<unsigned> fetch(Addr a, u8* buf, unsigned len);

    // Silent access for tooling (snapshots, the shell's `x` command) that must
    // not perturb the observed event stream or W^X state.
    Result<u64> peek(Addr a, unsigned bytes) const { return mem_.read_int(a, bytes); }
    Result<void> poke(Addr a, unsigned bytes, u64 v) { return mem_.write_int(a, bytes, v); }

    void reset_wx() { written_pages_.clear(); }

private:
    GuestMemory& mem_;
    IEventSink*& sink_;
    const ExecContext& ctx_;
    std::set<u64> written_pages_;  // pages written and not yet re-executed
};

}  // namespace dede
