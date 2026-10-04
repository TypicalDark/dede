// SPDX-License-Identifier: Apache-2.0
//
// The ExecutionCore owns the machine (registers + memory), drives the backend
// one instruction at a time, and is the Originator of the Memento pattern. It
// knows nothing about timelines, macros, or the shell — those sit above it and
// talk to it through the AnalysisSession Facade.
#pragma once

#include <functional>
#include <memory>

#include "dede/common/cpu_state.hpp"
#include "dede/common/memory.hpp"
#include "dede/core/backend.hpp"
#include "dede/core/event.hpp"
#include "dede/core/exec_context.hpp"
#include "dede/core/memento.hpp"
#include "dede/core/memory_proxy.hpp"
#include "dede/core/transparency_iface.hpp"
#include "dede/disasm/disassembler.hpp"

namespace dede {

class ExecutionCore {
public:
    // Dependency injection: the backend (the central Strategy) is built by a
    // factory that can be swapped — the in-tree interpreter by default, a
    // Unicorn/KVM backend otherwise — so adding one needs no edit here (OCP/DIP).
    using BackendFactory = std::function<std::unique_ptr<IExecutionBackend>(IDisassembler&)>;

    explicit ExecutionCore(Arch arch = Arch::X86_64, BackendFactory backend_factory = {});

    // --- machine access ------------------------------------------------------
    CpuState& cpu() noexcept { return cpu_; }
    const CpuState& cpu() const noexcept { return cpu_; }
    GuestMemory& memory() noexcept { return mem_; }
    const GuestMemory& memory() const noexcept { return mem_; }
    MemoryProxy& memory_proxy() noexcept { return *proxy_; }
    IDisassembler& disassembler() noexcept { return *disasm_; }
    const IDisassembler& disassembler() const noexcept { return *disasm_; }

    Arch arch() const noexcept { return arch_; }
    Tick tick() const noexcept { return tick_; }
    std::string backend_name() const { return backend_->name(); }

    // --- wiring (Observer + transparency) ------------------------------------
    // Default to the Null Object for each, so a bare core runs with no listeners.
    void set_event_sink(IEventSink* s) noexcept { sink_ = s ? s : &null_sink_; }
    void set_transparency(ITransparency* t) noexcept { transp_ = t ? t : &null_transp_; }

    // Current sink, so the replay layer can mute observers during silent replay
    // and restore them afterwards.
    IEventSink* event_sink() const noexcept { return sink_; }

    // --- execution -----------------------------------------------------------
    // Execute one instruction. Advances tick on a retired instruction.
    StepOutcome step();

    // --- Memento (Originator) ------------------------------------------------
    StateMemento snapshot() const;
    void restore(const StateMemento& m);

private:
    Arch arch_;
    CpuState cpu_{};
    GuestMemory mem_{};
    ExecContext ctx_{};
    Tick tick_ = 0;

    NullEventSink null_sink_{};
    NullTransparency null_transp_{};
    IEventSink* sink_ = &null_sink_;
    ITransparency* transp_ = &null_transp_;

    std::unique_ptr<IDisassembler> disasm_;
    std::unique_ptr<MemoryProxy> proxy_;
    std::unique_ptr<IExecutionBackend> backend_;

    // Snapshot reuse cache: avoids re-copying the page map on steps that write no
    // memory (mutable because snapshot() is const but memoises).
    mutable std::shared_ptr<const MemorySnapshot> mem_cache_;
    mutable u64 mem_cache_gen_ = ~0ull;
};

}  // namespace dede
