// SPDX-License-Identifier: Apache-2.0
//
// Strategy (GoF): the pluggable execution backend. The built-in interpreter and
// a (future) Unicorn/KVM backend implement the same interface, so the core can
// swap one for another without change. make_builtin_backend() builds the
// in-tree x86-64 interpreter; a Unicorn adapter would provide its own factory.
#pragma once

#include <memory>
#include <string>

#include "dede/common/cpu_state.hpp"
#include "dede/core/event.hpp"
#include "dede/core/exec_context.hpp"
#include "dede/core/memory_proxy.hpp"
#include "dede/core/transparency_iface.hpp"
#include "dede/disasm/disassembler.hpp"

namespace dede {

struct StepOutcome {
    enum class Status {
        Ok,           // one instruction executed, control continues
        Halted,       // guest executed hlt
        Breakpoint,   // guest executed int3 itself
        Unsupported,  // interpreter does not model this instruction
        Fault         // bad memory access or malformed instruction
    } status = Status::Ok;
    std::string note;
};

class IExecutionBackend {
public:
    virtual ~IExecutionBackend() = default;
    virtual std::string name() const = 0;
    virtual Arch arch() const = 0;

    // Execute exactly one instruction at cpu.rip(), mutating cpu and memory,
    // emitting the specific events it produces (mem access, cpuid, rdtsc, ...),
    // and consulting the transparency chain for probes. The core is responsible
    // for the Step event and the tick counter.
    virtual StepOutcome step(CpuState& cpu, MemoryProxy& mem, ITransparency& tr,
                             IEventSink& sink, const ExecContext& ctx) = 0;
};

// The in-tree deterministic x86-64 interpreter. It borrows the core's
// disassembler and owns its own Flyweight decode cache.
std::unique_ptr<IExecutionBackend> make_builtin_backend(IDisassembler& disasm);

}  // namespace dede
