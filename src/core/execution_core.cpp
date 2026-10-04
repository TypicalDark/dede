// SPDX-License-Identifier: Apache-2.0
#include "dede/core/execution_core.hpp"

namespace dede {

ExecutionCore::ExecutionCore(Arch arch, BackendFactory backend_factory) : arch_(arch) {
    disasm_ = make_disassembler(arch_);
    proxy_ = std::make_unique<MemoryProxy>(mem_, sink_, ctx_);
    backend_ = backend_factory ? backend_factory(*disasm_) : make_builtin_backend(*disasm_);
    if (backend_->arch() != arch_)
        throw DedeError("ExecutionCore: backend architecture does not match the core");
}

StepOutcome ExecutionCore::step() {
    ctx_.pc = cpu_.rip();
    ctx_.tick = tick_;
    StepOutcome o = backend_->step(cpu_, *proxy_, *transp_, *sink_, ctx_);

    switch (o.status) {
        case StepOutcome::Status::Ok:
            // Increment first so the Step event's tick is the retired-instruction
            // count (what run points and the timeline key on), and its `address`
            // is where execution now sits (breakpoint-at-address semantics).
            ++tick_;
            sink_->emit(Event{EventKind::Step, ctx_.pc, cpu_.rip(), 0, 0, tick_, {}});
            break;
        case StepOutcome::Status::Halted:
        case StepOutcome::Status::Breakpoint:
            // The instruction retired; the backend already emitted its event.
            ++tick_;
            break;
        case StepOutcome::Status::Unsupported:
        case StepOutcome::Status::Fault:
            // Did not retire: tick and rip are left where they are so the analyst
            // sees exactly where execution stopped.
            break;
    }
    return o;
}

StateMemento ExecutionCore::snapshot() const {
    StateMemento m;
    m.cpu_ = cpu_;
    // Reuse the cached memory snapshot when nothing was written since it was taken;
    // only re-copy the page map when memory actually changed.
    u64 gen = mem_.write_gen();
    if (!mem_cache_ || gen != mem_cache_gen_) {
        mem_cache_ = std::make_shared<const MemorySnapshot>(mem_.snapshot());
        mem_cache_gen_ = gen;
    }
    m.mem_ = mem_cache_;
    m.tick_ = tick_;
    return m;
}

void ExecutionCore::restore(const StateMemento& m) {
    cpu_ = m.cpu_;
    mem_.restore(*m.mem_);
    tick_ = m.tick_;
    // Memory now equals this snapshot; make it the cache so an immediately
    // following snapshot (with no writes) reuses it.
    mem_cache_ = m.mem_;
    mem_cache_gen_ = mem_.write_gen();
    proxy_->reset_wx();
}

}  // namespace dede
