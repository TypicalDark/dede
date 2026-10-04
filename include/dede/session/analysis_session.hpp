// SPDX-License-Identifier: Apache-2.0
//
// AnalysisSession is the Facade: the single object the shell and the embedded
// script engine talk to. It wires the execution core, the Memento timeline, the
// macro/run-point engine, the transparency chain, the disassembler, the
// assembler, the decompiler, and introspection together, and presents one stable
// API over them. It also implements IDebugController so Commands and macros act
// on it, and owns the session State machine.
//
// Subsystems are injected (Dependency Injection): the default constructor wires
// the production implementations, but tests can supply their own.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "dede/core/execution_core.hpp"
#include "dede/decompiler/decompiler.hpp"
#include "dede/disasm/assembler.hpp"
#include "dede/introspection/introspector.hpp"
#include "dede/macro/command.hpp"
#include "dede/macro/controller.hpp"
#include "dede/macro/event_bus.hpp"
#include "dede/macro/macro_engine.hpp"
#include "dede/macro/run_point.hpp"
#include "dede/replay/timeline.hpp"
#include "dede/session/engine.hpp"
#include "dede/session/session_state.hpp"
#include "dede/transparency/interceptor.hpp"

namespace dede {

// Injected dependencies; any left null are filled with the production default.
struct SessionDeps {
    std::unique_ptr<IAssembler> assembler;
    std::unique_ptr<IDecompiler> decompiler;
    std::unique_ptr<IIntrospector> introspector;
    ExecutionCore::BackendFactory backend;  // {} => default in-tree interpreter
    TimelineManager::Config timeline{};     // ring/snapshot sizing
};

class AnalysisSession final : public IAnalysisEngine {
public:
    explicit AnalysisSession(Arch arch = Arch::X86_64);
    AnalysisSession(Arch arch, SessionDeps deps);

    Arch arch() const override { return core_.arch(); }
    Phase phase() const override { return state_->phase(); }
    const ISessionState& state() const { return *state_; }
    const char* phase_name() const override { return state_->name(); }
    std::string backend_name() const override { return core_.backend_name(); }
    Addr rip() const override { return core_.cpu().rip(); }
    u64 rflags() const override { return core_.cpu().rflags(); }

    // --- loading the target --------------------------------------------------
    void map(Addr base, u64 size, u8 perms) override { core_.memory().map(base, size, perms); }
    Result<void> load(Addr base, const std::vector<u8>& bytes, u8 perms = perm::RX) override;
    void set_entry(Addr rip) override;  // sets rip, captures tick 0, enters Paused

    // --- IDebugController: observing ----------------------------------------
    u64 read_reg(Reg r) const override { return core_.cpu().get(r); }
    Result<u64> read_mem(Addr a, unsigned bytes) const override {
        return core_.memory().read_int(a, bytes);
    }
    Result<std::vector<u8>> read_bytes(Addr a, unsigned len) const override {
        return core_.memory().read(a, len);
    }
    Tick now() const override { return core_.tick(); }
    Result<std::vector<u8>> assemble(const std::string& text, Addr at) const override {
        return assembler_->assemble(text, at);
    }

    // --- IDebugController: mutating (logged as injected events) --------------
    void write_reg(Reg r, u64 v, const std::string& note = {}) override;
    Result<void> write_bytes(Addr a, const std::vector<u8>& data,
                             const std::string& note = {}) override;

    // --- IDebugController: control ------------------------------------------
    StepOutcome step() override;
    Result<void> step_back(Tick n) override;

    // --- higher-level control ------------------------------------------------
    StepOutcome run(u64 max_steps = kRunForever) override;     // until stop/halt/fault
    Result<void> run_to(Addr addr, u64 max_steps = kRunForever) override;
    Result<void> seek(Tick tick) override;                    // absolute time-travel

    // --- views ---------------------------------------------------------------
    std::vector<DecodedInsn> disassemble(Addr addr, std::size_t count) const override;
    Result<std::string> decompile(Addr addr, u64 len) override;
    Cfg build_cfg(Addr entry) const override;
    IDisassembler& disassembler() { return core_.disassembler(); }

    // --- run points & macros -------------------------------------------------
    u64 add_breakpoint(Addr addr, std::string label = {}) override;
    u64 add_run_point(RunPoint rp) override;
    bool bind_macro(u64 run_point_id, MacroPtr macro) override;
    bool remove_run_point(u64 id) override { return macros_.remove_run_point(id); }
    bool enable_run_point(u64 id, bool on) override { return macros_.set_enabled(id, on); }
    const std::vector<RunPoint>& run_points() const override { return macros_.run_points(); }

    // Macro recording: begin, run commands through the session, then finalise.
    void start_recording() override;
    MacroPtr stop_recording(std::string name) override;
    bool recording() const override { return macros_.recording(); }
    // Execute a command through the session (and capture it if recording).
    Result<void> run_command(CommandPtr cmd) override;

    // --- transparency --------------------------------------------------------
    void enable_transparency(ForgedEnvironment env = {}) override;
    void disable_transparency() override;
    bool transparency_enabled() const override { return transparency_on_; }

    // --- quality-of-life -----------------------------------------------------
    SymbolTable& symbols() override { return symbols_; }
    const SymbolTable& symbols() const override { return symbols_; }
    const EventHistory& history() const override { return history_; }
    std::vector<Addr> search(Addr start, u64 len, const std::vector<u8>& needle) const override;
    std::optional<Event> who_wrote(Addr addr, unsigned size = 1) const override {
        return history_.last_write(addr, size);
    }
    Result<void> save_session(const std::string& path) const override;
    Result<void> load_session(const std::string& path) override;
    std::vector<Region> memory_map() const override;

    // --- introspection & timeline (UI-facing) --------------------------------
    IIntrospector& introspector() override { return *introspector_; }
    TimelineStats timeline_stats() const override {
        return {timeline_.now(), timeline_.max_tick(), timeline_.ring_size(),
                timeline_.snapshot_count(), timeline_.injected_count()};
    }

    // --- live events (Observer) ---------------------------------------------
    void subscribe(IEventObserver* o) override { bus_.subscribe(o); }
    void unsubscribe(IEventObserver* o) override { bus_.unsubscribe(o); }

    // --- subsystem access for wiring code (apps/tests), not the UI -----------
    EventBus& event_bus() { return bus_; }
    MacroEngine& macros() { return macros_; }
    TimelineManager& timeline() { return timeline_; }
    ExecutionCore& core() { return core_; }

private:
    void set_phase(Phase p) { state_ = &session_state(p); }

    ExecutionCore core_;
    EventBus bus_;
    TimelineManager timeline_;
    MacroEngine macros_;

    std::unique_ptr<IAssembler> assembler_;
    std::unique_ptr<IDecompiler> decompiler_;
    std::unique_ptr<IIntrospector> introspector_;
    std::unique_ptr<TransparencyChain> transparency_;
    bool transparency_on_ = false;

    SymbolTable symbols_;
    EventHistory history_;

    const ISessionState* state_ = &session_state(Phase::Idle);
};

}  // namespace dede
