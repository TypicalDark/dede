// SPDX-License-Identifier: Apache-2.0
//
// IAnalysisEngine is the contract a user interface binds onto — the Facade's
// public face, expressed as an interface so the front end (CLI today; a TUI or
// web view tomorrow) depends on behaviour, not on the concrete session or any
// subsystem. A UI must never reach past this into the core, timeline, or bus.
// It extends IDebugController so the same object also drives Commands and macros.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "dede/analysis/cfg.hpp"              // Cfg
#include "dede/core/backend.hpp"              // StepOutcome
#include "dede/disasm/instruction.hpp"        // DecodedInsn
#include "dede/introspection/introspector.hpp"
#include "dede/macro/controller.hpp"          // IDebugController
#include "dede/macro/event_bus.hpp"           // IEventObserver
#include "dede/macro/run_point.hpp"           // RunPoint, MacroPtr, CommandPtr
#include "dede/session/event_history.hpp"     // EventHistory
#include "dede/session/session_state.hpp"     // Phase
#include "dede/session/symbol_table.hpp"      // SymbolTable
#include "dede/transparency/forged_env.hpp"   // ForgedEnvironment

namespace dede {

class IAnalysisEngine : public IDebugController {
public:
    struct Region {
        Addr base = 0;
        u64 size = 0;
        u8 perms = 0;
    };
    struct TimelineStats {
        Tick now = 0;
        Tick max = 0;
        std::size_t ring = 0;
        std::size_t snapshots = 0;
        std::size_t injected = 0;
    };

    // --- identity & state ----------------------------------------------------
    virtual Arch arch() const = 0;
    virtual Phase phase() const = 0;
    virtual const char* phase_name() const = 0;
    virtual std::string backend_name() const = 0;
    virtual Addr rip() const = 0;
    virtual u64 rflags() const = 0;

    // --- loading the target --------------------------------------------------
    virtual void map(Addr base, u64 size, u8 perms) = 0;
    virtual Result<void> load(Addr base, const std::vector<u8>& bytes, u8 perms) = 0;
    virtual void set_entry(Addr rip) = 0;

    // --- views ---------------------------------------------------------------
    virtual std::vector<DecodedInsn> disassemble(Addr addr, std::size_t count) const = 0;
    virtual Result<std::string> decompile(Addr addr, u64 len) = 0;
    // Control-flow graph of the function at `entry`, from the live byte image.
    virtual Cfg build_cfg(Addr entry) const = 0;

    // Safety cap for "run until it stops on its own" (a runaway guard, not a
    // semantic limit). Shared by the interface default and the implementation.
    static constexpr u64 kRunForever = 100'000'000ull;

    // --- higher-level control (step/step_back come from IDebugController) -----
    virtual StepOutcome run(u64 max_steps = kRunForever) = 0;
    virtual Result<void> run_to(Addr addr, u64 max_steps = kRunForever) = 0;
    virtual Result<void> seek(Tick tick) = 0;

    // --- run points & macros -------------------------------------------------
    virtual u64 add_breakpoint(Addr addr, std::string label = {}) = 0;
    virtual u64 add_run_point(RunPoint rp) = 0;
    virtual bool bind_macro(u64 run_point_id, MacroPtr macro) = 0;
    virtual bool remove_run_point(u64 id) = 0;
    virtual bool enable_run_point(u64 id, bool on) = 0;
    virtual const std::vector<RunPoint>& run_points() const = 0;
    virtual void start_recording() = 0;
    virtual MacroPtr stop_recording(std::string name) = 0;
    virtual bool recording() const = 0;
    virtual Result<void> run_command(CommandPtr cmd) = 0;

    // --- transparency --------------------------------------------------------
    virtual void enable_transparency(ForgedEnvironment env = {}) = 0;
    virtual void disable_transparency() = 0;
    virtual bool transparency_enabled() const = 0;

    // --- quality-of-life -----------------------------------------------------
    virtual SymbolTable& symbols() = 0;
    virtual const SymbolTable& symbols() const = 0;
    virtual const EventHistory& history() const = 0;
    // Find every occurrence of `needle` in [start, start+len).
    virtual std::vector<Addr> search(Addr start, u64 len, const std::vector<u8>& needle) const = 0;
    // Most recent instruction that wrote [addr,addr+size): {pc, tick} or nullopt.
    virtual std::optional<Event> who_wrote(Addr addr, unsigned size = 1) const = 0;
    virtual Result<void> save_session(const std::string& path) const = 0;
    virtual Result<void> load_session(const std::string& path) = 0;
    // Mapped memory regions (coalesced contiguous same-perm pages), ascending.
    virtual std::vector<Region> memory_map() const = 0;

    // --- introspection & timeline -------------------------------------------
    virtual IIntrospector& introspector() = 0;
    virtual TimelineStats timeline_stats() const = 0;

    // --- live events (Observer) ---------------------------------------------
    virtual void subscribe(IEventObserver* o) = 0;
    virtual void unsubscribe(IEventObserver* o) = 0;
};

}  // namespace dede
