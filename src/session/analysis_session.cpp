// SPDX-License-Identifier: Apache-2.0
#include "dede/session/analysis_session.hpp"

namespace dede {

AnalysisSession::AnalysisSession(Arch arch) : AnalysisSession(arch, SessionDeps{}) {}

AnalysisSession::AnalysisSession(Arch arch, SessionDeps deps)
    : core_(arch), timeline_(core_, deps.timeline) {
    // Observer wiring: the core emits to the bus; the macro engine subscribes.
    core_.set_event_sink(&bus_);
    bus_.subscribe(&macros_);
    macros_.bind_controller(this);

    // Dependency injection with production defaults.
    assembler_ = deps.assembler ? std::move(deps.assembler) : make_assembler(arch);
    decompiler_ = deps.decompiler ? std::move(deps.decompiler)
                                  : make_decompiler(core_.disassembler());
    introspector_ = deps.introspector ? std::move(deps.introspector) : make_introspector();
}

Result<void> AnalysisSession::load(Addr base, const std::vector<u8>& bytes, u8 perms) {
    core_.memory().map(base, bytes.empty() ? 1 : bytes.size(), perms);
    return core_.memory().write(base, bytes);
}

void AnalysisSession::set_entry(Addr rip) {
    core_.cpu().set_rip(rip);
    timeline_.begin();
    set_phase(Phase::Paused);
}

void AnalysisSession::write_reg(Reg r, u64 v, const std::string& note) {
    // Editing the past forks the timeline.
    if (timeline_.now() < timeline_.max_tick()) timeline_.truncate_after(timeline_.now());
    core_.cpu().set(r, v);
    InjectedEvent ev;
    ev.tick = now();
    ev.kind = InjectedEvent::Kind::RegWrite;
    ev.reg = r;
    ev.value = v;
    ev.note = note;
    timeline_.inject(std::move(ev));
    timeline_.amend();
}

Result<void> AnalysisSession::write_bytes(Addr a, const std::vector<u8>& data,
                                          const std::string& note) {
    if (timeline_.now() < timeline_.max_tick()) timeline_.truncate_after(timeline_.now());
    auto r = core_.memory().write(a, data);
    if (!r) return r;
    InjectedEvent ev;
    ev.tick = now();
    ev.kind = InjectedEvent::Kind::MemWrite;
    ev.addr = a;
    ev.bytes = data;
    ev.note = note;
    timeline_.inject(std::move(ev));
    timeline_.amend();
    return {};
}

StepOutcome AnalysisSession::step() {
    if (!state_->can_step()) {
        return {StepOutcome::Status::Fault, "cannot step in state '" +
                                                std::string(state_->name()) + "'"};
    }
    StepOutcome o = core_.step();      // emits events -> bus -> macro engine queues matches
    macros_.fire_pending();            // run matched macros (may mutate + inject)
    timeline_.record();                // memento now reflects any macro mutations
    return o;
}

Result<void> AnalysisSession::step_back(Tick n) {
    set_phase(Phase::Replaying);
    auto r = timeline_.step_back(n);
    set_phase(Phase::Paused);
    return r;
}

Result<void> AnalysisSession::seek(Tick tick) {
    set_phase(Phase::Replaying);
    auto r = timeline_.seek(tick);
    set_phase(Phase::Paused);
    return r;
}

StepOutcome AnalysisSession::run(u64 max_steps) {
    set_phase(Phase::Running);
    StepOutcome o{StepOutcome::Status::Ok, {}};
    for (u64 i = 0; i < max_steps; ++i) {
        o = step();
        if (o.status != StepOutcome::Status::Ok) break;
        if (macros_.consume_stop()) break;  // a pausing run point (breakpoint) fired
    }
    set_phase(Phase::Paused);
    return o;
}

Result<void> AnalysisSession::run_to(Addr addr, u64 max_steps) {
    set_phase(Phase::Running);
    for (u64 i = 0; i < max_steps; ++i) {
        if (core_.cpu().rip() == addr) {
            set_phase(Phase::Paused);
            return {};
        }
        StepOutcome o = step();
        if (o.status != StepOutcome::Status::Ok) {
            set_phase(Phase::Paused);
            return make_error("run_to: execution stopped (" + o.note + ") before reaching target");
        }
    }
    set_phase(Phase::Paused);
    return (core_.cpu().rip() == addr) ? Result<void>{} : make_error("run_to: target not reached");
}

std::vector<DecodedInsn> AnalysisSession::disassemble(Addr addr, std::size_t count) const {
    std::vector<u8> buf;
    buf.reserve(count * 15);
    for (std::size_t i = 0; i < count * 15; ++i) {
        auto b = core_.memory().read8(addr + i);
        if (!b) break;
        buf.push_back(b.value());
    }
    return core_.disassembler().decode(buf.data(), buf.size(), addr, count);
}

Result<std::string> AnalysisSession::decompile(Addr addr, u64 len) {
    auto code = read_bytes(addr, static_cast<unsigned>(len));
    if (!code) return code.error();
    return decompiler_->decompile(code.value(), addr);
}

u64 AnalysisSession::add_breakpoint(Addr addr, std::string label) {
    RunPoint rp;
    rp.type = RunPointType::Address;
    rp.address = addr;
    rp.pause = true;
    rp.label = label.empty() ? ("bp@" + std::to_string(addr)) : std::move(label);
    return macros_.add_run_point(std::move(rp));
}

u64 AnalysisSession::add_run_point(RunPoint rp) { return macros_.add_run_point(std::move(rp)); }

bool AnalysisSession::bind_macro(u64 run_point_id, MacroPtr macro) {
    if (RunPoint* rp = macros_.find(run_point_id)) {
        rp->macro = std::move(macro);
        return true;
    }
    return false;
}

void AnalysisSession::start_recording() {
    macros_.start_recording();
    set_phase(Phase::Recording);
}

MacroPtr AnalysisSession::stop_recording(std::string name) {
    auto m = macros_.stop_recording(std::move(name));
    set_phase(Phase::Paused);
    return m;
}

Result<void> AnalysisSession::run_command(CommandPtr cmd) {
    auto r = cmd->execute(*this);
    if (r && macros_.recording()) macros_.record_command(cmd);
    return r;
}

void AnalysisSession::enable_transparency(ForgedEnvironment env) {
    transparency_ = make_transparency_chain(std::move(env));
    core_.set_transparency(transparency_.get());
    transparency_on_ = true;
}

void AnalysisSession::disable_transparency() {
    core_.set_transparency(nullptr);
    transparency_on_ = false;
}

}  // namespace dede
