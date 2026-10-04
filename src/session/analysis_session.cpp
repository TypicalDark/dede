// SPDX-License-Identifier: Apache-2.0
#include "dede/session/analysis_session.hpp"

#include <fstream>
#include <sstream>
#include <string>

namespace dede {

AnalysisSession::AnalysisSession(Arch arch) : AnalysisSession(arch, SessionDeps{}) {}

AnalysisSession::AnalysisSession(Arch arch, SessionDeps deps)
    : core_(arch, deps.backend), timeline_(core_, deps.timeline) {
    // Observer wiring: the core emits to the bus; the macro engine and the event
    // history subscribe.
    core_.set_event_sink(&bus_);
    bus_.subscribe(&macros_);
    bus_.subscribe(&history_);
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
    if (!state_->can_mutate()) return;  // State pattern: no edits while Idle/Replaying
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
    if (!state_->can_mutate())
        return make_error("cannot modify memory in state '" + std::string(state_->name()) + "'");
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
    // Forward into unexplored territory must go through the full step pipeline so
    // run points and mutating macros fire (and get injected); only backward / within
    // the explored timeline is a silent memento replay.
    if (tick > timeline_.max_tick()) {
        set_phase(Phase::Running);
        if (timeline_.now() != timeline_.max_tick()) {
            if (auto r = timeline_.seek(timeline_.max_tick()); !r) { set_phase(Phase::Paused); return r; }
        }
        while (core_.tick() < tick) {
            StepOutcome o = step();  // core.step + fire_pending + record
            if (o.status != StepOutcome::Status::Ok) {
                set_phase(Phase::Paused);
                return make_error("seek: execution stopped (" + o.note + ") before the target tick");
            }
        }
        set_phase(Phase::Paused);
        return {};
    }
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

Cfg AnalysisSession::build_cfg(Addr entry) const {
    const GuestMemory& mem = core_.memory();
    ByteReader read = [&mem](Addr a) -> std::optional<u8> {
        auto b = mem.read8(a);
        if (!b) return std::nullopt;
        return b.value();
    };
    return dede::build_cfg(core_.disassembler(), read, entry);
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
    if (!state_->can_record_start()) return;  // State pattern: only from Paused
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

std::vector<Addr> AnalysisSession::search(Addr start, u64 len,
                                          const std::vector<u8>& needle) const {
    std::vector<Addr> hits;
    if (needle.empty() || len < needle.size()) return hits;
    const GuestMemory& mem = core_.memory();
    // Simple sliding window; unmapped bytes break a candidate match.
    for (u64 i = 0; i + needle.size() <= len; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            auto b = mem.read8(start + i + j);
            if (!b || b.value() != needle[j]) { match = false; break; }
        }
        if (match) hits.push_back(start + i);
    }
    return hits;
}

namespace {
char nib(u8 v) { return "0123456789abcdef"[v & 0xf]; }
bool page_all_zero(const GuestMemory& m, u64 base) {
    for (u64 i = 0; i < kPageSize; ++i) {
        auto b = m.read8(base + i);
        if (b && b.value() != 0) return false;
    }
    return true;
}
std::string to_hex(u64 v) {
    std::ostringstream o;
    o << std::hex << v;
    return o.str();
}
}  // namespace

Result<void> AnalysisSession::save_session(const std::string& path) const {
    std::ofstream f(path);
    if (!f) return make_error("save_session: cannot open " + path);
    f << "DEDE-SESSION 1\nARCH x86_64\nENTRY 0x" << to_hex(core_.cpu().rip()) << "\n";
    for (int i = 0; i < static_cast<int>(kNumReg); ++i) {
        Reg r = static_cast<Reg>(i);
        f << "REG " << reg_name(r) << " 0x" << to_hex(core_.cpu().get(r)) << "\n";
    }
    for (u64 base : core_.memory().mapped_pages()) {
        f << "MAP 0x" << to_hex(base) << " 0x" << to_hex(kPageSize) << " "
          << unsigned(core_.memory().permissions(base)) << "\n";
        if (page_all_zero(core_.memory(), base)) continue;  // sparse: skip blanks
        f << "DATA 0x" << to_hex(base) << " ";
        for (u64 i = 0; i < kPageSize; ++i) {
            auto b = core_.memory().read8(base + i);
            u8 v = b ? b.value() : 0;
            f << nib(v >> 4) << nib(v);
        }
        f << "\n";
    }
    for (const auto& [addr, name] : symbols_.all())
        f << "SYM 0x" << to_hex(addr) << " " << name << "\n";
    for (const auto& rp : macros_.run_points())
        if (rp.type == RunPointType::Address)
            f << "BP 0x" << to_hex(rp.address) << " " << rp.label << "\n";
    return {};
}

Result<void> AnalysisSession::load_session(const std::string& path) {
    std::ifstream f(path);
    if (!f) return make_error("load_session: cannot open " + path);
    std::string line;
    Addr entry = 0;
    auto parse = [](const std::string& s) -> u64 {
        return s.empty() ? 0 : std::stoull(s, nullptr, 0);
    };
    while (std::getline(f, line)) {
        std::istringstream is(line);
        std::string k;
        is >> k;
        if (k == "ENTRY") { std::string v; is >> v; entry = parse(v); }
        else if (k == "REG") {
            std::string name, v; is >> name >> v;
            if (auto r = reg_from_name(name)) core_.cpu().set(*r, parse(v));
        } else if (k == "MAP") {
            std::string base, size; unsigned perms = 0; is >> base >> size >> perms;
            core_.memory().map(parse(base), parse(size), static_cast<u8>(perms));
        } else if (k == "DATA") {
            std::string base, run; is >> base >> run;
            u64 b = parse(base);
            for (std::size_t i = 0; i + 1 < run.size(); i += 2)
                core_.memory().write8(b + i / 2,
                                      static_cast<u8>(std::stoul(run.substr(i, 2), nullptr, 16)));
        } else if (k == "SYM") {
            std::string a, name; is >> a >> name;
            symbols_.add(parse(a), name);
        } else if (k == "BP") {
            std::string a; is >> a;
            add_breakpoint(parse(a));
        }
    }
    core_.cpu().set_rip(entry);
    timeline_.begin();
    set_phase(Phase::Paused);
    return {};
}

std::vector<IAnalysisEngine::Region> AnalysisSession::memory_map() const {
    std::vector<Region> out;
    for (u64 base : core_.memory().mapped_pages()) {
        u8 p = core_.memory().permissions(base);
        if (!out.empty() && out.back().base + out.back().size == base && out.back().perms == p) {
            out.back().size += kPageSize;  // coalesce contiguous same-perm pages
        } else {
            out.push_back({base, kPageSize, p});
        }
    }
    return out;
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
