// SPDX-License-Identifier: Apache-2.0
#include "dede/shell/shell.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace dede {
namespace {

std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::istringstream is(line);
    std::string tok;
    while (is >> tok) out.push_back(tok);
    return out;
}

bool parse_u64(const std::string& s, u64& out) {
    try {
        std::size_t pos = 0;
        out = std::stoull(s, &pos, 0);
        return pos == s.size();
    } catch (...) {
        return false;
    }
}

std::string hex(u64 v) {
    std::ostringstream o;
    o << "0x" << std::hex << v;
    return o.str();
}

}  // namespace

void Shell::TraceObserver::on_event(const Event& e) {
    if (!on_) return;
    out_ << "    [t=" << e.tick << "] " << to_string(e.kind) << " @ " << hex(e.pc);
    if (e.kind == EventKind::MemRead || e.kind == EventKind::MemWrite)
        out_ << " " << hex(e.address) << " = " << hex(e.value) << " (" << e.size << "B)";
    if (!e.note.empty()) out_ << "  ; " << e.note;
    out_ << "\n";
}

Shell::Shell(IAnalysisEngine& engine, IScriptEngine& script, std::ostream& out)
    : s_(engine), script_(script), out_(out), trace_(out, trace_on_) {
    s_.subscribe(&trace_);
}

bool Shell::execute(const std::string& line) {
    auto tok = tokenize(line);
    if (tok.empty()) return true;
    const std::string& cmd = tok[0];
    auto arg_u64 = [&](std::size_t i, u64 def) -> u64 {
        u64 v = def;
        if (i < tok.size()) parse_u64(tok[i], v);
        return v;
    };

    if (cmd == "quit" || cmd == "exit" || cmd == "q") return false;

    if (cmd == "help" || cmd == "?") {
        out_ <<
            "commands:\n"
            "  regs                     dump registers\n"
            "  reg <name> [value]       read or set a register\n"
            "  x <addr> [n]             hexdump n bytes (default 64)\n"
            "  dis [addr] [n]           disassemble n instrs (default: at rip)\n"
            "  decompile <addr> <len>   decompile a byte range\n"
            "  step [n] | s             step n instructions\n"
            "  back [n] | sb            step back n instructions (time-travel)\n"
            "  run | c                  run until breakpoint/halt\n"
            "  runto <addr>             run until rip == addr\n"
            "  goto <tick>              seek to an absolute instruction count\n"
            "  bp <addr>                set a breakpoint (pausing run point)\n"
            "  rp [del <id>|cond <e>|wx|mem <a>]  list/manage run points\n"
            "  where | w                show current instruction\n"
            "  timeline | tl            timeline statistics\n"
            "  transparency on|off      toggle the anti-analysis layer\n"
            "  patch <addr> <asm...>    assemble and patch in place\n"
            "  record start|stop [name] record a macro\n"
            "  trace on|off             live event trace\n"
            "  lua <code>               evaluate script\n"
            "  quit                     exit\n";
        return true;
    }

    if (cmd == "regs") {
        for (int i = 0; i < 16; ++i) {
            Reg r = static_cast<Reg>(i);
            out_ << std::setw(3) << std::left << reg_name(r) << " = " << hex(s_.read_reg(r)) << "   ";
            if (i % 2 == 1) out_ << "\n";
        }
        out_ << "rip = " << hex(s_.rip()) << "   flags = " << hex(s_.rflags())
             << "   [tick " << s_.now() << ", " << s_.phase_name() << "]\n";
        return true;
    }

    if (cmd == "reg") {
        if (tok.size() < 2) { out_ << "usage: reg <name> [value]\n"; return true; }
        auto r = reg_from_name(tok[1]);
        if (!r) { out_ << "unknown register: " << tok[1] << "\n"; return true; }
        if (tok.size() >= 3) {
            u64 v;
            if (!parse_u64(tok[2], v)) { out_ << "bad value\n"; return true; }
            s_.run_command(std::make_shared<WriteRegCommand>(*r, v, "shell reg set"));
            out_ << reg_name(*r) << " = " << hex(v) << "\n";
        } else {
            out_ << reg_name(*r) << " = " << hex(s_.read_reg(*r)) << "\n";
        }
        return true;
    }

    if (cmd == "x") {
        if (tok.size() < 2) { out_ << "usage: x <addr> [n]\n"; return true; }
        u64 addr = arg_u64(1, 0), n = arg_u64(2, 64);
        for (u64 i = 0; i < n; i += 16) {
            out_ << hex(addr + i) << ":";
            std::string ascii;
            for (u64 j = 0; j < 16 && i + j < n; ++j) {
                auto b = s_.read_mem(addr + i + j, 1);
                if (!b) { out_ << " ??"; ascii += '.'; continue; }
                out_ << " " << std::setw(2) << std::setfill('0') << std::hex << b.value()
                     << std::setfill(' ');
                u8 c = static_cast<u8>(b.value());
                ascii += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
            }
            out_ << "  " << ascii << "\n";
        }
        return true;
    }

    if (cmd == "dis") {
        u64 addr = tok.size() >= 2 ? arg_u64(1, s_.rip()) : s_.rip();
        u64 n = arg_u64(tok.size() >= 3 ? 2 : 99, 10);
        for (const auto& in : s_.disassemble(addr, n)) {
            out_ << (in.addr == s_.rip() ? "=> " : "   ") << hex(in.addr) << ":  "
                 << in.text() << "\n";
        }
        return true;
    }

    if (cmd == "decompile" || cmd == "dec") {
        if (tok.size() < 3) { out_ << "usage: decompile <addr> <len>\n"; return true; }
        auto r = s_.decompile(arg_u64(1, 0), arg_u64(2, 0));
        out_ << (r ? r.value() : ("error: " + r.message() + "\n"));
        return true;
    }

    if (cmd == "step" || cmd == "s") {
        u64 n = arg_u64(1, 1);
        StepOutcome o;
        for (u64 i = 0; i < n; ++i) {
            o = s_.step();
            if (o.status != StepOutcome::Status::Ok) {
                out_ << "stopped: " << o.note << "\n";
                break;
            }
        }
        execute("where");
        return true;
    }

    if (cmd == "back" || cmd == "sb") {
        auto r = s_.step_back(arg_u64(1, 1));
        if (!r) out_ << "error: " << r.message() << "\n";
        execute("where");
        return true;
    }

    if (cmd == "run" || cmd == "c" || cmd == "continue") {
        StepOutcome o = s_.run();
        out_ << "stopped at " << hex(s_.rip()) << " (" << o.note << ") tick "
             << s_.now() << "\n";
        return true;
    }

    if (cmd == "runto") {
        if (tok.size() < 2) { out_ << "usage: runto <addr>\n"; return true; }
        auto r = s_.run_to(arg_u64(1, 0));
        out_ << (r ? "reached " + hex(s_.rip()) + "\n" : "error: " + r.message() + "\n");
        return true;
    }

    if (cmd == "goto") {
        auto r = s_.seek(arg_u64(1, 0));
        if (!r) out_ << "error: " << r.message() << "\n";
        execute("where");
        return true;
    }

    if (cmd == "bp") {
        if (tok.size() < 2) { out_ << "usage: bp <addr>\n"; return true; }
        u64 id = s_.add_breakpoint(arg_u64(1, 0));
        out_ << "breakpoint #" << id << " @ " << hex(arg_u64(1, 0)) << "\n";
        return true;
    }

    if (cmd == "rp") {
        if (tok.size() == 1 || tok[1] == "list") {
            for (const auto& rp : s_.run_points()) {
                out_ << "  #" << rp.id << " " << to_string(rp.type)
                     << (rp.enabled ? "" : " [disabled]") << (rp.pause ? " [pause]" : "")
                     << (rp.macro ? " -> macro '" + rp.macro->name + "'" : "")
                     << "  hits=" << rp.hit_count << "\n";
            }
            return true;
        }
        if (tok[1] == "del" && tok.size() >= 3) {
            out_ << (s_.remove_run_point(arg_u64(2, 0)) ? "removed\n" : "no such run point\n");
            return true;
        }
        if (tok[1] == "wx") {
            RunPoint rp;
            rp.type = RunPointType::WrittenThenExec;
            rp.pause = true;
            u64 id = s_.add_run_point(std::move(rp));
            out_ << "W^X run point #" << id << "\n";
            return true;
        }
        if (tok[1] == "mem" && tok.size() >= 3) {
            RunPoint rp;
            rp.type = RunPointType::MemWrite;
            rp.address = arg_u64(2, 0);
            rp.pause = true;
            out_ << "mem-write run point #" << s_.add_run_point(std::move(rp)) << "\n";
            return true;
        }
        if (tok[1] == "cond") {
            std::string expr = line.substr(line.find("cond") + 4);
            auto c = Condition::parse(expr);
            if (!c) { out_ << "bad condition (use e.g. rp cond rax == 0x10)\n"; return true; }
            RunPoint rp;
            rp.type = RunPointType::Condition;
            rp.condition = *c;
            rp.pause = true;
            out_ << "condition run point #" << s_.add_run_point(std::move(rp)) << "\n";
            return true;
        }
        out_ << "usage: rp [list|del <id>|wx|mem <addr>|cond <expr>]\n";
        return true;
    }

    if (cmd == "where" || cmd == "w") {
        auto ins = s_.disassemble(s_.rip(), 1);
        out_ << "=> " << hex(s_.rip()) << ":  "
             << (ins.empty() ? "(unmapped)" : ins[0].text()) << "   [tick " << s_.now() << "]\n";
        return true;
    }

    if (cmd == "timeline" || cmd == "tl") {
        auto t = s_.timeline_stats();
        out_ << "tick " << t.now << " / max " << t.max << "  ring=" << t.ring
             << " snapshots=" << t.snapshots << " injected=" << t.injected << "\n";
        return true;
    }

    if (cmd == "transparency" || cmd == "transp") {
        if (tok.size() >= 2 && tok[1] == "on") { s_.enable_transparency(); out_ << "transparency ON\n"; }
        else if (tok.size() >= 2 && tok[1] == "off") { s_.disable_transparency(); out_ << "transparency OFF\n"; }
        else out_ << "transparency is " << (s_.transparency_enabled() ? "ON" : "OFF") << "\n";
        return true;
    }

    if (cmd == "patch") {
        if (tok.size() < 3) { out_ << "usage: patch <addr> <asm...>\n"; return true; }
        u64 addr = arg_u64(1, 0);
        std::string asm_text = line.substr(line.find(tok[2]));
        auto r = s_.run_command(std::make_shared<PatchCommand>(addr, asm_text));
        out_ << (r ? "patched " + hex(addr) + ": " + asm_text + "\n" : "error: " + r.message() + "\n");
        return true;
    }

    if (cmd == "record") {
        if (tok.size() >= 2 && tok[1] == "start") { s_.start_recording(); out_ << "recording...\n"; }
        else if (tok.size() >= 2 && tok[1] == "stop") {
            auto m = s_.stop_recording(tok.size() >= 3 ? tok[2] : "macro");
            out_ << "recorded macro '" << m->name << "' with " << m->commands.size()
                 << " commands (" << (m->mutating ? "mutating" : "observing") << ")\n";
        } else out_ << "usage: record start|stop [name]\n";
        return true;
    }

    if (cmd == "trace") {
        trace_on_ = (tok.size() >= 2 && tok[1] == "on");
        out_ << "trace " << (trace_on_ ? "ON" : "OFF") << "\n";
        return true;
    }

    if (cmd == "lua") {
        std::string code = line.size() > 4 ? line.substr(4) : "";
        auto r = script_.eval(code);
        out_ << (r ? r.value() : ("error: " + r.message())) << "\n";
        return true;
    }

    out_ << "unknown command: " << cmd << " (try 'help')\n";
    return true;
}

void Shell::repl(std::istream& in) {
    out_ << "dede — transparent time-travel analysis shell\n";
    out_ << "backend: " << s_.backend_name() << "   (type 'help')\n";
    std::string line;
    out_ << "dede> " << std::flush;
    while (std::getline(in, line)) {
        if (!execute(line)) break;
        out_ << "dede> " << std::flush;
    }
    out_ << "\n";
}

}  // namespace dede
