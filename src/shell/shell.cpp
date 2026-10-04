// SPDX-License-Identifier: Apache-2.0
#include "dede/shell/shell.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "dede/analysis/arch_view.hpp"
#include "dede/analysis/scan.hpp"

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

// Parse a needle for `find`: a quoted "string" or a run of hex byte pairs.
std::vector<u8> parse_needle(const std::vector<std::string>& tok, std::size_t from) {
    std::vector<u8> out;
    if (from >= tok.size()) return out;
    const std::string& first = tok[from];
    if (!first.empty() && first.front() == '"') {
        // reassemble quoted string across tokens
        std::string s;
        for (std::size_t i = from; i < tok.size(); ++i) s += (i > from ? " " : "") + tok[i];
        if (s.size() >= 2 && s.front() == '"' && s.back() == '"') s = s.substr(1, s.size() - 2);
        for (char c : s) out.push_back(static_cast<u8>(c));
        return out;
    }
    for (std::size_t i = from; i < tok.size(); ++i) {
        const std::string& h = tok[i];
        for (std::size_t j = 0; j + 1 < h.size(); j += 2) {
            try { out.push_back(static_cast<u8>(std::stoul(h.substr(j, 2), nullptr, 16))); }
            catch (...) {}
        }
    }
    return out;
}

}  // namespace

std::string Shell::annotate(Addr a) const {
    if (auto d = s_.symbols().describe(a)) return " <" + *d + ">";
    return {};
}

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
    if (!line.empty()) cmd_history_.push_back(line);

    // Alias expansion: replace a leading alias with its definition, keeping args.
    if (auto it = aliases_.find(tok[0]); it != aliases_.end()) {
        std::string expanded = it->second;
        for (std::size_t i = 1; i < tok.size(); ++i) expanded += " " + tok[i];
        return execute(expanded);
    }
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
            "  cfg [addr] [dot]         control-flow graph (code flow)\n"
            "  callgraph [addr]         program call graph\n"
            "  scan [addr] [n]          detect anti-vm/anti-debug/timing/crypto + complexity\n"
            "  entropy <addr> <len>     Shannon entropy of a region\n"
            "  opcodes [addr] [n]       instruction-frequency histogram\n"
            "  strings <addr> <len>     extract ASCII strings\n"
            "  capture on|off|list      capture guest syscalls/probes (Wireshark-style)\n"
            "  info                     image format, sections, imports, symbols\n"
            "  sections                 list loaded sections\n"
            "  imports [filter]         list imported (undefined) symbols\n"
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
            "  sym add <addr> <name>    name an address (shown in dis/stack)\n"
            "  find <start> <len> X     search memory (hex bytes or \"string\")\n"
            "  stack [n]                telescope the stack\n"
            "  watch <addr>             break on write to an address\n"
            "  who <addr> [size]        which instruction last wrote it (time-travel)\n"
            "  history [n]              recent execution events\n"
            "  save/load <path>         save or restore a session\n"
            "  alias <name> <cmd...>    define a command alias\n"
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
            bool is_bp = false;
            for (const auto& rp : s_.run_points())
                if (rp.type == RunPointType::Address && rp.address == in.addr) is_bp = true;
            out_ << (in.addr == s_.rip() ? "=> " : (is_bp ? " * " : "   ")) << hex(in.addr)
                 << annotate(in.addr) << ":  " << in.text() << "\n";
        }
        return true;
    }

    if (cmd == "cfg") {
        Addr entry = tok.size() >= 2 ? arg_u64(1, s_.rip()) : s_.rip();
        Cfg g = s_.build_cfg(entry);
        if (tok.size() >= 3 && tok[2] == "dot") {
            out_ << g.to_dot();
            return true;
        }
        out_ << "CFG of " << hex(entry) << annotate(entry) << ": " << g.blocks.size()
             << " blocks, " << g.edges.size() << " edges\n";
        for (const auto& b : g.blocks) {
            out_ << "  loc_" << std::hex << b.start << std::dec << annotate(b.start) << "  ("
                 << b.insns.size() << " insns" << (b.terminates ? ", terminal" : "") << ")\n";
            for (const auto& e : g.edges)
                if (e.from == b.start)
                    out_ << "      --" << to_string(e.kind) << "--> loc_" << std::hex << e.to
                         << std::dec << "\n";
        }
        out_ << "(use 'cfg " << hex(entry) << " dot' for graphviz)\n";
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
        out_ << "=> " << hex(s_.rip()) << annotate(s_.rip()) << ":  "
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

    if (cmd == "sym") {
        if (tok.size() >= 4 && tok[1] == "add") {
            s_.symbols().add(arg_u64(2, 0), tok[3]);
            out_ << "symbol " << tok[3] << " @ " << hex(arg_u64(2, 0)) << "\n";
        } else if (tok.size() >= 3 && tok[1] == "del") {
            s_.symbols().remove(arg_u64(2, 0));
            out_ << "removed\n";
        } else {
            for (const auto& [a, n] : s_.symbols().all()) out_ << "  " << hex(a) << "  " << n << "\n";
        }
        return true;
    }

    if (cmd == "find") {
        if (tok.size() < 4) { out_ << "usage: find <start> <len> <hexbytes | \"string\">\n"; return true; }
        auto needle = parse_needle(tok, 3);
        if (needle.empty()) { out_ << "empty needle\n"; return true; }
        auto hits = s_.search(arg_u64(1, 0), arg_u64(2, 0), needle);
        out_ << hits.size() << " hit(s)\n";
        for (std::size_t i = 0; i < hits.size() && i < 32; ++i)
            out_ << "  " << hex(hits[i]) << annotate(hits[i]) << "\n";
        return true;
    }

    if (cmd == "stack") {
        u64 n = arg_u64(1, 8), sp = s_.read_reg(Reg::Rsp);
        for (u64 i = 0; i < n; ++i) {
            Addr at = sp + i * 8;
            auto v = s_.read_mem(at, 8);
            out_ << "  " << hex(at) << (at == sp ? " <- rsp" : "       ") << " : "
                 << (v ? hex(v.value()) : "????") << (v ? annotate(v.value()) : "") << "\n";
        }
        return true;
    }

    if (cmd == "watch") {
        if (tok.size() < 2) { out_ << "usage: watch <addr>\n"; return true; }
        RunPoint rp;
        rp.type = RunPointType::MemWrite;
        rp.address = arg_u64(1, 0);
        rp.pause = true;
        rp.label = "watch@" + hex(arg_u64(1, 0));
        out_ << "watchpoint #" << s_.add_run_point(std::move(rp)) << " on write to " << hex(arg_u64(1, 0)) << "\n";
        return true;
    }

    if (cmd == "who") {
        if (tok.size() < 2) { out_ << "usage: who <addr> [size]\n"; return true; }
        auto w = s_.who_wrote(arg_u64(1, 0), static_cast<unsigned>(arg_u64(2, 1)));
        if (w) out_ << "last written by instruction at " << hex(w->pc) << annotate(w->pc)
                    << " at tick " << w->tick << " (value " << hex(w->value) << ")\n";
        else out_ << "no recorded write to that address in the event window\n";
        return true;
    }

    if (cmd == "history" || cmd == "hist") {
        const auto& ev = s_.history().events();
        u64 n = arg_u64(1, 20);
        std::size_t start = ev.size() > n ? ev.size() - n : 0;
        for (std::size_t i = start; i < ev.size(); ++i)
            out_ << "  [t=" << ev[i].tick << "] " << to_string(ev[i].kind) << " @ " << hex(ev[i].pc)
                 << (ev[i].kind == EventKind::MemWrite || ev[i].kind == EventKind::MemRead
                         ? " " + hex(ev[i].address) : "")
                 << "\n";
        return true;
    }

    if (cmd == "save") {
        if (tok.size() < 2) { out_ << "usage: save <path>\n"; return true; }
        auto r = s_.save_session(tok[1]);
        out_ << (r ? "saved to " + tok[1] + "\n" : "error: " + r.message() + "\n");
        return true;
    }
    if (cmd == "load") {
        if (tok.size() < 2) { out_ << "usage: load <path>\n"; return true; }
        auto r = s_.load_session(tok[1]);
        out_ << (r ? "loaded " + tok[1] + "\n" : "error: " + r.message() + "\n");
        return true;
    }

    // A ByteReader over the live guest image for the analysis functions.
    auto reader = [this](Addr a) -> std::optional<u8> {
        auto b = s_.read_mem(a, 1);
        if (!b) return std::nullopt;
        return static_cast<u8>(b.value());
    };

    if (cmd == "entropy") {
        if (tok.size() < 3) { out_ << "usage: entropy <addr> <len>\n"; return true; }
        double h = shannon_entropy(reader, arg_u64(1, 0), arg_u64(2, 0));
        out_ << "entropy = " << h << " bits/byte "
             << (h > 7.0 ? "(high — encrypted/compressed)" : h < 1.0 ? "(very low)" : "(normal)") << "\n";
        return true;
    }
    if (cmd == "opcodes") {
        Addr a = tok.size() >= 2 ? arg_u64(1, s_.rip()) : s_.rip();
        auto h = opcode_histogram(s_.arch(), reader, a, arg_u64(tok.size() >= 3 ? 2 : 99, 200));
        u64 total = 0, nops = 0;
        for (auto& [m, c] : h) { total += c; if (m == "nop") nops = c; }
        for (std::size_t i = 0; i < h.size() && i < 15; ++i)
            out_ << "  " << std::setw(8) << std::left << h[i].first << " " << h[i].second << "\n";
        if (total && nops * 10 > total) out_ << "  ! high NOP ratio (" << nops << "/" << total << ") — padding/obfuscation?\n";
        return true;
    }
    if (cmd == "strings") {
        if (tok.size() < 3) { out_ << "usage: strings <addr> <len> [minlen]\n"; return true; }
        auto ss = extract_strings(reader, arg_u64(1, 0), arg_u64(2, 0), arg_u64(3, 4));
        std::string filt = tok.size() >= 5 ? tok[4] : "";
        for (const auto& s : ss)
            if (filt.empty() || s.text.find(filt) != std::string::npos)
                out_ << "  " << hex(s.addr) << "  \"" << s.text << "\"\n";
        return true;
    }
    if (cmd == "scan") {
        Addr a = tok.size() >= 2 ? arg_u64(1, s_.rip()) : s_.rip();
        auto f = detect(s_.arch(), reader, a, arg_u64(tok.size() >= 3 ? 2 : 99, 400));
        out_ << f.size() << " finding(s) from " << hex(a) << ":\n";
        for (const auto& x : f)
            out_ << "  [" << x.category << "/" << x.severity << "] " << hex(x.addr) << "  " << x.rule
                 << "  (" << x.detail << ")\n";
        Cfg g = s_.build_cfg(a);
        out_ << "cyclomatic complexity of function @ " << hex(a) << " = " << cyclomatic_complexity(g) << "\n";
        return true;
    }
    if (cmd == "callgraph" || cmd == "cg") {
        Addr a = tok.size() >= 2 ? arg_u64(1, s_.rip()) : s_.rip();
        auto g = build_call_graph(s_.arch(), reader, a);
        out_ << g.funcs.size() << " function(s), " << g.calls.size() << " call edge(s):\n";
        for (const auto& n : g.funcs) out_ << "  sub_" << std::hex << n.entry << std::dec
                                           << annotate(n.entry) << " (" << n.blocks << " blocks)\n";
        for (const auto& c : g.calls) out_ << "  " << hex(c.first) << " -> " << hex(c.second) << "\n";
        return true;
    }

    if (cmd == "info") {
        out_ << "format: " << s_.image_format() << "   entry/rip: " << hex(s_.rip())
             << "   arch: x86-64\n";
        out_ << "sections: " << s_.sections().size() << "   imports: " << s_.imports().size()
             << "   symbols: " << s_.symbols().size() << "\n";
        auto t = s_.timeline_stats();
        out_ << "tick " << t.now << "/" << t.max << "   phase: " << s_.phase_name()
             << "   transparency: " << (s_.transparency_enabled() ? "on" : "off") << "\n";
        return true;
    }
    if (cmd == "sections" || cmd == "sec") {
        for (const auto& s : s_.sections())
            out_ << "  " << hex(s.addr) << "  " << std::setw(10) << std::left << s.name
                 << " size=" << hex(s.size) << "  "
                 << ((s.perms & perm::R) ? 'r' : '-') << ((s.perms & perm::W) ? 'w' : '-')
                 << ((s.perms & perm::X) ? 'x' : '-') << "\n";
        out_ << s_.sections().size() << " section(s)\n";
        return true;
    }
    if (cmd == "imports" || cmd == "imp") {
        std::string filt = tok.size() >= 2 ? tok[1] : "";
        std::size_t shown = 0;
        for (const auto& im : s_.imports())
            if (filt.empty() || im.find(filt) != std::string::npos) { out_ << "  " << im << "\n"; ++shown; }
        out_ << shown << " / " << s_.imports().size() << " import(s)\n";
        return true;
    }

    if (cmd == "capture" || cmd == "cap") {
        std::string sub = tok.size() >= 2 ? tok[1] : "list";
        if (sub == "on") { s_.capture_enable(true); out_ << "capture ON\n"; }
        else if (sub == "off") { s_.capture_enable(false); out_ << "capture OFF\n"; }
        else if (sub == "clear") { s_.capture_clear(); out_ << "capture cleared\n"; }
        else if (sub == "list") {
            for (const auto& e : s_.capture_log())
                out_ << "  #" << e.seq << " [t=" << e.tick << "] " << hex(e.pc) << "  " << e.summary << "\n";
            out_ << s_.capture_log().size() << " transaction(s)\n";
        } else {
            out_ << "usage: capture on|off|clear|list\n";
        }
        return true;
    }

    if (cmd == "arch") {
        if (tok.size() >= 2 && tok[1] == "dot") { out_ << architecture_dot(); return true; }
        for (const auto& s : architecture()) {
            out_ << "  " << s.name << "  [";
            for (std::size_t i = 0; i < s.patterns.size(); ++i)
                out_ << (i ? ", " : "") << s.patterns[i];
            out_ << "]\n";
        }
        out_ << "(use 'arch dot' for a graphviz diagram)\n";
        return true;
    }

    if (cmd == "alias") {
        if (tok.size() >= 3) {
            std::string def = tok[2];
            for (std::size_t i = 3; i < tok.size(); ++i) def += " " + tok[i];
            aliases_[tok[1]] = def;
            out_ << "alias " << tok[1] << " = " << def << "\n";
        } else {
            for (const auto& [k, v] : aliases_) out_ << "  " << k << " = " << v << "\n";
        }
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
