// SPDX-License-Identifier: Apache-2.0
//
// The command-line front end. The shell's own command language is a small
// Interpreter over tokens that drives the AnalysisSession Facade. Unknown
// commands prefixed with `lua` are forwarded to the embedded script engine.
#pragma once

#include <iosfwd>
#include <map>
#include <string>
#include <vector>

#include "dede/common/types.hpp"

#include "dede/macro/event_bus.hpp"
#include "dede/script/script_engine.hpp"
#include "dede/session/engine.hpp"

namespace dede {

class Shell {
public:
    Shell(IAnalysisEngine& engine, IScriptEngine& script, std::ostream& out);

    // Execute one command line. Returns false when the user asked to quit.
    bool execute(const std::string& line);

    // Read-eval-print loop over `in`, prompting to `out`.
    void repl(std::istream& in);

private:
    // A live trace Observer the `trace on` command attaches to the event bus.
    class TraceObserver final : public IEventObserver {
    public:
        TraceObserver(std::ostream& out, bool& on) : out_(out), on_(on) {}
        void on_event(const Event& e) override;

    private:
        std::ostream& out_;
        bool& on_;
    };

    // Counts executed instructions per address, for the `profile` command.
    class ExecCounter final : public IEventObserver {
    public:
        void on_event(const Event& e) override;
        std::map<Addr, u64> counts;
        u64 total = 0;
    };

    std::string annotate(Addr a) const;  // " <sym>" for disasm/stack views

    IAnalysisEngine& s_;
    IScriptEngine& script_;
    std::ostream& out_;
    bool trace_on_ = false;
    TraceObserver trace_;
    ExecCounter profiler_;
    std::vector<std::string> cmd_history_;
    std::map<std::string, std::string> aliases_;
};

}  // namespace dede
