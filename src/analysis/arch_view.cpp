// SPDX-License-Identifier: Apache-2.0
#include "dede/analysis/arch_view.hpp"

#include <sstream>

namespace dede {

const std::vector<SubsystemInfo>& architecture() {
    static const std::vector<SubsystemInfo> arch = {
        {"common", {}, {"Flyweight (COW pages)"}},
        {"disasm", {"common"}, {"Adapter (Capstone)", "Flyweight (decode cache)", "Strategy"}},
        {"core", {"disasm", "common"}, {"Strategy (backend)", "Proxy (memory)", "Memento", "Observer", "Null Object"}},
        {"replay", {"core"}, {"Memento (caretaker)", "Event Sourcing"}},
        {"transparency", {"core"}, {"Chain of Responsibility", "Null Object"}},
        {"macro", {"core"}, {"Command", "Composite", "Prototype", "Observer", "Interpreter"}},
        {"decompiler", {"disasm"}, {"Adapter (Ghidra)", "Visitor"}},
        {"analysis", {"disasm"}, {"Visitor (CFG passes)"}},
        {"introspection", {"common"}, {"Adapter (LibVMI)"}},
        {"session", {"core", "replay", "transparency", "macro", "decompiler", "analysis", "introspection"},
         {"Facade", "State", "Dependency Injection"}},
        {"script", {"session"}, {"Null Object", "Adapter (Luau)"}},
        {"shell", {"session", "script"}, {"Interpreter (command language)"}},
        {"gui", {"session", "script", "analysis"}, {"Bridge (engine/UI split)", "MVP"}},
    };
    return arch;
}

std::string architecture_dot() {
    std::ostringstream os;
    os << "digraph dede {\n  rankdir=BT;\n  node [shape=box fontname=\"monospace\"];\n";
    for (const auto& s : architecture()) {
        os << "  \"" << s.name << "\" [label=\"" << s.name;
        for (const auto& p : s.patterns) os << "\\n" << p;
        os << "\"];\n";
        for (const auto& dep : s.depends_on)
            os << "  \"" << s.name << "\" -> \"" << dep << "\";\n";
    }
    os << "}\n";
    return os.str();
}

}  // namespace dede
