// SPDX-License-Identifier: Apache-2.0
//
// The `dede` executable: wire a session, load an optional target (ELF/PE auto-
// detected, else a flat code blob), and drop into the interactive shell.
#include <iostream>
#include <string>

#include "dede/loader/loader.hpp"
#include "dede/script/script_engine.hpp"
#include "dede/session/analysis_session.hpp"
#include "dede/shell/shell.hpp"

using namespace dede;

namespace {
constexpr Addr kCodeBase = 0x1000;
constexpr Addr kStackBase = 0x70000;
}  // namespace

int main(int argc, char** argv) {
    AnalysisSession session(Arch::X86_64);
    auto script = make_script_engine(session);

    if (argc >= 2) {
        auto img = load_image_file(argv[1], kCodeBase);
        if (!img) {
            std::cerr << "could not load " << argv[1] << ": " << img.message() << "\n";
            return 1;
        }
        if (img.value().format == "flat") {
            // Flat blob: give it a generous RWX region + a stack.
            session.map(kCodeBase, 0x10000, perm::RWX);
            session.map(kStackBase, 0x10000, perm::RW);
            session.core().cpu().set(Reg::Rsp, kStackBase + 0x8000);
        }
        session.load_image(img.value());
        std::cout << "loaded " << argv[1] << " [" << img.value().format << "] entry=0x" << std::hex
                  << img.value().entry << std::dec << ", " << img.value().segments.size()
                  << " segment(s), " << img.value().symbols.size() << " symbol(s), "
                  << img.value().imports.size() << " import(s)\n";
    } else {
        // No file: a scratch RWX region + stack for pasted code / assembling.
        session.map(kCodeBase, 0x10000, perm::RWX);
        session.map(kStackBase, 0x10000, perm::RW);
        session.core().cpu().set(Reg::Rsp, kStackBase + 0x8000);
        session.set_entry(kCodeBase);
    }

    Shell shell(session, *script, std::cout);
    shell.repl(std::cin);
    return 0;
}
