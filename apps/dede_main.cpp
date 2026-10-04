// SPDX-License-Identifier: Apache-2.0
//
// The `dede` executable: wire a session, load an optional flat code blob, and
// drop into the interactive shell.
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "dede/script/script_engine.hpp"
#include "dede/session/analysis_session.hpp"
#include "dede/shell/shell.hpp"

using namespace dede;

namespace {
constexpr Addr kCodeBase = 0x1000;
constexpr Addr kStackBase = 0x70000;

std::vector<u8> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
}  // namespace

int main(int argc, char** argv) {
    AnalysisSession session(Arch::X86_64);
    auto script = make_script_engine(session);

    // A generous RWX code region and a stack, so loaded blobs can run and call.
    session.map(kCodeBase, 0x10000, perm::RWX);
    session.map(kStackBase, 0x10000, perm::RW);
    session.core().cpu().set(Reg::Rsp, kStackBase + 0x8000);

    if (argc >= 2) {
        auto bytes = read_file(argv[1]);
        if (bytes.empty()) {
            std::cerr << "could not read " << argv[1] << "\n";
            return 1;
        }
        session.core().memory().write(kCodeBase, bytes);
        std::cout << "loaded " << bytes.size() << " bytes at " << std::hex << kCodeBase
                  << std::dec << "\n";
    }
    session.set_entry(kCodeBase);

    Shell shell(session, *script, std::cout);
    shell.repl(std::cin);
    return 0;
}
