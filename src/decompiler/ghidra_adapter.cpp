// SPDX-License-Identifier: Apache-2.0
//
// Adapter over Ghidra's native decompiler (the C++ decompiler + SLEIGH, as
// extracted by r2ghidra/rz-ghidra). Compiled only when DEDE_WITH_GHIDRA is set
// and the ghidra-native headers/libs are found by CMake. The rest of the project
// sees only IDecompiler, so this file is the single place the Ghidra API lives.
//
// The key piece is a LoadImage subclass that feeds bytes from our live trace
// (through the memory proxy) instead of from a file on disk, so the decompiler
// reads the *current, possibly self-modified* code image rather than the static
// binary. Code versioning for self-modifying code is handled above, in the
// decode cache's (addr, bytes-tag) key.
#ifdef DEDE_WITH_GHIDRA

#include "dede/decompiler/decompiler.hpp"

// #include <libdecomp.hh>   // from ghidra-native
// #include <loadimage.hh>

namespace dede {
namespace {

// class TraceLoadImage final : public ghidra::LoadImage {
//  public:
//   explicit TraceLoadImage(IDisassembler& d) : LoadImage("dede-trace"), disasm_(d) {}
//   void loadFill(uint1* ptr, int4 size, const Address& addr) override {
//       // copy `size` bytes at `addr` from the live guest image into ptr
//   }
//   std::string getArchType() const override { return "x86:LE:64:default"; }
//   void adjustVma(long) override {}
// };

class GhidraDecompiler final : public IDecompiler {
public:
    explicit GhidraDecompiler(IDisassembler& d) : disasm_(d) {
        // ghidra::startDecompilerLibrary(sleigh_spec_dir);
    }
    std::string name() const override { return "ghidra-native"; }
    Result<std::string> decompile(const std::vector<u8>& code, Addr addr) override {
        (void)code; (void)addr; (void)disasm_;
        return make_error("ghidra-native adapter not yet implemented in this build");
    }

private:
    IDisassembler& disasm_;
};

}  // namespace

std::unique_ptr<IDecompiler> make_decompiler(IDisassembler& disasm) {
    return std::make_unique<GhidraDecompiler>(disasm);
}

}  // namespace dede

#endif  // DEDE_WITH_GHIDRA
