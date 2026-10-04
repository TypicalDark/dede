// SPDX-License-Identifier: Apache-2.0
//
// The scenario the whole design is built around, run end to end:
//   1. A self-decrypting stub xors an encrypted "stage 2" blob into real code.
//   2. A W^X run point fires the moment that freshly-written page is executed.
//   3. A bound MUTATING macro patches the revealed code; the edit is logged as an
//      injected event so it survives replay.
//   4. We decompile the now-visible stage 2.
//   5. We time-travel back over the whole thing and forward again — the patch is
//      reproduced from the injected-event log without re-running the macro.
// Nothing here writes an int3 or touches a debug register: the change is
// invisible to the sample.
#include <iostream>

#include "dede/session/analysis_session.hpp"

using namespace dede;

namespace {
constexpr Addr kStub = 0x1000;
constexpr Addr kStage2 = 0x2000;
constexpr u8 kKey = 0x5A;

// Decryptor stub (see apps/decrypt_demo for the hand-assembly notes):
//   movabs rsi, 0x2000 ; mov rcx, 8
//   loop: mov al,[rsi] ; xor al,0x5A ; mov [rsi],al ; inc rsi ; dec rcx ; jnz loop
//   jmp 0x2000
const std::vector<u8> kDecryptStub = {
    0x48, 0xBE, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rsi, 0x2000
    0x48, 0xC7, 0xC1, 0x08, 0x00, 0x00, 0x00,                    // mov rcx, 8
    0x8A, 0x06,                                                  // mov al, [rsi]
    0x34, 0x5A,                                                  // xor al, 0x5A
    0x88, 0x06,                                                  // mov [rsi], al
    0x48, 0xFF, 0xC6,                                            // inc rsi
    0x48, 0xFF, 0xC9,                                            // dec rcx
    0x75, 0xF2,                                                  // jnz loop
    0xE9, 0xDC, 0x0F, 0x00, 0x00                                 // jmp 0x2000
};

// Plaintext stage 2: mov rax, 0xC0FFEE ; hlt
const std::vector<u8> kStage2Plain = {0x48, 0xC7, 0xC0, 0xEE, 0xFF, 0xC0, 0x00, 0xF4};

std::vector<u8> xor_encrypt(std::vector<u8> v, u8 key) {
    for (auto& b : v) b ^= key;
    return v;
}

void dump_dis(AnalysisSession& s, Addr a, int n, const char* title) {
    std::cout << "    " << title << ":\n";
    for (const auto& in : s.disassemble(a, n))
        std::cout << "      " << std::hex << in.addr << std::dec << ":  " << in.text() << "\n";
}

}  // namespace

int main() {
    // Force a tiny ring and frequent snapshots so the final time-travel genuinely
    // replays from a sparse anchor and re-applies the injected patch, rather than
    // trivially restoring a fine-grained memento.
    SessionDeps deps;
    deps.timeline.ring_capacity = 4;
    deps.timeline.snapshot_interval = 8;
    AnalysisSession s(Arch::X86_64, std::move(deps));

    s.map(0x1000, 0x2000, perm::RWX);
    s.map(0x70000, 0x1000, perm::RW);
    s.core().cpu().set(Reg::Rsp, 0x70800);
    s.load(kStub, kDecryptStub, perm::RWX);
    s.load(kStage2, xor_encrypt(kStage2Plain, kKey), perm::RWX);
    s.set_entry(kStub);

    std::cout << "== dede decrypt-and-reveal demo ==\n\n";
    std::cout << "[1] Before execution, stage 2 is encrypted garbage:\n";
    dump_dis(s, kStage2, 3, "stage2 @ 0x2000 (encrypted)");

    // A run point at the address just after the decrypt routine, where the real
    // code now exists (this is the design's canonical scenario). It fires on
    // arrival — before the revealed instruction executes — so the macro's patch
    // takes effect. (A WrittenThenExec run point is also available for a W^X
    // trigger; watch the event trace to see it fire.)
    u64 wx = s.add_run_point([] {
        RunPoint rp;
        rp.type = RunPointType::Address;
        rp.address = kStage2;
        rp.label = "stage2 revealed";
        return rp;
    }());

    // A MUTATING macro bound to it: the analyst "fixes up" the revealed code,
    // rewriting the immediate so rax ends up 0xD00D instead of 0xC0FFEE.
    auto macro = std::make_shared<Macro>();
    macro->name = "fixup-revealed-code";
    macro->mutating = true;
    macro->callback = [](IDebugController& c) {
        c.write_bytes(kStage2, {0x48, 0xC7, 0xC0, 0x0D, 0xD0, 0x00, 0x00},
                      "patch revealed mov rax");
    };
    s.bind_macro(wx, macro);

    std::cout << "\n[2] Running the self-decrypting stub...\n";
    StepOutcome o = s.run();
    std::cout << "    halted: " << o.note << " at tick " << s.now() << "\n";
    std::cout << "    W^X run point hit " << s.run_points()[0].hit_count << " time(s)\n";

    std::cout << "\n[3] Stage 2 is now decrypted and the macro patched it:\n";
    dump_dis(s, kStage2, 3, "stage2 @ 0x2000 (revealed + patched)");
    auto dec = s.decompile(kStage2, 8);
    if (dec) std::cout << "    decompiled:\n" << dec.value();
    std::cout << "    rax = 0x" << std::hex << s.read_reg(Reg::Rax) << std::dec
              << "  (0xd00d means the mutating macro took effect)\n";

    Tick final_tick = s.now();
    u64 final_rax = s.read_reg(Reg::Rax);

    std::cout << "\n[4] Time-travel back to tick 0:\n";
    s.seek(0);
    dump_dis(s, kStage2, 1, "stage2 @ 0x2000 (back to encrypted)");
    std::cout << "    rax = 0x" << std::hex << s.read_reg(Reg::Rax) << std::dec << " at tick "
              << s.now() << "\n";

    std::cout << "\n[5] Replay forward to the end (from a sparse anchor, re-applying\n"
                 "    the injected patch — the macro is NOT re-run):\n";
    s.seek(final_tick);
    std::cout << "    rax = 0x" << std::hex << s.read_reg(Reg::Rax) << std::dec << " at tick "
              << s.now() << "\n";

    bool ok = (s.read_reg(Reg::Rax) == final_rax) && (final_rax == 0xD00D);
    std::cout << "\n== replay " << (ok ? "REPRODUCED the run exactly ✓" : "DIVERGED ✗") << " ==\n";
    return ok ? 0 : 1;
}
