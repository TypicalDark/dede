// SPDX-License-Identifier: Apache-2.0
#include "dede/samples/tiers.hpp"

namespace dede::samples {
namespace {

constexpr u8 kKey = 0x5A;

// A 36-byte self-decrypting stub at 0x1000 that xors `len` bytes at 0x2000 by the
// key in place, then jumps to 0x2000. Only the rcx immediate varies by `len`.
std::vector<u8> decrypt_stub(u8 len) {
    return {0x48, 0xBE, 0x00, 0x20, 0, 0, 0, 0, 0, 0,  // movabs rsi, 0x2000
            0x48, 0xC7, 0xC1, len, 0, 0, 0,            // mov rcx, len
            0x8A, 0x06, 0x34, kKey, 0x88, 0x06,        // mov al,[rsi]; xor al,key; mov [rsi],al
            0x48, 0xFF, 0xC6, 0x48, 0xFF, 0xC9, 0x75, 0xF2,  // inc rsi; dec rcx; jnz loop
            0xE9, 0xDC, 0x0F, 0x00, 0x00};             // jmp 0x2000
}

std::vector<u8> xor_enc(std::vector<u8> v) {
    for (auto& b : v) b ^= kKey;
    return v;
}

// Build a two-stage image: stub padded to 0x1000, then the encrypted stage2.
std::vector<u8> two_stage(const std::vector<u8>& stub, const std::vector<u8>& stage2_plain) {
    std::vector<u8> img(0x1000, 0x00);
    for (std::size_t i = 0; i < stub.size(); ++i) img[i] = stub[i];
    auto enc = xor_enc(stage2_plain);
    img.insert(img.end(), enc.begin(), enc.end());
    return img;
}

}  // namespace

Tier make_tier(int n) {
    Tier t;
    t.n = n;
    t.entry = 0x1000;
    switch (n) {
        case 1:
            t.name = "arithmetic loop";
            t.teaches = "load, regs, dis, step, run, bp, where, cfg";
            // mov rax,0 ; mov rcx,5 ; loop: add rax,rcx ; dec rcx ; jnz loop ; hlt
            t.image = {0x48, 0xC7, 0xC0, 0x00, 0, 0, 0, 0x48, 0xC7, 0xC1, 0x05, 0, 0, 0,
                       0x48, 0x01, 0xC8, 0x48, 0xFF, 0xC9, 0x75, 0xF8, 0xF4};
            break;
        case 2:
            t.name = "call + stack";
            t.teaches = "step-over, stack, callgraph, cfg";
            // mov rax,0x15 ; call helper ; hlt ; (pad) ; helper: shl rax,1 ; ret
            t.image = {0x48, 0xC7, 0xC0, 0x15, 0, 0, 0,   // 0x1000 mov rax,0x15
                       0xE8, 0x04, 0x00, 0x00, 0x00,       // 0x1007 call 0x1010
                       0xF4,                               // 0x100c hlt
                       0x90, 0x90, 0x90,                   // 0x100d..0x100f pad
                       0x48, 0xD1, 0xE0, 0xC3};            // 0x1010 helper: shl rax,1 ; ret
            break;
        case 3: {
            t.name = "self-decrypting stage";
            t.teaches = "scan(crypto), W^X run point, decrypt reveal, re-disasm, time-travel";
            t.stage2 = 0x2000;
            // stage2: mov rax, 0xC0FFEE ; hlt
            std::vector<u8> s2 = {0x48, 0xC7, 0xC0, 0xEE, 0xFF, 0xC0, 0x00, 0xF4};
            t.image = two_stage(decrypt_stub(static_cast<u8>(s2.size())), s2);
            break;
        }
        case 4:
            t.name = "anti-analysis";
            t.teaches = "transparency on/off, scan(anti-vm,timing), conditional run points, branches";
            // rdtsc ; mov eax,1 ; cpuid ; bt ecx,31 ; jc detected ;
            //   mov rax,0x600D ; hlt ; detected: mov rax,0xDEAD ; hlt
            t.image = {0x0F, 0x31,                                     // 0x1000 rdtsc
                       0xB8, 0x01, 0x00, 0x00, 0x00,                   // 0x1002 mov eax,1
                       0x0F, 0xA2,                                     // 0x1007 cpuid
                       0x0F, 0xBA, 0xE1, 0x1F,                         // 0x1009 bt ecx,31
                       0x72, 0x08,                                     // 0x100d jc +8 -> 0x1017
                       0x48, 0xC7, 0xC0, 0x0D, 0x60, 0x00, 0x00,       // 0x100f mov rax,0x600D
                       0xF4,                                           // 0x1016 hlt
                       0x48, 0xC7, 0xC0, 0xAD, 0xDE, 0x00, 0x00,       // 0x1017 mov rax,0xDEAD
                       0xF4};                                          // 0x101e hlt
            break;
        case 5: {
            t.name = "multi-stage: decrypt + syscall + mutate";
            t.teaches = "everything: scan, W^X, decompile, capture(syscall), MITM, time-travel";
            t.stage2 = 0x2000;
            // stage2: mov rax,1 (write) ; mov rdi,0xC0FFEE ; syscall ; hlt
            std::vector<u8> s2 = {0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax,1 (write)
                                  0x48, 0xC7, 0xC7, 0xEE, 0xFF, 0xC0, 0x00,  // mov rdi,0xC0FFEE
                                  0x0F, 0x05,                                // syscall
                                  0xF4};                                     // hlt
            t.image = two_stage(decrypt_stub(static_cast<u8>(s2.size())), s2);
            break;
        }
        default:
            t.name = "invalid";
            break;
    }
    return t;
}

}  // namespace dede::samples
