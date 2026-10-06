// SPDX-License-Identifier: Apache-2.0
#include "dede/analysis/xrefs.hpp"

#include <algorithm>
#include <set>

namespace dede {

const char* to_string(XrefKind k) noexcept {
    switch (k) {
        case XrefKind::Call: return "call";
        case XrefKind::Jump: return "jump";
        case XrefKind::Read: return "read";
        case XrefKind::Write: return "write";
        case XrefKind::AddrOf: return "addr-of";
    }
    return "?";
}

namespace {

std::vector<u8> read_bytes(const ByteReader& read, Addr a, unsigned n) {
    std::vector<u8> buf;
    for (unsigned i = 0; i < n; ++i) {
        auto b = read(a + i);
        if (!b) break;
        buf.push_back(*b);
    }
    return buf;
}

// Resolve a memory operand to an absolute target if it is statically knowable:
// rip-relative (`[rip+disp]`) or absolute (`[disp]` with no base/index). Returns
// false for base/index register-relative operands (not statically resolvable).
bool mem_target(const DecodedInsn& in, const MemOperand& m, Addr& out) {
    if (m.has_base && m.base == Reg::Rip) {  // rip-relative: rel to the NEXT insn
        out = static_cast<Addr>(in.addr + in.size + static_cast<i64>(m.disp));
        return true;
    }
    if (!m.has_base && !m.has_index && m.disp != 0) {  // absolute [disp]
        out = static_cast<Addr>(m.disp);
        return true;
    }
    return false;
}

bool pure_read_mnemonic(const std::string& m) {  // touches memory but never writes it
    return m == "cmp" || m == "test" || m == "push" || m == "jmp" || m == "call" ||
           m == "bt" || m == "ucomiss" || m == "ucomisd";
}

}  // namespace

std::vector<Xref> build_xrefs(const IDisassembler& dis, const ByteReader& read, Addr lo, Addr hi) {
    std::vector<Xref> out;
    Addr pc = lo;
    while (pc < hi) {
        auto buf = read_bytes(read, pc, 15);
        if (buf.empty()) { ++pc; continue; }
        auto r = dis.decode_one(buf.data(), buf.size(), pc);
        if (!r) { ++pc; continue; }
        const DecodedInsn& in = r.value();
        const auto& ops = in.operands;

        // Code xrefs: direct (immediate) call / branch targets.
        if (!ops.empty() && ops[0].kind == OpKind::Imm && (in.cf.is_call || in.cf.is_branch))
            out.push_back({in.addr, static_cast<Addr>(ops[0].imm), in.cf.is_call ? XrefKind::Call : XrefKind::Jump});

        // Data xrefs: resolvable memory operands + address-taking lea.
        for (std::size_t i = 0; i < ops.size(); ++i) {
            if (ops[i].kind != OpKind::Mem) continue;
            Addr tgt;
            if (!mem_target(in, ops[i].mem, tgt)) continue;
            XrefKind kind;
            if (in.mnemonic == "lea") kind = XrefKind::AddrOf;
            else if (i == 0 && !pure_read_mnemonic(in.mnemonic)) kind = XrefKind::Write;
            else kind = XrefKind::Read;
            out.push_back({in.addr, tgt, kind});
        }
        pc = in.addr + (in.size ? in.size : 1);
    }
    return out;
}

std::vector<Xref> build_xrefs(Arch arch, const ByteReader& read, Addr lo, Addr hi) {
    auto dis = make_disassembler(arch);
    return build_xrefs(*dis, read, lo, hi);
}

std::vector<Xref> refs_to(const std::vector<Xref>& xrefs, Addr addr) {
    std::vector<Xref> out;
    for (const auto& x : xrefs)
        if (x.to == addr) out.push_back(x);
    return out;
}

std::vector<Addr> discover_functions(const IDisassembler& dis, const ByteReader& read, Addr lo, Addr hi,
                                     const std::vector<Addr>& seeds) {
    std::set<Addr> entries;
    for (Addr s : seeds)
        if (s >= lo && s < hi) entries.insert(s);

    // Call targets from the xref sweep (indirectly-referenced functions included).
    for (const auto& x : build_xrefs(dis, read, lo, hi))
        if (x.kind == XrefKind::Call && x.to >= lo && x.to < hi) entries.insert(x.to);

    // Prologue signatures, validated by a clean decode at the candidate position.
    auto decodes_to = [&](Addr a, const char* mnem) -> std::optional<DecodedInsn> {
        auto buf = read_bytes(read, a, 15);
        if (buf.empty()) return std::nullopt;
        auto r = dis.decode_one(buf.data(), buf.size(), a);
        if (!r || r.value().mnemonic != mnem) return std::nullopt;
        return r.value();
    };
    for (Addr a = lo; a + 4 <= hi; ++a) {
        // endbr64 (F3 0F 1E FA)
        if (read(a) == std::optional<u8>(0xF3) && read(a + 1) == std::optional<u8>(0x0F) &&
            read(a + 2) == std::optional<u8>(0x1E) && read(a + 3) == std::optional<u8>(0xFA)) {
            entries.insert(a);
            continue;
        }
        // push rbp ; mov rbp,rsp  (55 48 89 E5) — validate both decodes.
        if (read(a) == std::optional<u8>(0x55)) {
            auto push = decodes_to(a, "push");
            if (push) {
                Addr nxt = a + push->size;
                if (read(nxt) == std::optional<u8>(0x48) && read(nxt + 1) == std::optional<u8>(0x89) &&
                    read(nxt + 2) == std::optional<u8>(0xE5))
                    entries.insert(a);
            }
        }
    }
    return {entries.begin(), entries.end()};
}

std::vector<Addr> discover_functions(Arch arch, const ByteReader& read, Addr lo, Addr hi,
                                     const std::vector<Addr>& seeds) {
    auto dis = make_disassembler(arch);
    return discover_functions(*dis, read, lo, hi, seeds);
}

}  // namespace dede
