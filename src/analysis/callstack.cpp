// SPDX-License-Identifier: Apache-2.0
#include "dede/analysis/callstack.hpp"

namespace dede {

namespace {
// Read a little-endian u64; nullopt if any byte is unmapped.
std::optional<u64> read_u64(const ByteReader& read, Addr a) {
    u64 v = 0;
    for (unsigned i = 0; i < 8; ++i) {
        auto b = read(a + i);
        if (!b) return std::nullopt;
        v |= static_cast<u64>(*b) << (8 * i);
    }
    return v;
}
}  // namespace

bool is_call_preceded(const IDisassembler& dis, const ByteReader& read, Addr addr) {
    // A return address is legitimate when a `call` ends exactly at it. Calls are
    // `E8 rel32` (5 bytes) or `FF /2` (2-7 bytes), so probe those lengths and
    // accept the first decode that is a call whose end == addr.
    for (unsigned len = 2; len <= 7; ++len) {
        if (len > addr) break;
        Addr start = addr - len;
        std::vector<u8> buf;
        for (unsigned i = 0; i < len; ++i) {
            auto b = read(start + i);
            if (!b) { buf.clear(); break; }
            buf.push_back(*b);
        }
        if (buf.size() != len) continue;
        auto r = dis.decode_one(buf.data(), buf.size(), start);
        if (r && r.value().cf.is_call && r.value().addr + r.value().size == addr) return true;
    }
    return false;
}

std::vector<StackFrame> unwind_stack(const IDisassembler& dis, const ByteReader& read,
                                     Addr /*rip*/, u64 rbp, std::size_t max_frames) {
    std::vector<StackFrame> frames;
    u64 fp = rbp;
    for (std::size_t i = 0; i < max_frames; ++i) {
        if (fp == 0) break;
        auto saved = read_u64(read, fp);       // [rbp]   -> caller's rbp
        auto ret = read_u64(read, fp + 8);     // [rbp+8] -> return address
        if (!saved || !ret) break;
        StackFrame f;
        f.frame_ptr = fp;
        f.return_addr = *ret;
        f.is_base = (*saved == 0);  // chain terminates here (process entry)
        f.ret_call_preceded = is_call_preceded(dis, read, *ret);
        frames.push_back(f);
        if (*saved <= fp) break;  // frame pointers grow upward; stop at base/loop/garbage
        fp = *saved;
    }
    return frames;
}

IntegrityReport check_stack_integrity(const IDisassembler& dis, const ByteReader& read,
                                      Addr rip, u64 rbp, std::size_t max_frames) {
    IntegrityReport rep;
    rep.frames = unwind_stack(dis, read, rip, rbp, max_frames);
    for (const auto& f : rep.frames)
        if (!f.is_base && !f.ret_call_preceded) rep.violations.push_back(f.return_addr);
    return rep;
}

std::vector<StackFrame> unwind_stack(Arch arch, const ByteReader& read, Addr rip, u64 rbp,
                                     std::size_t max_frames) {
    auto dis = make_disassembler(arch);
    return unwind_stack(*dis, read, rip, rbp, max_frames);
}

IntegrityReport check_stack_integrity(Arch arch, const ByteReader& read, Addr rip, u64 rbp,
                                      std::size_t max_frames) {
    auto dis = make_disassembler(arch);
    return check_stack_integrity(*dis, read, rip, rbp, max_frames);
}

}  // namespace dede
