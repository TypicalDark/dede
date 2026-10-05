// SPDX-License-Identifier: Apache-2.0
#include "dede/ir/eval.hpp"

#include <map>

namespace dede::ir {

namespace {
u64 mask_of(unsigned char sz) { return sz >= 8 ? ~0ull : ((1ull << (sz * 8)) - 1); }

u64 sext_to64(u64 v, unsigned char sz) {
    if (sz >= 8) return v;
    unsigned bits = sz * 8;
    u64 m = 1ull << (bits - 1);
    v &= mask_of(sz);
    return (v ^ m) - m;  // sign-extend
}
bool parity8(u64 v) {
    v &= 0xff; v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
    return (v & 1) == 0;
}
}  // namespace

std::optional<Addr> eval(const std::vector<Insn>& code, EvalEnv& env) {
    std::map<int, u64> temps;

    auto read = [&](const Vn& v) -> u64 {
        switch (v.kind) {
            case VnKind::Const: return (u64)v.cval & mask_of(v.size);
            case VnKind::Reg: return env.get_reg(v.reg) & mask_of(v.size);
            case VnKind::Temp: return temps[v.temp] & mask_of(v.size);
            case VnKind::Flag: return env.get_flag(v.flag) ? 1u : 0u;
            default: return 0;
        }
    };
    auto write = [&](const Vn& o, u64 val) {
        switch (o.kind) {
            case VnKind::Temp: temps[o.temp] = val & mask_of(o.size); break;
            case VnKind::Flag: env.set_flag(o.flag, (val & 1) != 0); break;
            case VnKind::Reg: {
                u64 cur = env.get_reg(o.reg);
                if (o.size >= 8) cur = val;
                else if (o.size == 4) cur = val & 0xffffffffull;  // x86-64 zero-extends 32-bit writes
                else cur = (cur & ~mask_of(o.size)) | (val & mask_of(o.size));
                env.set_reg(o.reg, cur);
                break;
            }
            default: break;
        }
    };

    std::optional<Addr> target;
    for (const auto& in : code) {
        unsigned char sz = in.out.is_none() ? in.a.size : in.out.size;
        u64 m = mask_of(sz);
        switch (in.op) {
            case Op::Copy: write(in.out, read(in.a)); break;
            case Op::Load: write(in.out, env.load((Addr)read(in.a), in.out.size)); break;
            case Op::Store: env.store((Addr)read(in.a), in.b.size, read(in.b)); break;
            case Op::Subpiece: write(in.out, (read(in.a) >> (read(in.b) * 8)) & m); break;
            case Op::Zext: write(in.out, read(in.a)); break;  // read masks to a.size already
            case Op::Sext: write(in.out, sext_to64(read(in.a), in.a.size) & m); break;
            case Op::Add: write(in.out, (read(in.a) + read(in.b)) & m); break;
            case Op::Sub: write(in.out, (read(in.a) - read(in.b)) & m); break;
            case Op::Mul: write(in.out, (read(in.a) * read(in.b)) & m); break;
            case Op::And: write(in.out, (read(in.a) & read(in.b)) & m); break;
            case Op::Or: write(in.out, (read(in.a) | read(in.b)) & m); break;
            case Op::Xor: write(in.out, (read(in.a) ^ read(in.b)) & m); break;
            case Op::Not: write(in.out, (~read(in.a)) & m); break;
            case Op::Neg: write(in.out, (0 - read(in.a)) & m); break;
            case Op::Shl: { unsigned c = read(in.b) & (sz == 8 ? 63 : 31); write(in.out, (read(in.a) << c) & m); break; }
            case Op::Shr: { unsigned c = read(in.b) & (sz == 8 ? 63 : 31); write(in.out, (read(in.a) & m) >> c); break; }
            case Op::Sar: { unsigned c = read(in.b) & (sz == 8 ? 63 : 31); write(in.out, ((u64)(sext_to64(read(in.a), in.a.size) >> c)) & m); break; }
            case Op::Equal: write(in.out, read(in.a) == read(in.b)); break;
            case Op::NotEqual: write(in.out, read(in.a) != read(in.b)); break;
            case Op::Less: write(in.out, read(in.a) < read(in.b)); break;
            case Op::SLess: write(in.out, sext_to64(read(in.a), in.a.size) < sext_to64(read(in.b), in.b.size) ? 1 : 0); break;
            case Op::LessEqual: write(in.out, read(in.a) <= read(in.b)); break;
            case Op::SLessEqual: write(in.out, (i64)sext_to64(read(in.a), in.a.size) <= (i64)sext_to64(read(in.b), in.b.size)); break;
            case Op::Carry: {
                unsigned char s = in.a.size; unsigned bits = s * 8;
                unsigned __int128 full = (unsigned __int128)(read(in.a) & mask_of(s)) + (read(in.b) & mask_of(s));
                write(in.out, (u64)((full >> bits) & 1)); break;
            }
            case Op::SCarry: {
                unsigned char s = in.a.size; unsigned bits = s * 8;
                u64 a = read(in.a), b = read(in.b), r = (a + b) & mask_of(s);
                bool sa = (a >> (bits - 1)) & 1, sb = (b >> (bits - 1)) & 1, sr = (r >> (bits - 1)) & 1;
                write(in.out, (sa == sb) && (sr != sa)); break;
            }
            case Op::SBorrow: {
                unsigned char s = in.a.size; unsigned bits = s * 8;
                u64 a = read(in.a), b = read(in.b), r = (a - b) & mask_of(s);
                bool sa = (a >> (bits - 1)) & 1, sb = (b >> (bits - 1)) & 1, sr = (r >> (bits - 1)) & 1;
                write(in.out, (sa != sb) && (sr != sa)); break;
            }
            case Op::SignBit: { unsigned bits = in.a.size * 8; write(in.out, (read(in.a) >> (bits - 1)) & 1); break; }
            case Op::Parity: write(in.out, parity8(read(in.a))); break;
            case Op::AuxAdd: { u64 a = read(in.a), b = read(in.b); write(in.out, ((((a & 0xf) + (b & 0xf)) >> 4) & 1)); break; }
            case Op::AuxSub: { u64 a = read(in.a), b = read(in.b); write(in.out, (a & 0xf) < (b & 0xf)); break; }
            case Op::IsZero: write(in.out, (read(in.a) & mask_of(in.a.size)) == 0); break;
            case Op::Branch: case Op::BranchInd: case Op::Call: target = (Addr)read(in.a); break;
            case Op::CBranch: if (read(in.a)) target = (Addr)read(in.b); break;
            case Op::Return: case Op::Intrinsic: break;
        }
    }
    return target;
}

}  // namespace dede::ir
