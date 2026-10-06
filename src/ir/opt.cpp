// SPDX-License-Identifier: Apache-2.0
#include "dede/ir/opt.hpp"

#include <array>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>

namespace dede::ir {
namespace {

bool is_pure_value_op(Op op) {
    switch (op) {
        case Op::Add: case Op::Sub: case Op::Mul: case Op::And: case Op::Or:
        case Op::Xor: case Op::Shl: case Op::Shr: case Op::Sar: case Op::Neg:
        case Op::Not: case Op::Zext: case Op::Sext: case Op::Subpiece:
        case Op::Equal: case Op::NotEqual: case Op::Less: case Op::SLess:
        case Op::LessEqual: case Op::SLessEqual: case Op::Carry: case Op::SCarry:
        case Op::SBorrow: case Op::SignBit: case Op::Parity: case Op::AuxAdd:
        case Op::AuxSub: case Op::IsZero:
            return true;
        default:
            return false;
    }
}

bool foldable(Op op) {
    switch (op) {
        case Op::Add: case Op::Sub: case Op::Mul: case Op::And: case Op::Or:
        case Op::Xor: case Op::Shl: case Op::Shr: case Op::Sar:
            return true;
        default:
            return false;
    }
}

long long fold(Op op, long long a, long long b) {
    switch (op) {
        case Op::Add: return a + b;
        case Op::Sub: return a - b;
        case Op::Mul: return a * b;
        case Op::And: return a & b;
        case Op::Or:  return a | b;
        case Op::Xor: return a ^ b;
        case Op::Shl: return a << (b & 63);
        case Op::Shr: return (long long)((unsigned long long)a >> (b & 63));
        case Op::Sar: return a >> (b & 63);
        default: return 0;
    }
}

u64 vkey(const Vn& v) {
    switch (v.kind) {
        case VnKind::Const: return (u64(1) << 60) ^ u64(v.cval);
        case VnKind::Reg:   return (u64(2) << 60) ^ u64(v.reg);
        case VnKind::Temp:  return (u64(3) << 60) ^ u64((unsigned)v.temp);
        case VnKind::Flag:  return (u64(4) << 60) ^ u64(v.flag);
        case VnKind::None:  return 0;
    }
    return 0;
}

bool same(const Vn& a, const Vn& b) { return a.kind == b.kind && vkey(a) == vkey(b); }

bool has_unmodeled(const std::vector<Insn>& code) {
    for (const auto& in : code)
        if (in.op == Op::Call || in.op == Op::BranchInd || in.op == Op::Intrinsic) return true;
    return false;
}

}  // namespace

std::vector<Insn> simplify_block(const std::vector<Insn>& code, bool cse, OptStats* stats) {
    if (stats) *stats = {};
    if (stats) stats->before = static_cast<unsigned>(code.size());
    if (has_unmodeled(code)) {  // conservative: leave calls/indirect/opaque blocks alone
        if (stats) stats->after = static_cast<unsigned>(code.size());
        return code;
    }

    auto reg_idx = [](Reg r) { return static_cast<std::size_t>(r); };

    // Registers written anywhere in the block are NOT block-invariant: a value
    // that references one of them cannot be forwarded to a later use, because the
    // consumer (the decompiler's expression emitter) prints a register leaf by
    // its *current* name, and that name may since have been overwritten. Only
    // constants, invariant registers, and temps built from them are forwardable.
    std::array<bool, 32> reg_written{};
    for (const auto& in : code)
        if (in.out.kind == VnKind::Reg) reg_written[reg_idx(in.out.reg)] = true;

    std::map<Reg, Vn> reg_val;                 // reg -> value it currently holds (for forwarding)
    std::map<int, Vn> temp_val;                // temp id -> canonical replacement
    std::map<int, bool> temp_safe;             // is that replacement forwardable (invariant)?
    std::unordered_map<unsigned long long, int> cse_map;

    std::function<bool(const Vn&)> safe = [&](const Vn& v) -> bool {
        if (v.kind == VnKind::Const) return true;
        if (v.kind == VnKind::Reg) return !reg_written[reg_idx(v.reg)];
        if (v.kind == VnKind::Temp) { auto it = temp_safe.find(v.temp); return it != temp_safe.end() && it->second; }
        return false;  // Flag / None: not forwarded
    };

    // Full resolution (follows copies/consts) — used for folding and CSE keys.
    // Iterative with a visited guard so a degenerate cycle (e.g. a value that
    // maps back to its own storage) terminates instead of recursing forever.
    auto resolve = [&](Vn v) -> Vn {
        std::set<int> seen_temp;
        std::set<Reg> seen_reg;
        unsigned char sz = v.size;
        for (;;) {
            if (v.kind == VnKind::Temp) {
                if (!seen_temp.insert(v.temp).second) break;
                auto it = temp_val.find(v.temp);
                if (it == temp_val.end()) break;
                v = it->second;
            } else if (v.kind == VnKind::Reg) {
                if (!seen_reg.insert(v.reg).second) break;
                auto it = reg_val.find(v.reg);
                if (it == reg_val.end()) break;
                v = it->second;
            } else {
                break;
            }
        }
        v.size = sz;
        return v;
    };

    // The Vn to actually emit for a use: its resolved form only if that form is
    // forwardable, otherwise the original (which the emitter handles soundly).
    auto emit_use = [&](const Vn& v) -> Vn {
        Vn full = resolve(v);
        if (safe(full)) { if (stats && !same(full, v)) ++stats->propagated; return full; }
        return v;
    };

    std::vector<Insn> mid;
    mid.reserve(code.size());

    for (const auto& in0 : code) {
        if (in0.op == Op::Copy) {
            if (in0.out.kind == VnKind::Temp) {
                Vn r = resolve(in0.a);
                if (safe(r)) { temp_val[in0.out.temp] = r; temp_safe[in0.out.temp] = true; continue; }
                // unsafe alias: materialize so the name stays valid
                Insn in = in0; in.a = emit_use(in0.a);
                temp_val[in0.out.temp] = Vn::t(in0.out.temp, in0.out.size);
                temp_safe[in0.out.temp] = false;
                mid.push_back(in);
                continue;
            }
            if (in0.out.kind == VnKind::Reg) {
                Insn in = in0; in.a = emit_use(in0.a);
                reg_val[in0.out.reg] = resolve(in0.a);  // for forwarding (guarded by safe())
                mid.push_back(in);
                continue;
            }
            if (in0.out.kind == VnKind::Flag) { Insn in = in0; in.a = emit_use(in0.a); mid.push_back(in); continue; }
        }

        if (is_pure_value_op(in0.op) && in0.out.kind == VnKind::Temp) {
            Vn ra = resolve(in0.a), rb = resolve(in0.b);
            // constant folding
            if (foldable(in0.op) && ra.kind == VnKind::Const && rb.kind == VnKind::Const) {
                temp_val[in0.out.temp] = Vn::k(fold(in0.op, ra.cval, rb.cval), in0.out.size);
                temp_safe[in0.out.temp] = true;
                if (stats) ++stats->folded;
                continue;
            }
            // algebraic identities: alias the temp to a simpler value when that
            // value is forwardable; x^x is always the constant 0.
            bool ident = false;
            if (in0.op == Op::Xor && same(ra, rb)) {
                temp_val[in0.out.temp] = Vn::k(0, in0.out.size); temp_safe[in0.out.temp] = true;
                continue;
            }
            if (((in0.op == Op::Add || in0.op == Op::Sub || in0.op == Op::Or) && rb.kind == VnKind::Const && rb.cval == 0) ||
                (in0.op == Op::Mul && rb.kind == VnKind::Const && rb.cval == 1))
                ident = safe(ra);
            if (ident) { temp_val[in0.out.temp] = ra; temp_safe[in0.out.temp] = true; continue; }
            // CSE (optional)
            if (cse) {
                unsigned long long key = (static_cast<unsigned long long>(in0.op) << 1) ^
                                         (vkey(ra) * 1000003ull) ^ (vkey(rb) * 19ull) ^
                                         (static_cast<unsigned long long>(in0.out.size) << 3);
                auto it = cse_map.find(key);
                if (it != cse_map.end() && temp_safe.count(it->second) && temp_safe[it->second]) {
                    temp_val[in0.out.temp] = Vn::t(it->second, in0.out.size);
                    temp_safe[in0.out.temp] = true;
                    if (stats) ++stats->cse;
                    continue;
                }
                cse_map[key] = in0.out.temp;
            }
            Insn in = in0; in.a = emit_use(in0.a); in.b = emit_use(in0.b);
            temp_val[in0.out.temp] = Vn::t(in0.out.temp, in0.out.size);
            temp_safe[in0.out.temp] = safe(ra) && safe(rb);
            mid.push_back(in);
            continue;
        }

        // Load / Store / flag producers / branches: keep, with resolved-safe inputs.
        Insn in = in0;
        in.a = emit_use(in0.a);
        in.b = emit_use(in0.b);
        if (in0.op == Op::Load && in0.out.kind == VnKind::Temp) {
            temp_val[in0.out.temp] = Vn::t(in0.out.temp, in0.out.size);
            temp_safe[in0.out.temp] = false;  // memory value: not forwardable
        }
        mid.push_back(in);
    }

    // --- backward dead-code elimination ---------------------------------------
    auto side_effect = [](Op op) {
        return op == Op::Store || op == Op::Call || op == Op::Branch || op == Op::CBranch ||
               op == Op::BranchInd || op == Op::Return || op == Op::Intrinsic || op == Op::Load;
    };
    std::array<bool, 32> reg_live; reg_live.fill(true);   // conservative: regs live out
    std::array<bool, 8> flag_live; flag_live.fill(true);  // and flags live out
    std::map<int, bool> temp_live;

    std::vector<bool> keep(mid.size(), false);
    for (std::size_t i = mid.size(); i-- > 0;) {
        const Insn& in = mid[i];
        bool live_def = false;
        if (in.out.kind == VnKind::Reg) live_def = reg_live[reg_idx(in.out.reg)];
        else if (in.out.kind == VnKind::Flag) live_def = flag_live[static_cast<std::size_t>(in.out.flag)];
        else if (in.out.kind == VnKind::Temp) live_def = temp_live[in.out.temp];

        bool kept = side_effect(in.op) || live_def;
        keep[i] = kept;
        if (!kept) { if (stats) ++stats->dce; continue; }

        if (in.out.kind == VnKind::Reg) reg_live[reg_idx(in.out.reg)] = false;
        else if (in.out.kind == VnKind::Flag) flag_live[static_cast<std::size_t>(in.out.flag)] = false;
        else if (in.out.kind == VnKind::Temp) temp_live[in.out.temp] = false;

        auto use = [&](const Vn& v) {
            if (v.kind == VnKind::Reg) reg_live[reg_idx(v.reg)] = true;
            else if (v.kind == VnKind::Flag) flag_live[static_cast<std::size_t>(v.flag)] = true;
            else if (v.kind == VnKind::Temp) temp_live[v.temp] = true;
        };
        use(in.a);
        use(in.b);
    }

    std::vector<Insn> out;
    out.reserve(mid.size());
    for (std::size_t i = 0; i < mid.size(); ++i)
        if (keep[i]) out.push_back(mid[i]);
    if (stats) stats->after = static_cast<unsigned>(out.size());
    return out;
}

}  // namespace dede::ir
