// SPDX-License-Identifier: Apache-2.0
#include "dede/types/types.hpp"

#include <array>
#include <cstdio>
#include <set>

namespace dede::types {

LType meet(LType a, LType b) {
    LType r;
    // class: refine toward the more specific; pointer evidence beats integer.
    auto rank = [](TClass c) {
        switch (c) { case TClass::Pointer: return 4; case TClass::Code: return 3;
                     case TClass::Bool: return 2; case TClass::Integer: return 1; default: return 0; }
    };
    if (a.cls == TClass::Bottom || b.cls == TClass::Bottom) r.cls = TClass::Bottom;
    else if (a.cls == TClass::Top) r.cls = b.cls;
    else if (b.cls == TClass::Top) r.cls = a.cls;
    else r.cls = rank(a.cls) >= rank(b.cls) ? a.cls : b.cls;
    // width: the widest concrete observation.
    r.width = a.width > b.width ? a.width : b.width;
    // sign: agree, or fall back to unknown on conflict.
    if (a.sign == Sign::Unknown) r.sign = b.sign;
    else if (b.sign == Sign::Unknown) r.sign = a.sign;
    else r.sign = (a.sign == b.sign) ? a.sign : Sign::Unknown;
    return r;
}

std::string c_type(const LType& t) {
    if (t.cls == TClass::Pointer || t.cls == TClass::Code) return "void *";
    if (t.cls == TClass::Bool) return "bool";
    const char* w = t.width == 1 ? "8" : t.width == 2 ? "16" : t.width == 4 ? "32" : "64";
    return (t.sign == Sign::Unsigned ? std::string("uint") : std::string("int")) + w + "_t";
}

namespace {
bool is_arg_reg(Reg r) {
    return r == Reg::Rdi || r == Reg::Rsi || r == Reg::Rdx || r == Reg::Rcx || r == Reg::R8 || r == Reg::R9;
}
Sign jcc_sign(const std::string& m) {
    if (m == "jl" || m == "jg" || m == "jle" || m == "jge" || m == "jnge" || m == "jnle" || m == "jng" || m == "jnl")
        return Sign::Signed;
    if (m == "ja" || m == "jb" || m == "jae" || m == "jbe" || m == "jnae" || m == "jnbe" || m == "jna" || m == "jnb")
        return Sign::Unsigned;
    return Sign::Unknown;
}
}  // namespace

FuncTypes infer_function(const IDisassembler& dis, const ByteReader& read, Addr entry) {
    FuncTypes ft;
    ft.entry = entry;
    Cfg cfg = build_cfg(dis, read, entry);

    std::set<Reg> defined;
    std::set<Reg> live_set;
    std::vector<Reg> live_order;

    // Per-base dereference accesses, for struct/array (aggregate) recovery.
    struct Acc { bool array = false; unsigned stride = 0; std::map<i64, Field> offs; };
    std::map<Reg, Acc> derefs;
    auto record_read = [&](Reg r) {
        if (!defined.count(r) && !live_set.count(r)) { live_set.insert(r); live_order.push_back(r); }
    };
    auto refine = [&](Reg r, LType c) { ft.regs[r] = meet(ft.regs[r], c); };

    Reg cmp_a = Reg::Rax, cmp_b = Reg::Rax;
    bool cmp_a_reg = false, cmp_b_reg = false, have_cmp = false;

    for (const auto& bb : cfg.blocks) {
        for (const auto& in : bb.insns) {
            const auto& ops = in.operands;
            const std::string& m = in.mnemonic;
            bool writes_dst = !(m == "cmp" || m == "test" || m == "push" || in.cf.is_branch ||
                                in.cf.is_call || in.cf.is_ret);

            for (std::size_t i = 0; i < ops.size(); ++i) {
                const auto& op = ops[i];
                if (op.kind == OpKind::Mem) {
                    if (op.mem.has_base) {
                        record_read(op.mem.base);
                        if (m != "lea") {  // a real dereference -> the base is a pointer
                            refine(op.mem.base, {TClass::Pointer, 8, Sign::Unknown});
                            // Record the access shape for aggregate recovery.
                            unsigned sz = op.size ? op.size : (op.mem.size ? op.mem.size : 8);
                            Acc& acc = derefs[op.mem.base];
                            if (op.mem.has_index) { acc.array = true; acc.stride = op.mem.scale ? op.mem.scale : sz; }
                            acc.offs[op.mem.disp] = Field{op.mem.disp, static_cast<unsigned char>(sz), Sign::Unknown, false};
                        }
                    }
                    if (op.mem.has_index) record_read(op.mem.index);
                } else if (op.kind == OpKind::Reg) {
                    bool is_dst = (i == 0 && writes_dst);
                    if (!is_dst) record_read(op.reg);
                    refine(op.reg, {TClass::Top, static_cast<unsigned char>(op.size ? op.size : 8), Sign::Unknown});
                }
            }

            if ((m == "movsx" || m == "movsxd") && !ops.empty() && ops[0].kind == OpKind::Reg)
                refine(ops[0].reg, {TClass::Integer, static_cast<unsigned char>(ops[0].size), Sign::Signed});
            if (m == "movzx" && !ops.empty() && ops[0].kind == OpKind::Reg)
                refine(ops[0].reg, {TClass::Integer, static_cast<unsigned char>(ops[0].size), Sign::Unsigned});

            if (m == "cmp" && ops.size() >= 2) {
                cmp_a_reg = ops[0].kind == OpKind::Reg; cmp_a = cmp_a_reg ? ops[0].reg : Reg::Rax;
                cmp_b_reg = ops[1].kind == OpKind::Reg; cmp_b = cmp_b_reg ? ops[1].reg : Reg::Rax;
                have_cmp = true;
            }
            if (in.cf.is_cond_branch && have_cmp) {
                Sign s = jcc_sign(m);
                if (s != Sign::Unknown) {
                    if (cmp_a_reg) refine(cmp_a, {TClass::Integer, 0, s});
                    if (cmp_b_reg) refine(cmp_b, {TClass::Integer, 0, s});
                }
                have_cmp = false;
            }

            if (writes_dst && !ops.empty() && ops[0].kind == OpKind::Reg) defined.insert(ops[0].reg);
        }
    }

    // parameters: live-in argument registers, in SysV order
    for (Reg r : {Reg::Rdi, Reg::Rsi, Reg::Rdx, Reg::Rcx, Reg::R8, Reg::R9}) {
        if (live_set.count(r) && is_arg_reg(r)) {
            LType t = ft.regs.count(r) ? ft.regs[r] : LType{};
            ft.params.push_back({r, t});
        }
    }
    // return: rax's view, or a default integer
    ft.ret = ft.regs.count(Reg::Rax) ? ft.regs[Reg::Rax] : LType{TClass::Integer, 8, Sign::Signed};
    if (ft.ret.cls == TClass::Top) ft.ret.cls = TClass::Integer;

    // Aggregate recovery: a pointer dereferenced at several offsets is a struct;
    // indexed access makes it an array. A lone `[p+0]` is just `*p`, not a struct.
    for (auto& [base, acc] : derefs) {
        auto rit = ft.regs.find(base);
        if (rit == ft.regs.end() || rit->second.cls != TClass::Pointer) continue;
        Aggregate ag;
        ag.tag = std::string("s_") + std::string(reg_name(base));
        ag.is_array = acc.array;
        ag.stride = acc.stride;
        for (auto& [off, f] : acc.offs) ag.fields.push_back(f);  // std::map => sorted by offset
        const bool structural = ag.is_array || ag.fields.size() >= 2 ||
                                (ag.fields.size() == 1 && ag.fields[0].offset != 0);
        if (structural) ft.aggregates[base] = std::move(ag);
    }
    return ft;
}

namespace {
// The C spelling of a parameter, preferring a recovered aggregate pointer type.
std::string param_ctype(const Param& p, const std::map<Reg, Aggregate>& aggs) {
    auto it = aggs.find(p.reg);
    if (it != aggs.end()) {
        const Aggregate& ag = it->second;
        if (ag.is_array) {  // element type * : the stride/first field gives the element
            unsigned char w = ag.fields.empty() ? static_cast<unsigned char>(ag.stride ? ag.stride : 8)
                                                 : ag.fields.front().width;
            return c_type({TClass::Integer, w, Sign::Unknown}) + " *";
        }
        return "struct " + ag.tag + " *";
    }
    return c_type(p.type);
}
}  // namespace

std::string FuncTypes::signature() const {
    char h[24];
    std::snprintf(h, sizeof h, "%llx", (unsigned long long)entry);
    std::string s = c_type(ret) + " sub_" + h + "(";
    if (params.empty()) { s += "void"; }
    else {
        for (std::size_t i = 0; i < params.size(); ++i) {
            if (i) s += ", ";
            s += param_ctype(params[i], aggregates) + " " + std::string(reg_name(params[i].reg));
        }
    }
    s += ")";
    return s;
}

std::string FuncTypes::aggregate_defs() const {
    std::string s;
    for (const auto& [reg, ag] : aggregates) {
        if (ag.is_array) continue;  // arrays render as `T *`, no struct def needed
        s += "struct " + ag.tag + " {\n";
        for (const auto& f : ag.fields) {
            char off[24];
            std::snprintf(off, sizeof off, "%llx", (unsigned long long)f.offset);
            s += "    " + c_type({f.is_pointer ? TClass::Pointer : TClass::Integer, f.width, f.sign}) +
                 " field_" + off + ";  // +0x" + off + "\n";
        }
        s += "};\n";
    }
    return s;
}

}  // namespace dede::types
