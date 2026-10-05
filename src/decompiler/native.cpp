// SPDX-License-Identifier: Apache-2.0
//
// The native decompiler (docs/DECOMPILER.md, M3-lite + condition re-fusion + a C
// emitter). It lifts each basic block to IR, builds expression trees with
// constant folding, copy propagation and a few algebraic identities, re-fuses
// cmp/jcc into high-level comparisons, and emits readable C over the existing CFG
// (goto control flow for now; structuring is M5). It replaces the linear
// per-instruction fallback as the default IDecompiler.
#include <cstdio>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>

#include "dede/analysis/cfg.hpp"
#include "dede/decompiler/decompiler.hpp"
#include "dede/ir/lifter.hpp"
#include "dede/types/types.hpp"

namespace dede {

namespace {

using ir::Flag;
using ir::Op;

// --- expression trees -------------------------------------------------------
struct Expr;
using ExprP = std::shared_ptr<Expr>;
struct Expr {
    enum class K { Const, Reg, Flag, Load, Binary, Unary } k;
    long long cval = 0;
    Reg reg = Reg::Rax;
    Flag flag = Flag::CF;
    Op op = Op::Copy;
    ExprP a, b;
    unsigned char size = 8;
};
ExprP mk(Expr e) { return std::make_shared<Expr>(std::move(e)); }
ExprP ec(long long v, unsigned char s = 8) { return mk({Expr::K::Const, v, Reg::Rax, Flag::CF, Op::Copy, nullptr, nullptr, s}); }
ExprP er(Reg r, unsigned char s = 8) { Expr e; e.k = Expr::K::Reg; e.reg = r; e.size = s; return mk(e); }
ExprP ef(Flag f) { Expr e; e.k = Expr::K::Flag; e.flag = f; e.size = 1; return mk(e); }

bool equal(const ExprP& x, const ExprP& y) {
    if (!x || !y) return x == y;
    if (x->k != y->k) return false;
    switch (x->k) {
        case Expr::K::Const: return x->cval == y->cval;
        case Expr::K::Reg: return x->reg == y->reg;
        case Expr::K::Flag: return x->flag == y->flag;
        case Expr::K::Binary: return x->op == y->op && equal(x->a, y->a) && equal(x->b, y->b);
        case Expr::K::Unary: return x->op == y->op && equal(x->a, y->a);
        case Expr::K::Load: return equal(x->a, y->a);
    }
    return false;
}

long long fold(Op op, long long a, long long b) {
    switch (op) {
        case Op::Add: return a + b; case Op::Sub: return a - b; case Op::Mul: return a * b;
        case Op::And: return a & b; case Op::Or: return a | b; case Op::Xor: return a ^ b;
        case Op::Shl: return a << (b & 63); case Op::Shr: return (long long)((unsigned long long)a >> (b & 63));
        case Op::Sar: return a >> (b & 63);
        default: return 0;
    }
}
bool foldable(Op op) {
    switch (op) {
        case Op::Add: case Op::Sub: case Op::Mul: case Op::And: case Op::Or:
        case Op::Xor: case Op::Shl: case Op::Shr: case Op::Sar: return true;
        default: return false;
    }
}

ExprP binary(Op op, ExprP a, ExprP b) {
    if (a->k == Expr::K::Const && b->k == Expr::K::Const && foldable(op))
        return ec(fold(op, a->cval, b->cval), a->size);
    // algebraic identities
    auto isk = [](const ExprP& e, long long v) { return e->k == Expr::K::Const && e->cval == v; };
    if ((op == Op::Add || op == Op::Sub || op == Op::Or || op == Op::Shl || op == Op::Shr || op == Op::Sar) && isk(b, 0)) return a;
    if (op == Op::Add && isk(a, 0)) return b;
    if (op == Op::Mul && (isk(a, 0) || isk(b, 0))) return ec(0, a->size);
    if (op == Op::Mul && isk(b, 1)) return a;
    if (op == Op::Mul && isk(a, 1)) return b;
    if (op == Op::And && (isk(a, 0) || isk(b, 0))) return ec(0, a->size);
    if (op == Op::Xor && equal(a, b)) return ec(0, a->size);   // xor x,x -> 0 (zeroing idiom)
    if (op == Op::And && equal(a, b)) return a;
    Expr e; e.k = Expr::K::Binary; e.op = op; e.a = a; e.b = b; e.size = a->size;
    return mk(e);
}

const char* cop(Op op) {
    switch (op) {
        case Op::Add: return " + "; case Op::Sub: return " - "; case Op::Mul: return " * ";
        case Op::And: return " & "; case Op::Or: return " | "; case Op::Xor: return " ^ ";
        case Op::Shl: return " << "; case Op::Shr: return " >> "; case Op::Sar: return " >> ";
        case Op::Equal: return " == "; case Op::NotEqual: return " != ";
        case Op::Less: return " < "; case Op::SLess: return " < ";
        case Op::LessEqual: return " <= "; case Op::SLessEqual: return " <= ";
        default: return " ? ";
    }
}

std::string hexc(long long v) {
    char b[32];
    if (v >= 0 && v < 10) std::snprintf(b, sizeof b, "%lld", v);
    else std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    return b;
}

std::string print(const ExprP& e, int prec = 0);
std::string print_binary(const ExprP& e, int prec) {
    int myprec = (e->op == Op::Mul) ? 6 : (e->op == Op::Add || e->op == Op::Sub) ? 5
               : (e->op == Op::Shl || e->op == Op::Shr || e->op == Op::Sar) ? 4
               : (e->op == Op::And) ? 3 : (e->op == Op::Xor) ? 2 : (e->op == Op::Or) ? 1 : 0;
    std::string s = print(e->a, myprec) + cop(e->op) + print(e->b, myprec + 1);
    if (myprec < prec) return "(" + s + ")";
    return s;
}
std::string print(const ExprP& e, int prec) {
    if (!e) return "?";
    switch (e->k) {
        case Expr::K::Const: return hexc(e->cval);
        case Expr::K::Reg: return std::string(reg_name(e->reg));
        case Expr::K::Flag: { const char* n[] = {"CF", "PF", "AF", "ZF", "SF", "OF"}; return n[(int)e->flag]; }
        case Expr::K::Load: return "*(uint" + std::to_string(e->size * 8) + "_t *)(" + print(e->a) + ")";
        case Expr::K::Binary: return print_binary(e, prec);
        case Expr::K::Unary: return (e->op == Op::Neg ? "-" : "~") + print(e->a, 7);
    }
    return "?";
}

// --- per-block fold ---------------------------------------------------------
struct BlockOut {
    std::vector<std::string> stmts;
    std::string condition;  // non-empty if the block ends in a conditional branch
};

struct Folder {
    std::map<int, ExprP> temp;
    std::map<Reg, ExprP> regs;
    std::map<Flag, ExprP> flags;
    std::map<Reg, bool> written;

    ExprP of(const ir::Vn& v) {
        switch (v.kind) {
            case ir::VnKind::Const: return ec(v.cval, v.size);
            case ir::VnKind::Temp: { auto it = temp.find(v.temp); return it == temp.end() ? ec(0) : it->second; }
            case ir::VnKind::Reg: { auto it = regs.find(v.reg); return it == regs.end() ? er(v.reg, v.size) : it->second; }
            case ir::VnKind::Flag: { auto it = flags.find(v.flag); return it == flags.end() ? ef(v.flag) : it->second; }
            default: return ec(0);
        }
    }

    // Track the last flag source so a following jcc re-fuses into a comparison.
    // Cmp/Test = a two-operand compare with no destination; Reg = an arithmetic
    // op whose result landed in a register (so the condition is reg-vs-0).
    struct FlagSrc { enum K { None, Cmp, Test, RegResult } kind = None; ExprP a, b; Reg reg = Reg::Rax; } fs;
    int pending_flag_temp = -1;  // result temp of the last Sub/And, for reg linking

    std::string condition(const std::string& jcc) {
        std::string cc = jcc.substr(1);  // strip 'j'
        auto neg = [&](bool& inv) { inv = false; };
        (void)neg;
        if (fs.kind == FlagSrc::RegResult) {
            std::string r = std::string(reg_name(fs.reg));
            if (cc == "e" || cc == "z") return r + " == 0";
            if (cc == "ne" || cc == "nz") return r + " != 0";
            if (cc == "l" || cc == "nge" || cc == "s") return r + " < 0";
            if (cc == "ge" || cc == "nl" || cc == "ns") return r + " >= 0";
            if (cc == "g" || cc == "nle") return r + " > 0";
            if (cc == "le" || cc == "ng") return r + " <= 0";
        } else if (fs.kind == FlagSrc::Cmp) {
            std::string a = print(fs.a), b = print(fs.b);
            if (cc == "e" || cc == "z") return a + " == " + b;
            if (cc == "ne" || cc == "nz") return a + " != " + b;
            if (cc == "l" || cc == "nge") return a + " < " + b;
            if (cc == "le" || cc == "ng") return a + " <= " + b;
            if (cc == "g" || cc == "nle") return a + " > " + b;
            if (cc == "ge" || cc == "nl") return a + " >= " + b;
            if (cc == "b" || cc == "c" || cc == "nae") return "(unsigned)" + a + " < (unsigned)" + b;
            if (cc == "a" || cc == "nbe") return "(unsigned)" + a + " > (unsigned)" + b;
            if (cc == "be" || cc == "na") return "(unsigned)" + a + " <= (unsigned)" + b;
            if (cc == "ae" || cc == "nb") return "(unsigned)" + a + " >= (unsigned)" + b;
        } else if (fs.kind == FlagSrc::Test) {
            std::string t = equal(fs.a, fs.b) ? print(fs.a) : "(" + print(fs.a) + " & " + print(fs.b) + ")";
            if (cc == "e" || cc == "z") return t + " == 0";
            if (cc == "ne" || cc == "nz") return t + " != 0";
            if (cc == "s") return t + " < 0";
            if (cc == "ns") return t + " >= 0";
        }
        // CF-based (e.g. bt+jb) from the recovered flag expression.
        auto cf = flags.find(Flag::CF);
        if (cf != flags.end()) {
            if (cc == "b" || cc == "c" || cc == "nae") return "(" + print(cf->second) + ") != 0";
            if (cc == "ae" || cc == "nb" || cc == "nc") return "(" + print(cf->second) + ") == 0";
        }
        if (cc == "e" || cc == "z") return "ZF";
        if (cc == "ne" || cc == "nz") return "!ZF";
        return "cond_" + cc;
    }

    BlockOut run(const ir::Block& b) {
        BlockOut out;
        for (const auto& in : b.code) {
            switch (in.op) {
                case Op::Copy:
                    if (in.out.kind == ir::VnKind::Temp) temp[in.out.temp] = of(in.a);
                    else if (in.out.kind == ir::VnKind::Reg) {
                        ExprP rhs = of(in.a);
                        // Emit the assignment in order, then let later uses refer to
                        // the register by name (so output stays sequential + correct).
                        out.stmts.push_back(std::string(reg_name(in.out.reg)) + " = " + print(rhs) + ";");
                        regs[in.out.reg] = er(in.out.reg, in.out.size);
                        written[in.out.reg] = true;
                        if (in.a.kind == ir::VnKind::Temp && in.a.temp == pending_flag_temp)
                            fs = {FlagSrc::RegResult, nullptr, nullptr, in.out.reg};
                    } else if (in.out.kind == ir::VnKind::Flag) flags[in.out.flag] = of(in.a);
                    break;
                case Op::Load: if (in.out.kind == ir::VnKind::Temp) { Expr e; e.k = Expr::K::Load; e.a = of(in.a); e.size = in.out.size; temp[in.out.temp] = mk(e); } break;
                case Op::Store: out.stmts.push_back("*(uint" + std::to_string(in.b.size * 8) + "_t *)(" + print(of(in.a)) + ") = " + print(of(in.b)) + ";"); break;
                case Op::Add: case Op::Sub: case Op::Mul: case Op::And: case Op::Or:
                case Op::Xor: case Op::Shl: case Op::Shr: case Op::Sar:
                    if (in.out.kind == ir::VnKind::Temp) {
                        // Record the flag source for a following jcc (sub = cmp,
                        // and = test). A later Copy of this temp to a register
                        // upgrades it to a reg-vs-0 condition.
                        if (in.op == Op::Sub) { fs = {FlagSrc::Cmp, of(in.a), of(in.b), Reg::Rax}; pending_flag_temp = in.out.temp; }
                        else if (in.op == Op::And) { fs = {FlagSrc::Test, of(in.a), of(in.b), Reg::Rax}; pending_flag_temp = in.out.temp; }
                        temp[in.out.temp] = binary(in.op, of(in.a), of(in.b));
                    }
                    break;
                case Op::Not: if (in.out.kind == ir::VnKind::Temp) { Expr e; e.k = Expr::K::Unary; e.op = Op::Not; e.a = of(in.a); e.size = in.out.size; temp[in.out.temp] = mk(e); } break;
                case Op::Neg: if (in.out.kind == ir::VnKind::Temp) { Expr e; e.k = Expr::K::Unary; e.op = Op::Neg; e.a = of(in.a); e.size = in.out.size; temp[in.out.temp] = mk(e); } break;
                case Op::Zext: case Op::Sext: if (in.out.kind == ir::VnKind::Temp) temp[in.out.temp] = of(in.a); break;
                case Op::Call: { ExprP t = of(in.a); char nm[24]; std::snprintf(nm, sizeof nm, "%llx", (unsigned long long)t->cval); out.stmts.push_back(std::string("sub_") + nm + "();"); break; }
                case Op::CBranch: out.condition = condition(in.note); break;
                default: break;  // flag-producer ops consumed via re-fusion; branches handled by CFG
            }
        }
        return out;
    }
};

// --- function emitter -------------------------------------------------------
std::string decompile_function(const IDisassembler& dis, const ByteReader& read, Addr entry) {
    Cfg cfg = build_cfg(dis, read, entry);
    types::FuncTypes ft = types::infer_function(dis, read, entry);

    // which block starts are jump targets (need a label)?
    std::set<Addr> labels;
    for (const auto& e : cfg.edges) labels.insert(e.to);

    // buffer the body first so declarations (which depend on written regs) lead
    std::ostringstream body;
    std::set<Reg> written_regs;
    for (const auto& bb : cfg.blocks) {
        if (labels.count(bb.start)) { char b[24]; std::snprintf(b, sizeof b, "%llx", (unsigned long long)bb.start); body << "loc_" << b << ":\n"; }
        ir::Block ib = ir::lift_block(bb);
        Folder f;
        BlockOut bo = f.run(ib);
        for (const auto& [r, w] : f.written) if (w) written_regs.insert(r);
        for (const auto& s : bo.stmts) body << "    " << s << "\n";
        // control-flow tail from the CFG
        Addr taken = 0, nottaken = 0, jump = 0;
        bool term = bb.terminates;
        for (const auto& e : cfg.edges) {
            if (e.from != bb.start) continue;
            if (e.kind == EdgeKind::Taken) taken = e.to;
            else if (e.kind == EdgeKind::NotTaken) nottaken = e.to;
            else if (e.kind == EdgeKind::Jump) jump = e.to;
            else if (e.kind == EdgeKind::Fallthrough) nottaken = e.to;
        }
        char tb[24], nb[24], jb[24];
        std::snprintf(tb, sizeof tb, "%llx", (unsigned long long)taken);
        std::snprintf(nb, sizeof nb, "%llx", (unsigned long long)nottaken);
        std::snprintf(jb, sizeof jb, "%llx", (unsigned long long)jump);
        if (!bo.condition.empty() && taken) {
            body << "    if (" << bo.condition << ") goto loc_" << tb << ";\n";
            if (nottaken) body << "    goto loc_" << nb << ";\n";
        } else if (jump) {
            body << "    goto loc_" << jb << ";\n";
        } else if (term) {
            body << "    return rax;\n";
        } else if (nottaken) {
            body << "    goto loc_" << nb << ";\n";
        }
    }

    // assemble: typed signature + local declarations + body
    std::ostringstream os;
    os << ft.signature() << " {\n";
    std::set<Reg> param_regs;
    for (const auto& p : ft.params) param_regs.insert(p.reg);
    bool any_decl = false;
    for (Reg r : written_regs) {
        if (param_regs.count(r) || r == Reg::Rsp || r == Reg::Rbp) continue;
        types::LType t = ft.regs.count(r) ? ft.regs.at(r) : types::LType{};
        os << "    " << types::c_type(t) << " " << std::string(reg_name(r)) << ";\n";
        any_decl = true;
    }
    if (any_decl) os << "\n";
    os << body.str() << "}\n";
    return os.str();
}

class NativeDecompiler final : public IDecompiler {
public:
    explicit NativeDecompiler(IDisassembler& d) : dis_(d) {}
    std::string name() const override { return "dede-native (IR + fold + re-fuse)"; }
    Result<std::string> decompile(const std::vector<u8>& code, Addr addr) override {
        if (code.empty()) return make_error("decompile: empty");
        ByteReader read = [&code, addr](Addr a) -> std::optional<u8> {
            if (a >= addr && a < addr + code.size()) return code[a - addr];
            return std::nullopt;
        };
        return decompile_function(dis_, read, addr);
    }

private:
    IDisassembler& dis_;
};

}  // namespace

#ifndef DEDE_WITH_GHIDRA
std::unique_ptr<IDecompiler> make_decompiler(IDisassembler& disasm) {
    return std::make_unique<NativeDecompiler>(disasm);
}
#endif

}  // namespace dede
