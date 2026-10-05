// SPDX-License-Identifier: Apache-2.0
//
// The native decompiler (docs/DECOMPILER.md, M3-lite + condition re-fusion + a C
// emitter). It lifts each basic block to IR, builds expression trees with
// constant folding, copy propagation and a few algebraic identities, re-fuses
// cmp/jcc into high-level comparisons, and emits readable C over the existing CFG
// (goto control flow for now; structuring is M5). It replaces the linear
// per-instruction fallback as the default IDecompiler.
#include <cstdio>
#include <functional>
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
    enum class K { Const, Reg, Flag, Load, Binary, Unary, Var } k;
    long long cval = 0;
    Reg reg = Reg::Rax;
    Flag flag = Flag::CF;
    Op op = Op::Copy;
    ExprP a, b;
    unsigned char size = 8;
    std::string text;  // Var: the synthesized local name (var_8 / arg_10)
};
ExprP mk(Expr e) { return std::make_shared<Expr>(std::move(e)); }
ExprP ec(long long v, unsigned char s = 8) { Expr e; e.k = Expr::K::Const; e.cval = v; e.size = s; return mk(e); }
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
        case Expr::K::Var: return x->text == y->text;
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

// If `m` is a contiguous low-bit mask (2^w - 1), return its width w, else 0.
int low_mask_width(long long m) {
    if (m <= 0) return 0;
    unsigned long long u = static_cast<unsigned long long>(m);
    if ((u & (u + 1)) != 0) return 0;  // not 2^w - 1
    int w = 0;
    while (u) { ++w; u >>= 1; }
    return w;
}

// Bitfield-read reconstruction: `(x >> lo) & ((1<<w)-1)` with a *multi-bit*
// field at a nonzero position is a struct bitfield access. Render it as the
// pseudo-C intrinsic BITFIELD(x, lo, width) — the same helper-form Ghidra/
// Hex-Rays emit. Single-bit extracts (w == 1) are left as `(x >> k) & 1`
// bit-tests, and masks at position 0 are left as truncation masks, since both
// are ambiguous with a true bitfield.
std::optional<std::string> as_bitfield(const ExprP& e) {
    if (!e || e->k != Expr::K::Binary || e->op != Op::And || !e->a || !e->b) return std::nullopt;
    if (e->b->k != Expr::K::Const) return std::nullopt;
    int w = low_mask_width(e->b->cval);
    if (w < 2) return std::nullopt;
    const ExprP& sh = e->a;
    if (sh->k != Expr::K::Binary || (sh->op != Op::Shr && sh->op != Op::Sar)) return std::nullopt;
    if (!sh->b || sh->b->k != Expr::K::Const || sh->b->cval <= 0) return std::nullopt;
    return "BITFIELD(" + print(sh->a) + ", " + std::to_string(sh->b->cval) + ", " + std::to_string(w) + ")";
}

// Collect the register leaves of an expression (for soundness checks).
void reg_leaves(const ExprP& e, std::set<Reg>& out) {
    if (!e) return;
    switch (e->k) {
        case Expr::K::Reg: out.insert(e->reg); break;
        case Expr::K::Binary: reg_leaves(e->a, out); reg_leaves(e->b, out); break;
        case Expr::K::Unary: case Expr::K::Load: reg_leaves(e->a, out); break;
        default: break;
    }
}

// True if the expression touches memory (a Load or a recovered stack Var). A
// bitfield read is only collapsed across statements when it is purely register-
// based, so a later store cannot invalidate the inlined value.
bool touches_mem(const ExprP& e) {
    if (!e) return false;
    if (e->k == Expr::K::Load || e->k == Expr::K::Var) return true;
    if (e->k == Expr::K::Binary) return touches_mem(e->a) || touches_mem(e->b);
    if (e->k == Expr::K::Unary) return touches_mem(e->a);
    return false;
}

std::string print_binary(const ExprP& e, int prec) {
    if (auto bf = as_bitfield(e)) return *bf;  // BITFIELD(...) is a primary; no parens
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
        case Expr::K::Var: return e->text;
    }
    return "?";
}

// Recognise a frame-relative address (rbp/rsp ± k) and name it as a local.
std::optional<std::string> slot_name(const ExprP& addr) {
    auto frame = [](Reg r) { return r == Reg::Rbp; };  // stable frame pointer only
    auto fmt = [](const char* pfx, long long v) {
        char b[32]; std::snprintf(b, sizeof b, "%s%llx", pfx, (unsigned long long)v); return std::string(b);
    };
    if (addr->k == Expr::K::Reg && frame(addr->reg)) return std::string("var_0");
    if (addr->k == Expr::K::Binary && addr->op == Op::Add && addr->a->k == Expr::K::Reg &&
        frame(addr->a->reg) && addr->b->k == Expr::K::Const) {
        long long c = addr->b->cval;
        return c < 0 ? fmt("var_", -c) : fmt("arg_", c);
    }
    return std::nullopt;
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
    std::map<std::string, types::LType> stack_vars;  // recovered named locals
    const std::map<Reg, types::Aggregate>* aggs = nullptr;  // recovered struct/array ptrs

    // Render a dereference through a recovered struct pointer as `base->field_<off>`
    // (so `*(uint64_t *)(rdi + 8)` becomes `rdi->field_8`).
    std::optional<std::string> field_name(const ExprP& addr) const {
        if (!aggs) return std::nullopt;
        Reg base; long long off;
        if (addr->k == Expr::K::Reg) { base = addr->reg; off = 0; }
        else if (addr->k == Expr::K::Binary && addr->op == Op::Add && addr->a->k == Expr::K::Reg &&
                 addr->b->k == Expr::K::Const) { base = addr->a->reg; off = addr->b->cval; }
        else return std::nullopt;
        auto it = aggs->find(base);
        if (it == aggs->end() || it->second.is_array || !it->second.field_at(off)) return std::nullopt;
        char b[48];
        std::snprintf(b, sizeof b, "%s->field_%llx", std::string(reg_name(base)).c_str(), (unsigned long long)off);
        return std::string(b);
    }

    // Parallel symbolic-value track used ONLY to recognise multi-statement
    // idioms (bitfield reads) and collapse them. Unlike `regs`/`temp`, these
    // are not reset to the register name after each def, so they carry the full
    // value expression across statements within a straight-line region.
    std::map<int, ExprP> symtmp;
    std::map<Reg, ExprP> symreg;
    std::map<Reg, std::vector<std::size_t>> chain;  // removable feeder stmt indices per reg
    std::set<std::size_t> dead;                     // out.stmts indices to drop

    ExprP of(const ir::Vn& v) {
        switch (v.kind) {
            case ir::VnKind::Const: return ec(v.cval, v.size);
            case ir::VnKind::Temp: { auto it = temp.find(v.temp); return it == temp.end() ? ec(0) : it->second; }
            case ir::VnKind::Reg: { auto it = regs.find(v.reg); return it == regs.end() ? er(v.reg, v.size) : it->second; }
            case ir::VnKind::Flag: { auto it = flags.find(v.flag); return it == flags.end() ? ef(v.flag) : it->second; }
            default: return ec(0);
        }
    }

    ExprP symof(const ir::Vn& v) {
        switch (v.kind) {
            case ir::VnKind::Const: return ec(v.cval, v.size);
            case ir::VnKind::Temp: { auto it = symtmp.find(v.temp); return it == symtmp.end() ? ec(0) : it->second; }
            case ir::VnKind::Reg: { auto it = symreg.find(v.reg); return it == symreg.end() ? er(v.reg, v.size) : it->second; }
            case ir::VnKind::Flag: return ef(v.flag);
            default: return ec(0);
        }
    }

    // A register leaf is safe to name in a collapsed expression only if it has
    // not been reassigned earlier in the block (so it still holds its entry
    // value at this point); memory operands are never collapsed.
    bool collapsible(const ExprP& sym) {
        if (touches_mem(sym)) return false;
        std::set<Reg> leaves;
        reg_leaves(sym, leaves);
        for (Reg r : leaves) { auto w = written.find(r); if (w != written.end() && w->second) return false; }
        return true;
    }
    void barrier() { for (auto& c : chain) c.second.clear(); }  // stores/branches end a region

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
                    if (in.out.kind == ir::VnKind::Temp) { temp[in.out.temp] = of(in.a); symtmp[in.out.temp] = symof(in.a); }
                    else if (in.out.kind == ir::VnKind::Reg) {
                        ExprP rhs = of(in.a);
                        ExprP sym = symof(in.a);
                        Reg dst = in.out.reg;
                        std::string name = std::string(reg_name(dst));
                        std::size_t idx = out.stmts.size();
                        // Multi-statement bitfield read `(x >> lo) & mask` collapses to
                        // a BITFIELD(x, lo, width) intrinsic; its dead feeder statements
                        // (the shift + mask chain) are removed.
                        if (auto bf = as_bitfield(sym); bf && collapsible(sym)) {
                            for (std::size_t fi : chain[dst]) dead.insert(fi);
                            chain[dst].clear();
                            out.stmts.push_back(name + " = " + *bf + ";");
                            symreg[dst] = er(dst, in.out.size);
                        } else {
                            // Emit the assignment in order, then let later uses refer to
                            // the register by name (so output stays sequential + correct).
                            std::set<Reg> leaves;
                            reg_leaves(rhs, leaves);
                            bool reads_self = leaves.count(dst) > 0;
                            for (Reg s : leaves) if (s != dst) chain[s].clear();  // value escaped into dst
                            out.stmts.push_back(name + " = " + print(rhs) + ";");
                            if (reads_self) chain[dst].push_back(idx);
                            else chain[dst] = {idx};
                            symreg[dst] = sym;
                        }
                        regs[dst] = er(dst, in.out.size);
                        written[dst] = true;
                        if (in.a.kind == ir::VnKind::Temp && in.a.temp == pending_flag_temp)
                            fs = {FlagSrc::RegResult, nullptr, nullptr, dst};
                    } else if (in.out.kind == ir::VnKind::Flag) flags[in.out.flag] = of(in.a);
                    break;
                case Op::Load:
                    if (in.out.kind == ir::VnKind::Temp) {
                        ExprP a = of(in.a);
                        ExprP le;
                        if (auto nm = slot_name(a)) {
                            Expr e; e.k = Expr::K::Var; e.text = *nm; e.size = in.out.size;
                            le = mk(e);
                            stack_vars[*nm] = {types::TClass::Integer, in.out.size, types::Sign::Unknown};
                        } else if (auto fn = field_name(a)) {  // struct field access
                            Expr e; e.k = Expr::K::Var; e.text = *fn; e.size = in.out.size; le = mk(e);
                        } else {
                            Expr e; e.k = Expr::K::Load; e.a = a; e.size = in.out.size; le = mk(e);
                        }
                        temp[in.out.temp] = le;
                        symtmp[in.out.temp] = le;
                    }
                    break;
                case Op::Store: {
                    ExprP a = of(in.a);
                    if (auto nm = slot_name(a)) {
                        out.stmts.push_back(*nm + " = " + print(of(in.b)) + ";");
                        stack_vars[*nm] = {types::TClass::Integer, in.b.size, types::Sign::Unknown};
                    } else if (auto fn = field_name(a)) {  // struct field store
                        out.stmts.push_back(*fn + " = " + print(of(in.b)) + ";");
                    } else {
                        out.stmts.push_back("*(uint" + std::to_string(in.b.size * 8) + "_t *)(" + print(a) + ") = " + print(of(in.b)) + ";");
                    }
                    barrier();  // a store ends the straight-line region for collapsing
                    break;
                }
                case Op::Add: case Op::Sub: case Op::Mul: case Op::And: case Op::Or:
                case Op::Xor: case Op::Shl: case Op::Shr: case Op::Sar:
                    if (in.out.kind == ir::VnKind::Temp) {
                        // Record the flag source for a following jcc (sub = cmp,
                        // and = test). A later Copy of this temp to a register
                        // upgrades it to a reg-vs-0 condition.
                        if (in.op == Op::Sub) { fs = {FlagSrc::Cmp, of(in.a), of(in.b), Reg::Rax}; pending_flag_temp = in.out.temp; }
                        else if (in.op == Op::And) { fs = {FlagSrc::Test, of(in.a), of(in.b), Reg::Rax}; pending_flag_temp = in.out.temp; }
                        temp[in.out.temp] = binary(in.op, of(in.a), of(in.b));
                        symtmp[in.out.temp] = binary(in.op, symof(in.a), symof(in.b));
                    }
                    break;
                case Op::Not: if (in.out.kind == ir::VnKind::Temp) { Expr e; e.k = Expr::K::Unary; e.op = Op::Not; e.a = of(in.a); e.size = in.out.size; temp[in.out.temp] = mk(e); Expr se = e; se.a = symof(in.a); symtmp[in.out.temp] = mk(se); } break;
                case Op::Neg: if (in.out.kind == ir::VnKind::Temp) { Expr e; e.k = Expr::K::Unary; e.op = Op::Neg; e.a = of(in.a); e.size = in.out.size; temp[in.out.temp] = mk(e); Expr se = e; se.a = symof(in.a); symtmp[in.out.temp] = mk(se); } break;
                case Op::Zext: case Op::Sext: if (in.out.kind == ir::VnKind::Temp) { temp[in.out.temp] = of(in.a); symtmp[in.out.temp] = symof(in.a); } break;
                case Op::Call: { ExprP t = of(in.a); char nm[24]; std::snprintf(nm, sizeof nm, "%llx", (unsigned long long)t->cval); out.stmts.push_back(std::string("sub_") + nm + "();"); symreg.clear(); barrier(); break; }
                case Op::CBranch: out.condition = condition(in.note); barrier(); break;
                default: break;  // flag-producer ops consumed via re-fusion; branches handled by CFG
            }
        }
        // Drop the feeder statements made dead by a bitfield collapse.
        if (!dead.empty()) {
            std::vector<std::string> keep;
            keep.reserve(out.stmts.size());
            for (std::size_t i = 0; i < out.stmts.size(); ++i)
                if (!dead.count(i)) keep.push_back(out.stmts[i]);
            out.stmts.swap(keep);
        }
        return out;
    }
};

// Negate a condition for a loop whose test exits the loop. Flips a single
// comparison operator for readability; falls back to !(...) otherwise.
std::string negate_cond(const std::string& c) {
    struct F { const char* a; const char* b; };
    static const F flips[] = {{" >= ", " < "}, {" <= ", " > "}, {" > ", " <= "},
                              {" < ", " >= "}, {" == ", " != "}, {" != ", " == "}};
    if (c.find('(') == std::string::npos)
        for (const auto& f : flips) {
            std::string a = f.a;
            auto p = c.find(a);
            if (p != std::string::npos && c.find(a, p + 1) == std::string::npos)
                return c.substr(0, p) + f.b + c.substr(p + a.size());
        }
    return "!(" + c + ")";
}

// --- dominators / post-dominators -------------------------------------------
constexpr Addr kExit = ~Addr(0);

std::map<Addr, std::set<Addr>> compute_dom(const std::vector<Addr>& nodes, Addr root,
                                           const std::map<Addr, std::vector<Addr>>& preds) {
    std::map<Addr, std::set<Addr>> dom;
    std::set<Addr> all(nodes.begin(), nodes.end());
    for (Addr n : nodes) dom[n] = all;
    dom[root] = {root};
    bool changed = true;
    while (changed) {
        changed = false;
        for (Addr n : nodes) {
            if (n == root) continue;
            std::set<Addr> inter;
            bool first = true;
            auto it = preds.find(n);
            if (it != preds.end())
                for (Addr p : it->second) {
                    if (!dom.count(p)) continue;
                    if (first) { inter = dom[p]; first = false; }
                    else { std::set<Addr> t; for (Addr x : inter) if (dom[p].count(x)) t.insert(x); inter.swap(t); }
                }
            inter.insert(n);
            if (inter != dom[n]) { dom[n] = inter; changed = true; }
        }
    }
    return dom;
}

// Immediate post-dominator = the nearest post-dominator (the one with the most
// post-dominators of its own among n's strict post-dominators).
Addr ipdom_of(Addr n, const std::map<Addr, std::set<Addr>>& pdom) {
    auto it = pdom.find(n);
    if (it == pdom.end()) return kExit;
    Addr best = kExit; std::size_t bestsz = 0; bool found = false;
    for (Addr c : it->second) {
        if (c == n) continue;
        std::size_t sz = pdom.count(c) ? pdom.at(c).size() : 1;
        if (!found || sz > bestsz) { bestsz = sz; best = c; found = true; }
    }
    return best;
}

// --- function emitter -------------------------------------------------------
struct BInfo {
    std::vector<std::string> stmts;
    std::string condition;
    Addr taken = 0, nottaken = 0, jump = 0;
    std::vector<Addr> cases;  // n-way (recovered jump table)
    bool terminal = false;
};

std::string decompile_function(const IDisassembler& dis, const ByteReader& read, Addr entry) {
    Cfg cfg = build_cfg(dis, read, entry);
    types::FuncTypes ft = types::infer_function(dis, read, entry);

    std::map<Addr, BInfo> info;
    std::set<Reg> written_regs;
    std::map<std::string, types::LType> stack_vars;
    std::vector<Addr> nodes;
    std::map<Addr, std::vector<Addr>> succ, preds;

    for (const auto& bb : cfg.blocks) {
        nodes.push_back(bb.start);
        ir::Block ib = ir::lift_block(bb);
        Folder f;
        f.aggs = &ft.aggregates;  // render struct-pointer derefs as field accesses
        BlockOut bo = f.run(ib);
        for (const auto& [r, w] : f.written) if (w) written_regs.insert(r);
        for (const auto& [nm, t] : f.stack_vars) stack_vars[nm] = t;
        BInfo bi;
        bi.stmts = bo.stmts;
        bi.condition = bo.condition;
        bi.terminal = bb.terminates;
        std::vector<Addr> jumps;
        for (const auto& e : cfg.edges) {
            if (e.from != bb.start) continue;
            if (e.kind == EdgeKind::Taken) bi.taken = e.to;
            else if (e.kind == EdgeKind::NotTaken) bi.nottaken = e.to;
            else if (e.kind == EdgeKind::Jump) jumps.push_back(e.to);
            else if (e.kind == EdgeKind::Fallthrough) bi.nottaken = e.to;
        }
        if (jumps.size() == 1) bi.jump = jumps[0];
        else if (jumps.size() > 1) bi.cases = jumps;  // n-way jump table
        info[bb.start] = std::move(bi);
    }
    for (Addr n : nodes) {
        const BInfo& b = info[n];
        std::vector<Addr> s;
        if (b.taken) s.push_back(b.taken);
        if (b.nottaken) s.push_back(b.nottaken);
        if (b.jump) s.push_back(b.jump);
        for (Addr c : b.cases) s.push_back(c);  // n-way switch successors
        if (s.empty()) s.push_back(kExit);
        succ[n] = s;
        for (Addr t : s) preds[t].push_back(n);
    }
    auto dom = compute_dom(nodes, entry, preds);
    std::vector<Addr> rnodes = nodes; rnodes.push_back(kExit);
    auto pdom = compute_dom(rnodes, kExit, succ);  // reverse-graph preds = forward succ

    // loop headers: target of a back-edge (edge m->h where h dominates m)
    std::set<Addr> loop_headers;
    for (Addr m : nodes)
        for (Addr s : succ[m])
            if (s != kExit && dom.count(m) && dom.at(m).count(s)) loop_headers.insert(s);

    // can `from` reach `target` over flow edges (for while body/exit classification)?
    auto can_reach = [&](Addr from, Addr target) {
        std::set<Addr> vis;
        std::vector<Addr> st{from};
        while (!st.empty()) {
            Addr x = st.back(); st.pop_back();
            if (x == target) return true;
            if (x == kExit || vis.count(x)) continue;
            vis.insert(x);
            auto it = succ.find(x);
            if (it != succ.end()) for (Addr s : it->second) st.push_back(s);
        }
        return false;
    };

    auto hexa = [](Addr a) { char b[24]; std::snprintf(b, sizeof b, "%llx", (unsigned long long)a); return std::string(b); };

    // Two-pass structured emission: pass 1 discovers which blocks are goto'd (need
    // a label); pass 2 writes, labelling only those. do-while for self-loops, if/
    // else via the post-dominator join, goto fallback for everything else.
    std::set<Addr> need_label;
    std::set<Addr> seen;
    std::ostringstream body;
    std::function<void(Addr, Addr, int, bool)> emit = [&](Addr n, Addr stop, int ind, bool collect) {
        std::string pad(static_cast<std::size_t>(ind) * 4 + 4, ' ');
        while (n != kExit && n != stop && n != 0) {
            auto fit = info.find(n);
            if (fit == info.end()) return;
            const BInfo& b = fit->second;
            if (seen.count(n)) { if (collect) need_label.insert(n); else body << pad << "goto loc_" << hexa(n) << ";\n"; return; }
            seen.insert(n);
            if (!collect && need_label.count(n)) body << "loc_" << hexa(n) << ":\n";

            if (!b.condition.empty() && b.taken == n) {  // self-loop -> do/while
                if (!collect) { body << pad << "do {\n"; for (const auto& s : b.stmts) body << pad << "    " << s << "\n"; body << pad << "} while (" << b.condition << ");\n"; }
                n = b.nottaken; continue;
            }
            // pre-test while: a conditional loop header whose own stmts are just the
            // test (no side effects), with one successor in the loop and one out.
            if (loop_headers.count(n) && !b.condition.empty() && b.taken && b.nottaken && b.stmts.empty()) {
                bool taken_body = can_reach(b.taken, n);
                bool nottaken_body = can_reach(b.nottaken, n);
                if (taken_body != nottaken_body) {
                    Addr bodyN = taken_body ? b.taken : b.nottaken;
                    Addr exitN = taken_body ? b.nottaken : b.taken;
                    std::string cond = taken_body ? b.condition : negate_cond(b.condition);
                    if (!collect) body << pad << "while (" << cond << ") {\n";
                    emit(bodyN, n, ind + 1, collect);  // body closes at the header
                    if (!collect) body << pad << "}\n";
                    n = exitN; continue;
                }
            }
            if (!collect) for (const auto& s : b.stmts) body << pad << s << "\n";

            if (!b.cases.empty()) {  // recovered jump table -> switch
                if (!collect) body << pad << "switch (idx) {\n";
                for (std::size_t i = 0; i < b.cases.size(); ++i) {
                    if (collect) need_label.insert(b.cases[i]);
                    else body << pad << "    case " << i << ": goto loc_" << hexa(b.cases[i]) << ";\n";
                }
                if (!collect) body << pad << "}\n";
                return;
            }

            if (!b.condition.empty() && b.taken && b.nottaken) {
                bool back = dom.count(n) && (dom.at(n).count(b.taken) || dom.at(n).count(b.nottaken));
                Addr j = ipdom_of(n, pdom);
                if (!back && b.taken != b.nottaken && j != n) {
                    if (!collect) body << pad << "if (" << b.condition << ") {\n";
                    emit(b.taken, j, ind + 1, collect);
                    if (b.nottaken != j) { if (!collect) body << pad << "} else {\n"; emit(b.nottaken, j, ind + 1, collect); }
                    if (!collect) body << pad << "}\n";
                    if (j == kExit) return;
                    n = j; continue;
                }
                // fallback: conditional goto
                if (collect) need_label.insert(b.taken);
                else body << pad << "if (" << b.condition << ") goto loc_" << hexa(b.taken) << ";\n";
                n = b.nottaken; continue;
            } else if (b.jump) {
                if (b.jump == stop) return;  // back-edge/exit to an enclosing region closes it
                if (seen.count(b.jump)) { if (collect) need_label.insert(b.jump); else body << pad << "goto loc_" << hexa(b.jump) << ";\n"; return; }
                n = b.jump; continue;
            } else if (b.terminal) {
                if (!collect) body << pad << "return rax;\n";
                return;
            } else if (b.nottaken) {
                n = b.nottaken; continue;
            } else return;
        }
    };
    seen.clear(); emit(entry, kExit, 0, true);
    // residue: blocks reached only via case gotos get a label and a linear tail;
    // their own goto targets must be labelled too, so register them before pass 2.
    std::set<Addr> reached = seen;
    for (Addr n : nodes) {
        if (reached.count(n)) continue;
        need_label.insert(n);
        const BInfo& b = info.at(n);
        for (Addr c : b.cases) need_label.insert(c);
        if (b.taken) need_label.insert(b.taken);
        if (b.nottaken) need_label.insert(b.nottaken);
        if (b.jump) need_label.insert(b.jump);
    }
    seen.clear(); body.str(""); emit(entry, kExit, 0, false);
    // emit the residue blocks linearly after the structured body
    for (Addr n : nodes) {
        if (seen.count(n)) continue;
        const BInfo& b = info.at(n);
        body << "loc_" << hexa(n) << ":\n";
        for (const auto& s : b.stmts) body << "    " << s << "\n";
        if (!b.cases.empty()) {
            body << "    switch (idx) {\n";
            for (std::size_t i = 0; i < b.cases.size(); ++i) body << "        case " << i << ": goto loc_" << hexa(b.cases[i]) << ";\n";
            body << "    }\n";
        } else if (!b.condition.empty() && b.taken) {
            body << "    if (" << b.condition << ") goto loc_" << hexa(b.taken) << ";\n";
            if (b.nottaken) body << "    goto loc_" << hexa(b.nottaken) << ";\n";
        } else if (b.jump) body << "    goto loc_" << hexa(b.jump) << ";\n";
        else if (b.terminal) body << "    return rax;\n";
        else if (b.nottaken) body << "    goto loc_" << hexa(b.nottaken) << ";\n";
        seen.insert(n);
    }

    // assemble: recovered aggregate defs + typed signature + local declarations + body
    std::ostringstream os;
    std::string aggs = ft.aggregate_defs();
    if (!aggs.empty()) os << aggs << "\n";
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
    for (const auto& [nm, t] : stack_vars) {  // recovered stack locals
        os << "    " << types::c_type(t) << " " << nm << ";\n";
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

    // With an image oracle: read code from the `code` window, but fall back to
    // the full image for anything beyond it (the jump table in .rodata). The
    // window still bounds the instruction sweep; only out-of-window *data* reads
    // reach into the image.
    Result<std::string> decompile(const std::vector<u8>& code, Addr addr,
                                  const DecompReader& image) override {
        if (code.empty()) return make_error("decompile: empty");
        ByteReader read = [&code, addr, &image](Addr a) -> std::optional<u8> {
            if (a >= addr && a < addr + code.size()) return code[a - addr];
            return image ? image(a) : std::nullopt;
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
