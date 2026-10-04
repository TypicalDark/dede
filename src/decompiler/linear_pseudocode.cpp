// SPDX-License-Identifier: Apache-2.0
//
// The fallback decompiler: two Visitor passes over the decoded stream. The first
// collects branch targets as labels; the second emits a structured, C-flavoured
// listing (assignments, `if (...) goto`, `call`, `return`). It is not Ghidra,
// but it is an honest readable view that needs no external dependency.
#include <algorithm>
#include <map>
#include <set>
#include <sstream>

#include "dede/decompiler/decompiler.hpp"

namespace dede {

void accept(const DecodedInsn& in, IInsnVisitor& v) {
    if (in.cf.is_ret) return v.visit_ret(in);
    if (in.cf.is_call) return v.visit_call(in);
    if (in.cf.is_branch) return v.visit_branch(in);
    const std::string& m = in.mnemonic;
    if (m == "mov" || m == "lea" || m == "push" || m == "pop" || m == "xchg" ||
        m == "movzx" || m == "movsx" || m == "movsxd") {
        return v.visit_data(in);
    }
    if (m == "add" || m == "sub" || m == "and" || m == "or" || m == "xor" ||
        m == "inc" || m == "dec" || m == "neg" || m == "not" || m == "imul" ||
        m == "shl" || m == "sal" || m == "shr" || m == "sar" || m == "cmp" || m == "test") {
        return v.visit_arith(in);
    }
    return v.visit_other(in);
}

namespace {

// Pass 1: gather the set of addresses that are branch/call targets.
class LabelCollector final : public IInsnVisitor {
public:
    explicit LabelCollector(std::set<Addr>& labels) : labels_(labels) {}
    void visit_branch(const DecodedInsn& in) override { note_target(in); }
    void visit_call(const DecodedInsn& in) override { note_target(in); }
    void visit_data(const DecodedInsn&) override {}
    void visit_arith(const DecodedInsn&) override {}
    void visit_ret(const DecodedInsn&) override {}
    void visit_other(const DecodedInsn&) override {}

private:
    void note_target(const DecodedInsn& in) {
        if (!in.operands.empty() && in.operands[0].kind == OpKind::Imm) {
            labels_.insert(static_cast<Addr>(in.operands[0].imm));
        }
    }
    std::set<Addr>& labels_;
};

// Pass 2: emit pseudocode.
class PseudoEmitter final : public IInsnVisitor {
public:
    PseudoEmitter(std::ostringstream& os, const std::set<Addr>& labels)
        : os_(os), labels_(labels) {}

    void line(const DecodedInsn& in, const std::string& body) {
        if (labels_.count(in.addr)) os_ << "\nloc_" << std::hex << in.addr << std::dec << ":\n";
        os_ << "    " << body << ";    // " << in.text() << "\n";
    }

    void visit_data(const DecodedInsn& in) override {
        if (in.mnemonic == "mov" || in.mnemonic == "lea" || in.mnemonic == "movzx" ||
            in.mnemonic == "movsx" || in.mnemonic == "movsxd") {
            line(in, dst(in) + " = " + src(in));
        } else {
            line(in, in.text());  // push/pop/xchg: keep literal
        }
    }
    void visit_arith(const DecodedInsn& in) override {
        const auto& m = in.mnemonic;
        if (m == "cmp" || m == "test") { line(in, "flags = " + dst(in) + " " + m + " " + src(in)); return; }
        std::string opc = m == "add" ? "+=" : m == "sub" ? "-=" : m == "and" ? "&=" :
                          m == "or" ? "|=" : m == "xor" ? "^=" : m == "shl" || m == "sal" ? "<<=" :
                          m == "shr" || m == "sar" ? ">>=" : m == "imul" ? "*=" : "";
        if (!opc.empty() && in.operands.size() >= 2) line(in, dst(in) + " " + opc + " " + src(in));
        else if (m == "inc") line(in, dst(in) + "++");
        else if (m == "dec") line(in, dst(in) + "--");
        else if (m == "neg") line(in, dst(in) + " = -" + dst(in));
        else if (m == "not") line(in, dst(in) + " = ~" + dst(in));
        else line(in, in.text());
    }
    void visit_branch(const DecodedInsn& in) override {
        std::string tgt = target(in);
        if (in.cf.is_cond_branch) line(in, "if (" + cc(in.mnemonic) + ") goto " + tgt);
        else line(in, "goto " + tgt);
    }
    void visit_call(const DecodedInsn& in) override { line(in, target(in) + "()"); }
    void visit_ret(const DecodedInsn& in) override { line(in, "return"); }
    void visit_other(const DecodedInsn& in) override { line(in, in.text()); }

private:
    static std::string dst(const DecodedInsn& in) { return in.operands.empty() ? "?" : opstr(in.operands[0]); }
    static std::string src(const DecodedInsn& in) { return in.operands.size() < 2 ? "?" : opstr(in.operands[1]); }
    static std::string target(const DecodedInsn& in) {
        if (!in.operands.empty() && in.operands[0].kind == OpKind::Imm) {
            std::ostringstream t; t << "loc_" << std::hex << (Addr)in.operands[0].imm;
            return t.str();
        }
        return in.op_str.empty() ? "?" : in.op_str;
    }
    static std::string opstr(const Operand& op) {
        switch (op.kind) {
            case OpKind::Reg: return std::string(reg_name(op.reg));
            case OpKind::Imm: { std::ostringstream o; o << "0x" << std::hex << op.imm; return o.str(); }
            case OpKind::Mem: return "mem";
            default: return "?";
        }
    }
    static std::string cc(const std::string& m) {
        if (m == "je" || m == "jz") return "ZF";
        if (m == "jne" || m == "jnz") return "!ZF";
        if (m == "jg" || m == "jnle") return "greater";
        if (m == "jl" || m == "jnge") return "less";
        return m.substr(1);  // drop the leading 'j'
    }
    std::ostringstream& os_;
    const std::set<Addr>& labels_;
};

class LinearDecompiler final : public IDecompiler {
public:
    explicit LinearDecompiler(IDisassembler& d) : disasm_(d) {}
    std::string name() const override { return "linear-pseudocode (fallback)"; }

    Result<std::string> decompile(const std::vector<u8>& code, Addr addr) override {
        auto insns = disasm_.decode(code.data(), code.size(), addr, 0);
        if (insns.empty()) return make_error("decompile: nothing decoded");

        std::set<Addr> labels;
        LabelCollector lc(labels);
        for (const auto& in : insns) accept(in, lc);

        std::ostringstream os;
        os << "// linear reconstruction of " << insns.size() << " instructions at 0x"
           << std::hex << addr << std::dec << "\n";
        os << "void sub_" << std::hex << addr << std::dec << "() {\n";
        PseudoEmitter pe(os, labels);
        for (const auto& in : insns) accept(in, pe);
        os << "}\n";
        return os.str();
    }

private:
    IDisassembler& disasm_;
};

}  // namespace

#ifndef DEDE_WITH_GHIDRA
std::unique_ptr<IDecompiler> make_decompiler(IDisassembler& disasm) {
    return std::make_unique<LinearDecompiler>(disasm);
}
#endif

}  // namespace dede
