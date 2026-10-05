// SPDX-License-Identifier: Apache-2.0
//
// Lift a decoded x86-64 instruction (dede's supported subset) into IR. Mirrors
// the interpreter's semantics so the two agree under differential execution.
#include "dede/ir/lifter.hpp"

namespace dede::ir {

namespace {

struct Lifter {
    std::vector<Insn>& out;
    Addr addr;
    int next_temp = 0;

    Vn tmp(unsigned char sz) { return Vn::t(next_temp++, sz); }
    void emit(Op op, Vn o, Vn a = Vn::none(), Vn b = Vn::none(), std::string note = {}) {
        out.push_back({op, o, a, b, addr, std::move(note)});
    }

    unsigned char osize(const Operand& op) { return static_cast<unsigned char>(op.size ? op.size : 8); }

    // Effective address of a memory operand into a fresh 8-byte temp.
    Vn addr_of(const MemOperand& m) {
        Vn acc = Vn::k(m.disp, 8);
        bool have = true;
        if (m.has_base) { Vn t = tmp(8); emit(Op::Add, t, Vn::r(m.base, 8), acc); acc = t; }
        else if (m.disp != 0) { have = true; }  // acc already the disp const
        if (m.has_index) {
            Vn idx = Vn::r(m.index, 8);
            if (m.scale > 1) { Vn s = tmp(8); emit(Op::Mul, s, idx, Vn::k((long long)m.scale, 8)); idx = s; }
            Vn t = tmp(8); emit(Op::Add, t, acc, idx); acc = t;
        }
        (void)have;
        return acc;
    }

    // Value of an operand (loads memory operands).
    Vn read(const Operand& op) {
        switch (op.kind) {
            case OpKind::Reg: return Vn::r(op.reg, osize(op));
            case OpKind::Imm: return Vn::k(op.imm, osize(op));
            case OpKind::Mem: {
                Vn a = addr_of(op.mem);
                Vn d = tmp(osize(op));
                emit(Op::Load, d, a);
                return d;
            }
            default: return Vn::none();
        }
    }

    // Write `val` to an operand.
    void write(const Operand& op, Vn val) {
        if (op.kind == OpKind::Reg) { emit(Op::Copy, Vn::r(op.reg, osize(op)), val); return; }
        if (op.kind == OpKind::Mem) { Vn a = addr_of(op.mem); emit(Op::Store, Vn::none(), a, val); return; }
    }

    // Flag helpers (mirror builtin_backend.cpp).
    void zsp(Vn res) {
        emit(Op::IsZero, Vn::f(Flag::ZF), res);
        emit(Op::SignBit, Vn::f(Flag::SF), res);
        emit(Op::Parity, Vn::f(Flag::PF), res);
    }
    void flags_add(Vn a, Vn b, Vn res) {
        emit(Op::Carry, Vn::f(Flag::CF), a, b);
        emit(Op::SCarry, Vn::f(Flag::OF), a, b);
        emit(Op::AuxAdd, Vn::f(Flag::AF), a, b);
        zsp(res);
    }
    void flags_sub(Vn a, Vn b, Vn res) {
        emit(Op::Less, Vn::f(Flag::CF), a, b);     // unsigned a<b
        emit(Op::SBorrow, Vn::f(Flag::OF), a, b);
        emit(Op::AuxSub, Vn::f(Flag::AF), a, b);
        zsp(res);
    }
    void flags_logic(Vn res) {
        emit(Op::Copy, Vn::f(Flag::CF), Vn::k(0, 1));
        emit(Op::Copy, Vn::f(Flag::OF), Vn::k(0, 1));
        emit(Op::Copy, Vn::f(Flag::AF), Vn::k(0, 1));
        zsp(res);
    }

    void binop(const DecodedInsn& in, Op op, bool is_add_like, bool is_sub_like, bool logic, bool store = true) {
        Vn a = read(in.operands[0]);
        Vn b = read(in.operands[1]);
        Vn res = tmp(osize(in.operands[0]));
        emit(op, res, a, b);
        // Flags BEFORE the write — a register destination would otherwise be
        // overwritten before the flag ops read its original value.
        if (is_add_like) flags_add(a, b, res);
        else if (is_sub_like) flags_sub(a, b, res);
        else if (logic) flags_logic(res);
        if (store) write(in.operands[0], res);
    }

    void lift(const DecodedInsn& in) {
        const std::string& m = in.mnemonic;
        auto& ops = in.operands;

        if (m == "nop" || m == "endbr64" || m == "endbr32" || m == "pause" ||
            m == "lfence" || m == "mfence" || m == "sfence") return;

        if (m == "mov" || m == "movabs") { write(ops[0], read(ops[1])); return; }
        if (m == "movzx") { Vn d = tmp(osize(ops[0])); emit(Op::Zext, d, read(ops[1])); write(ops[0], d); return; }
        if (m == "movsx" || m == "movsxd") { Vn d = tmp(osize(ops[0])); emit(Op::Sext, d, read(ops[1])); write(ops[0], d); return; }
        if (m == "lea") { write(ops[0], addr_of(ops[1].mem)); return; }

        if (m == "add") { binop(in, Op::Add, true, false, false); return; }
        if (m == "sub") { binop(in, Op::Sub, false, true, false); return; }
        if (m == "and") { binop(in, Op::And, false, false, true); return; }
        if (m == "or")  { binop(in, Op::Or, false, false, true); return; }
        if (m == "xor") { binop(in, Op::Xor, false, false, true); return; }
        if (m == "cmp") { binop(in, Op::Sub, false, true, false, /*store=*/false); return; }
        if (m == "test"){ binop(in, Op::And, false, false, true, /*store=*/false); return; }

        if (m == "inc" || m == "dec") {
            Vn a = read(ops[0]);
            unsigned char sz = osize(ops[0]);
            Vn res = tmp(sz);
            emit(m == "inc" ? Op::Add : Op::Sub, res, a, Vn::k(1, sz));
            // inc/dec affect OF/SF/ZF/AF/PF but NOT CF (flags before the write).
            if (m == "inc") { emit(Op::SCarry, Vn::f(Flag::OF), a, Vn::k(1, sz)); emit(Op::AuxAdd, Vn::f(Flag::AF), a, Vn::k(1, sz)); }
            else { emit(Op::SBorrow, Vn::f(Flag::OF), a, Vn::k(1, sz)); emit(Op::AuxSub, Vn::f(Flag::AF), a, Vn::k(1, sz)); }
            zsp(res);
            write(ops[0], res);
            return;
        }
        if (m == "neg") {
            Vn a = read(ops[0]);
            unsigned char sz = osize(ops[0]);
            Vn res = tmp(sz);
            emit(Op::Sub, res, Vn::k(0, sz), a);
            flags_sub(Vn::k(0, sz), a, res);  // CF = (0<a) = (a!=0), matches x86
            write(ops[0], res);
            return;
        }
        if (m == "not") {  // no flags
            Vn a = read(ops[0]); Vn res = tmp(osize(ops[0]));
            emit(Op::Not, res, a); write(ops[0], res); return;
        }
        if (m == "imul") {
            // One/two-operand forms: lift the two-operand (dst *= src) data effect.
            if (ops.size() >= 2) {
                Vn a = read(ops[0]); Vn b = read(ops[ops.size() - 1]);
                Vn res = tmp(osize(ops[0]));
                emit(Op::Mul, res, a, b);
                write(ops[0], res);
            } else {
                emit(Op::Intrinsic, Vn::none(), Vn::none(), Vn::none(), in.text());
            }
            return;
        }
        if (m == "shl" || m == "sal" || m == "shr" || m == "sar") {
            Vn a = read(ops[0]);
            Vn cnt = ops.size() >= 2 ? read(ops[1]) : Vn::k(1, 1);
            Vn res = tmp(osize(ops[0]));
            emit(m == "shr" ? Op::Shr : m == "sar" ? Op::Sar : Op::Shl, res, a, cnt);
            write(ops[0], res);
            // Shift flags are approximate (ZF/SF/PF from result); CF/OF left as-is.
            zsp(res);
            return;
        }

        if (m == "push") {
            emit(Op::Sub, Vn::r(Reg::Rsp, 8), Vn::r(Reg::Rsp, 8), Vn::k(8, 8));
            emit(Op::Store, Vn::none(), Vn::r(Reg::Rsp, 8), read(ops[0]));
            return;
        }
        if (m == "pop") {
            Vn d = tmp(8);
            emit(Op::Load, d, Vn::r(Reg::Rsp, 8));
            emit(Op::Add, Vn::r(Reg::Rsp, 8), Vn::r(Reg::Rsp, 8), Vn::k(8, 8));
            write(ops[0], d);
            return;
        }

        if (m == "bt") {  // CF = bit[pos] of operand (anti-VM: hypervisor-bit probe)
            unsigned char sz = osize(ops[0]);
            Vn sh = tmp(sz);
            emit(Op::Shr, sh, read(ops[0]), read(ops[1]));
            Vn bit = tmp(1);
            emit(Op::And, bit, sh, Vn::k(1, 1));
            emit(Op::Copy, Vn::f(Flag::CF), bit);
            return;
        }

        if (m == "jmp") { emit(Op::Branch, Vn::none(), read(ops[0])); return; }
        if (in.cf.is_cond_branch) {
            // Condition is a placeholder flag read until data-flow re-fuses it.
            emit(Op::CBranch, Vn::none(), Vn::f(Flag::ZF), read(ops[0]), m);
            return;
        }
        if (m == "call") { emit(Op::Call, Vn::none(), read(ops[0])); return; }
        if (m == "ret") { emit(Op::Return, Vn::none()); return; }

        emit(Op::Intrinsic, Vn::none(), Vn::none(), Vn::none(), in.text());
    }
};

}  // namespace

std::vector<Insn> lift_insn(const DecodedInsn& in) {
    std::vector<Insn> out;
    Lifter lf{out, in.addr};
    lf.lift(in);
    return out;
}

Block lift_block(const BasicBlock& bb) {
    Block b;
    b.start = bb.start;
    Lifter lf{b.code, bb.start};  // one lifter so temp ids are unique across the block
    for (const auto& in : bb.insns) {
        lf.addr = in.addr;
        lf.lift(in);
    }
    return b;
}

}  // namespace dede::ir
