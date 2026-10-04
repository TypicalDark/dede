// SPDX-License-Identifier: Apache-2.0
//
// The built-in execution backend: a small, fully deterministic interpreter for a
// documented subset of x86-64. It decodes through the same Capstone adapter the
// rest of the tool uses (so disassembly and execution always agree) and routes
// every data access through the memory Proxy (so reads/writes are observed and
// W^X is detected). Determinism is the whole point: given the same state, the
// same memory, and the same injected events, a replay reproduces a run exactly.
//
// Supported today: data movement (mov/movzx/movsx/lea/xchg/push/pop), integer
// arithmetic and logic (add/sub/and/or/xor/inc/dec/neg/not/imul/cmp/test and the
// shifts), control flow (jmp/jcc/call/ret) and the probes that matter for
// anti-analysis (cpuid/rdtsc), plus nop/hlt/syscall/int3. Anything else stops
// the core cleanly with an Unsupported event rather than silently misbehaving.
#include <array>
#include <optional>
#include <string>

#include "dede/core/backend.hpp"

namespace dede {
namespace {

inline u64 mask_bytes(unsigned bytes) {
    return bytes >= 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
}
inline unsigned opsize(const Operand& op) { return op.size ? op.size : 8; }
inline bool parity8(u64 v) {
    v &= 0xff;
    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1;
    return (v & 1) == 0;  // PF set when the number of 1 bits is even
}

void set_zsp(CpuState& c, u64 r, unsigned bytes) {
    unsigned bits = bytes * 8;
    c.set_flag(flags::ZF, (r & mask_bytes(bytes)) == 0);
    c.set_flag(flags::SF, ((r >> (bits - 1)) & 1) != 0);
    c.set_flag(flags::PF, parity8(r));
}

void flags_add(CpuState& c, u64 a, u64 b, u64 r, unsigned bytes) {
    unsigned bits = bytes * 8;
    unsigned __int128 full = (unsigned __int128)(a & mask_bytes(bytes)) + (b & mask_bytes(bytes));
    c.set_flag(flags::CF, ((full >> bits) & 1) != 0);
    bool sa = (a >> (bits - 1)) & 1, sb = (b >> (bits - 1)) & 1, sr = (r >> (bits - 1)) & 1;
    c.set_flag(flags::OF, (sa == sb) && (sr != sa));
    c.set_flag(flags::AF, ((((a & 0xf) + (b & 0xf)) >> 4) & 1) != 0);
    set_zsp(c, r, bytes);
}

void flags_sub(CpuState& c, u64 a, u64 b, u64 r, unsigned bytes) {
    unsigned bits = bytes * 8;
    c.set_flag(flags::CF, (a & mask_bytes(bytes)) < (b & mask_bytes(bytes)));
    bool sa = (a >> (bits - 1)) & 1, sb = (b >> (bits - 1)) & 1, sr = (r >> (bits - 1)) & 1;
    c.set_flag(flags::OF, (sa != sb) && (sr != sa));
    c.set_flag(flags::AF, (a & 0xf) < (b & 0xf));
    set_zsp(c, r, bytes);
}

void flags_logic(CpuState& c, u64 r, unsigned bytes) {
    c.set_flag(flags::CF, false);
    c.set_flag(flags::OF, false);
    c.set_flag(flags::AF, false);
    set_zsp(c, r, bytes);
}

// Sign-extend the low `from_bytes` of v to 64 bits.
u64 sign_extend(u64 v, unsigned from_bytes) {
    if (from_bytes >= 8) return v;
    unsigned bits = from_bytes * 8;
    u64 m = 1ull << (bits - 1);
    v &= mask_bytes(from_bytes);
    return (v ^ m) - m;
}

class BuiltinBackend final : public IExecutionBackend {
public:
    explicit BuiltinBackend(IDisassembler& disasm) : cache_(disasm) {}

    std::string name() const override { return "builtin-x86-64"; }
    Arch arch() const override { return Arch::X86_64; }

    StepOutcome step(CpuState& cpu, MemoryProxy& mem, ITransparency& tr, IEventSink& sink,
                     const ExecContext& ctx) override {
        Addr pc = cpu.rip();
        auto bytes = mem.fetch(pc, 15);
        if (!bytes) return fault(sink, pc, ctx.tick, bytes.message());

        auto insn = cache_.at(bytes.value().data(), bytes.value().size(), pc);
        if (!insn) return unsupported(sink, pc, ctx.tick, "undecodable bytes");

        const DecodedInsn& in = *insn;
        for (const auto& op : in.operands) {
            if (!op.supported) return unsupported(sink, pc, ctx.tick, "unmodelled operand in " + in.text());
        }

        Addr next = in.addr + in.size;
        Exec e{cpu, mem, tr, sink, in, next, ctx.tick};
        StepOutcome r = dispatch(e);
        if (r.status == StepOutcome::Status::Ok && !e.branched) cpu.set_rip(next);
        return r;
    }

private:
    // Per-instruction execution bundle, so helpers don't take eight arguments.
    struct Exec {
        CpuState& cpu;
        MemoryProxy& mem;
        ITransparency& tr;
        IEventSink& sink;
        const DecodedInsn& in;
        Addr next;
        Tick tick;
        bool branched = false;
    };

    static StepOutcome ok() { return {StepOutcome::Status::Ok, {}}; }

    static StepOutcome fault(IEventSink& s, Addr pc, Tick t, const std::string& why) {
        s.emit(Event{EventKind::Fault, pc, 0, 0, 0, t, why});
        return {StepOutcome::Status::Fault, why};
    }
    static StepOutcome unsupported(IEventSink& s, Addr pc, Tick t, const std::string& what) {
        s.emit(Event{EventKind::Unsupported, pc, 0, 0, 0, t, what});
        return {StepOutcome::Status::Unsupported, what};
    }

    Result<Addr> effective_addr(Exec& e, const MemOperand& m) {
        i64 a = m.disp;
        if (m.has_base) {
            a += (m.base == Reg::Rip) ? static_cast<i64>(e.in.addr + e.in.size)
                                      : static_cast<i64>(e.cpu.get(m.base));
        }
        if (m.has_index) a += static_cast<i64>(e.cpu.get(m.index)) * static_cast<i64>(m.scale);
        return static_cast<Addr>(a);
    }

    Result<u64> read_op(Exec& e, const Operand& op) {
        switch (op.kind) {
            case OpKind::Reg: return e.cpu.read(op.reg, op.width);
            case OpKind::Imm: return static_cast<u64>(op.imm) & mask_bytes(opsize(op));
            case OpKind::Mem: {
                auto a = effective_addr(e, op.mem);
                if (!a) return a.error();
                return e.mem.read(a.value(), opsize(op));
            }
            default: return make_error("read_op: bad operand");
        }
    }

    Result<void> write_op(Exec& e, const Operand& op, u64 v) {
        switch (op.kind) {
            case OpKind::Reg: e.cpu.write(op.reg, op.width, v); return {};
            case OpKind::Mem: {
                auto a = effective_addr(e, op.mem);
                if (!a) return a.error();
                return e.mem.write(a.value(), opsize(op), v);
            }
            default: return make_error("write_op: not an lvalue");
        }
    }

    // --- stack helpers -------------------------------------------------------
    Result<void> push64(Exec& e, u64 v) {
        u64 sp = e.cpu.get(Reg::Rsp) - 8;
        e.cpu.set(Reg::Rsp, sp);
        return e.mem.write(sp, 8, v);
    }
    Result<u64> pop64(Exec& e) {
        u64 sp = e.cpu.get(Reg::Rsp);
        auto v = e.mem.read(sp, 8);
        if (!v) return v;
        e.cpu.set(Reg::Rsp, sp + 8);
        return v;
    }

    Result<Addr> branch_target(Exec& e) {
        const Operand& op = e.in.operands.at(0);
        if (op.kind == OpKind::Imm) return static_cast<Addr>(op.imm);  // capstone gives absolute
        auto v = read_op(e, op);
        if (!v) return v.error();
        return static_cast<Addr>(v.value());
    }

    bool cond(const std::string& m, const CpuState& c) {
        bool zf = c.flag(flags::ZF), cf = c.flag(flags::CF), sf = c.flag(flags::SF);
        bool of = c.flag(flags::OF), pf = c.flag(flags::PF);
        if (m == "je" || m == "jz") return zf;
        if (m == "jne" || m == "jnz") return !zf;
        if (m == "js") return sf;
        if (m == "jns") return !sf;
        if (m == "jo") return of;
        if (m == "jno") return !of;
        if (m == "jp" || m == "jpe") return pf;
        if (m == "jnp" || m == "jpo") return !pf;
        if (m == "jb" || m == "jc" || m == "jnae") return cf;
        if (m == "jae" || m == "jnc" || m == "jnb") return !cf;
        if (m == "jbe" || m == "jna") return cf || zf;
        if (m == "ja" || m == "jnbe") return !cf && !zf;
        if (m == "jl" || m == "jnge") return sf != of;
        if (m == "jge" || m == "jnl") return sf == of;
        if (m == "jle" || m == "jng") return zf || (sf != of);
        if (m == "jg" || m == "jnle") return !zf && (sf == of);
        return false;
    }

    // --- the dispatch table --------------------------------------------------
    StepOutcome dispatch(Exec& e) {
        const std::string& m = e.in.mnemonic;
        auto& ops = e.in.operands;

        // Control flow -------------------------------------------------------
        if (m == "jmp") {
            auto t = branch_target(e);
            if (!t) return fault(e.sink, e.in.addr, e.tick, t.message());
            e.cpu.set_rip(t.value()); e.branched = true; return ok();
        }
        if (e.in.cf.is_cond_branch) {
            if (cond(m, e.cpu)) {
                auto t = branch_target(e);
                if (!t) return fault(e.sink, e.in.addr, e.tick, t.message());
                e.cpu.set_rip(t.value()); e.branched = true;
            }
            return ok();  // not taken: fall through to `next`
        }
        if (m == "call") {
            auto t = branch_target(e);
            if (!t) return fault(e.sink, e.in.addr, e.tick, t.message());
            if (auto r = push64(e, e.next); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            e.cpu.set_rip(t.value()); e.branched = true; return ok();
        }
        if (m == "ret") {
            auto v = pop64(e);
            if (!v) return fault(e.sink, e.in.addr, e.tick, v.message());
            if (!ops.empty() && ops[0].kind == OpKind::Imm)
                e.cpu.set(Reg::Rsp, e.cpu.get(Reg::Rsp) + static_cast<u64>(ops[0].imm));
            e.cpu.set_rip(v.value()); e.branched = true; return ok();
        }

        // Data movement ------------------------------------------------------
        if (m == "nop") return ok();
        if (m == "mov" || m == "movabs")
            return rr(e, [&](u64, u64 s) { return s; }, /*write*/ true, /*use_dst*/ false);
        if (m == "lea") {
            auto a = effective_addr(e, ops.at(1).mem);
            if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
            if (auto r = write_op(e, ops[0], a.value()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }
        if (m == "movzx" || m == "movsx" || m == "movsxd") {
            auto s = read_op(e, ops.at(1));
            if (!s) return fault(e.sink, e.in.addr, e.tick, s.message());
            u64 v = (m == "movzx") ? s.value() : sign_extend(s.value(), opsize(ops[1]));
            if (auto r = write_op(e, ops[0], v); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }
        if (m == "xchg") {
            auto a = read_op(e, ops.at(0)); auto b = read_op(e, ops.at(1));
            if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
            if (!b) return fault(e.sink, e.in.addr, e.tick, b.message());
            if (auto r = write_op(e, ops[0], b.value()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            if (auto r = write_op(e, ops[1], a.value()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }
        if (m == "push") {
            auto v = read_op(e, ops.at(0));
            if (!v) return fault(e.sink, e.in.addr, e.tick, v.message());
            if (auto r = push64(e, v.value()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }
        if (m == "pop") {
            auto v = pop64(e);
            if (!v) return fault(e.sink, e.in.addr, e.tick, v.message());
            if (auto r = write_op(e, ops.at(0), v.value()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }

        // Arithmetic / logic -------------------------------------------------
        if (m == "add") return alu(e, Alu::Add);
        if (m == "sub") return alu(e, Alu::Sub);
        if (m == "and") return alu(e, Alu::And);
        if (m == "or")  return alu(e, Alu::Or);
        if (m == "xor") return alu(e, Alu::Xor);
        if (m == "cmp") return alu(e, Alu::Cmp);
        if (m == "test") return alu(e, Alu::Test);
        if (m == "inc" || m == "dec") return incdec(e, m == "inc");
        if (m == "neg") return neg(e);
        if (m == "not") {
            auto a = read_op(e, ops.at(0));
            if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
            if (auto r = write_op(e, ops[0], ~a.value()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }
        if (m == "imul") return imul(e);
        if (m == "shl" || m == "sal" || m == "shr" || m == "sar") return shift(e, m);

        // Probes / specials --------------------------------------------------
        if (m == "cpuid") return do_cpuid(e);
        if (m == "rdtsc") return do_rdtsc(e);
        if (m == "hlt") {
            e.sink.emit(Event{EventKind::Halt, e.in.addr, 0, 0, 0, e.tick, "hlt"});
            return {StepOutcome::Status::Halted, "hlt"};
        }
        if (m == "syscall" || m == "sysenter") {
            e.sink.emit(Event{EventKind::Syscall, e.in.addr, 0, e.cpu.get(Reg::Rax), 0, e.tick, "syscall"});
            return ok();
        }
        if (m == "int3" || (m == "int" && !ops.empty() && ops[0].kind == OpKind::Imm && ops[0].imm == 3)) {
            e.cpu.set_rip(e.next); e.branched = true;  // step past the trap byte
            e.sink.emit(Event{EventKind::Breakpoint, e.in.addr, 0, 0, 0, e.tick, "guest int3"});
            return {StepOutcome::Status::Breakpoint, "guest int3"};
        }
        if (m == "int") {
            e.sink.emit(Event{EventKind::Syscall, e.in.addr, 0,
                              ops.empty() ? 0 : static_cast<u64>(ops[0].imm), 0, e.tick, "int"});
            return ok();
        }

        return unsupported(e.sink, e.in.addr, e.tick, "unsupported mnemonic: " + e.in.text());
    }

    // mov-style: compute value and write to dst.
    template <typename F>
    StepOutcome rr(Exec& e, F fn, bool write, bool use_dst) {
        auto& ops = e.in.operands;
        u64 d = 0;
        if (use_dst) {
            auto dr = read_op(e, ops.at(0));
            if (!dr) return fault(e.sink, e.in.addr, e.tick, dr.message());
            d = dr.value();
        }
        auto s = read_op(e, ops.at(1));
        if (!s) return fault(e.sink, e.in.addr, e.tick, s.message());
        u64 v = fn(d, s.value());
        if (write) {
            if (auto r = write_op(e, ops[0], v); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        }
        return ok();
    }

    enum class Alu { Add, Sub, And, Or, Xor, Cmp, Test };
    StepOutcome alu(Exec& e, Alu kind) {
        auto& ops = e.in.operands;
        unsigned bytes = opsize(ops.at(0));
        auto a = read_op(e, ops[0]);
        auto b = read_op(e, ops.at(1));
        if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
        if (!b) return fault(e.sink, e.in.addr, e.tick, b.message());
        u64 av = a.value(), bv = b.value(), res = 0;
        bool store = true;
        switch (kind) {
            case Alu::Add: res = av + bv; flags_add(e.cpu, av, bv, res, bytes); break;
            case Alu::Sub: res = av - bv; flags_sub(e.cpu, av, bv, res, bytes); break;
            case Alu::Cmp: res = av - bv; flags_sub(e.cpu, av, bv, res, bytes); store = false; break;
            case Alu::And: res = av & bv; flags_logic(e.cpu, res, bytes); break;
            case Alu::Or:  res = av | bv; flags_logic(e.cpu, res, bytes); break;
            case Alu::Xor: res = av ^ bv; flags_logic(e.cpu, res, bytes); break;
            case Alu::Test: res = av & bv; flags_logic(e.cpu, res, bytes); store = false; break;
        }
        if (store) {
            if (auto r = write_op(e, ops[0], res); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        }
        return ok();
    }

    StepOutcome incdec(Exec& e, bool inc) {
        auto& ops = e.in.operands;
        unsigned bytes = opsize(ops.at(0));
        auto a = read_op(e, ops[0]);
        if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
        bool cf = e.cpu.flag(flags::CF);  // inc/dec leave CF untouched
        u64 res = inc ? a.value() + 1 : a.value() - 1;
        inc ? flags_add(e.cpu, a.value(), 1, res, bytes) : flags_sub(e.cpu, a.value(), 1, res, bytes);
        e.cpu.set_flag(flags::CF, cf);
        if (auto r = write_op(e, ops[0], res); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        return ok();
    }

    StepOutcome neg(Exec& e) {
        auto& ops = e.in.operands;
        unsigned bytes = opsize(ops.at(0));
        auto a = read_op(e, ops[0]);
        if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
        u64 res = 0 - a.value();
        flags_sub(e.cpu, 0, a.value(), res, bytes);
        if (auto r = write_op(e, ops[0], res); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        return ok();
    }

    StepOutcome imul(Exec& e) {
        auto& ops = e.in.operands;
        unsigned bytes = opsize(ops.at(0));
        __int128 lhs = 0, rhs = 0;
        if (ops.size() == 3) {
            auto s = read_op(e, ops[1]); auto i = read_op(e, ops[2]);
            if (!s) return fault(e.sink, e.in.addr, e.tick, s.message());
            if (!i) return fault(e.sink, e.in.addr, e.tick, i.message());
            lhs = (__int128)(i64)sign_extend(s.value(), opsize(ops[1]));
            rhs = (__int128)(i64)sign_extend(i.value(), opsize(ops[2]));
        } else {  // 2-operand: dst *= src
            auto d = read_op(e, ops[0]); auto s = read_op(e, ops.at(1));
            if (!d) return fault(e.sink, e.in.addr, e.tick, d.message());
            if (!s) return fault(e.sink, e.in.addr, e.tick, s.message());
            lhs = (__int128)(i64)sign_extend(d.value(), bytes);
            rhs = (__int128)(i64)sign_extend(s.value(), opsize(ops[1]));
        }
        __int128 full = lhs * rhs;
        u64 res = (u64)full & mask_bytes(bytes);
        bool overflow = (full != (__int128)(i64)sign_extend(res, bytes));
        e.cpu.set_flag(flags::CF, overflow);
        e.cpu.set_flag(flags::OF, overflow);
        if (auto r = write_op(e, ops[0], res); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        return ok();
    }

    StepOutcome shift(Exec& e, const std::string& m) {
        auto& ops = e.in.operands;
        unsigned bytes = opsize(ops.at(0));
        unsigned bits = bytes * 8;
        auto a = read_op(e, ops[0]);
        if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
        unsigned cnt;
        if (ops.size() >= 2) {
            auto c = read_op(e, ops[1]);
            if (!c) return fault(e.sink, e.in.addr, e.tick, c.message());
            cnt = static_cast<unsigned>(c.value());
        } else {
            cnt = 1;
        }
        cnt &= (bytes == 8) ? 63u : 31u;
        u64 av = a.value() & mask_bytes(bytes), res = av;
        if (cnt != 0) {
            if (m == "shl" || m == "sal") {
                res = (av << cnt);
                e.cpu.set_flag(flags::CF, ((av >> (bits - cnt)) & 1) != 0);
            } else if (m == "shr") {
                res = (av >> cnt);
                e.cpu.set_flag(flags::CF, ((av >> (cnt - 1)) & 1) != 0);
            } else {  // sar
                res = (u64)(sign_extend(av, bytes) >> cnt);
                e.cpu.set_flag(flags::CF, ((av >> (cnt - 1)) & 1) != 0);
            }
            set_zsp(e.cpu, res, bytes);
        }
        if (auto r = write_op(e, ops[0], res); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        return ok();
    }

    StepOutcome do_cpuid(Exec& e) {
        u64 leaf = e.cpu.get(Reg::Rax), sub = e.cpu.get(Reg::Rcx);
        ProbeResult pr = e.tr.handle(ProbeRequest{ProbeRequest::Kind::Cpuid, leaf, sub, 0, e.tick});
        u64 a, b, c, d;
        if (pr.handled) {
            a = pr.a; b = pr.b; c = pr.c; d = pr.d;
        } else {
            // A plausible, deterministic default CPU with no hypervisor bit set.
            a = 0; b = 0; c = 0; d = 0;
            if (leaf == 0) { a = 0x16; b = 0x756e6547; d = 0x49656e69; c = 0x6c65746e; }  // "GenuineIntel"
            else if (leaf == 1) { a = 0x000906ea; c = 0x7ffafbff; d = 0xbfebfbff; }        // no ECX bit 31
        }
        e.cpu.write(Reg::Rax, Width::B4, a);
        e.cpu.write(Reg::Rbx, Width::B4, b);
        e.cpu.write(Reg::Rcx, Width::B4, c);
        e.cpu.write(Reg::Rdx, Width::B4, d);
        e.sink.emit(Event{EventKind::Cpuid, e.in.addr, 0, leaf, 0, e.tick, "cpuid"});
        return ok();
    }

    StepOutcome do_rdtsc(Exec& e) {
        ProbeResult pr = e.tr.handle(ProbeRequest{ProbeRequest::Kind::Rdtsc, 0, 0, 0, e.tick});
        u64 lo, hi;
        if (pr.handled) {
            lo = pr.a; hi = pr.d;
        } else {
            u64 tsc = e.tick;  // deterministic by construction => replay-safe
            lo = tsc & 0xffffffff; hi = tsc >> 32;
        }
        e.cpu.write(Reg::Rax, Width::B4, lo);
        e.cpu.write(Reg::Rdx, Width::B4, hi);
        e.sink.emit(Event{EventKind::Rdtsc, e.in.addr, 0, 0, 0, e.tick, "rdtsc"});
        return ok();
    }

    DecodeCache cache_;  // Flyweight: shares decodes, versioned for SMC
};

}  // namespace

std::unique_ptr<IExecutionBackend> make_builtin_backend(IDisassembler& disasm) {
    return std::make_unique<BuiltinBackend>(disasm);
}

}  // namespace dede
