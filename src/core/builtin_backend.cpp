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
#include <stdexcept>
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
        std::array<u8, 15> code;
        auto nread = mem.fetch(pc, code.data(), static_cast<unsigned>(code.size()));
        if (!nread) return fault(sink, pc, ctx.tick, nread.message());

        auto insn = cache_.at(code.data(), nread.value(), pc);
        if (!insn) return unsupported(sink, pc, ctx.tick, "undecodable bytes");

        const DecodedInsn& in = *insn;
        for (const auto& op : in.operands) {
            if (!op.supported) return unsupported(sink, pc, ctx.tick, "unmodelled operand in " + in.text());
        }

        Addr next = in.addr + in.size;
        Exec e{cpu, mem, tr, sink, in, next, ctx.tick};
        // Safety net: a decode/model operand-count mismatch (e.g. an instruction
        // form we don't expect) must degrade to Unsupported, never crash the tool
        // on a hostile sample.
        StepOutcome r;
        try {
            r = dispatch(e);
        } catch (const std::exception& ex) {
            return unsupported(sink, pc, ctx.tick,
                               std::string("internal: ") + ex.what() + " on " + in.text());
        }
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

    static Seg to_seg(SegReg s) { return static_cast<Seg>(static_cast<u8>(s)); }

    Result<u64> read_op(Exec& e, const Operand& op) {
        switch (op.kind) {
            case OpKind::Reg: return e.cpu.read(op.reg, op.width);
            case OpKind::SegReg: return static_cast<u64>(e.cpu.seg(to_seg(op.seg)));
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
            case OpKind::SegReg: e.cpu.set_seg(to_seg(op.seg), static_cast<u16>(v)); return {};
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

    // Evaluate an x86 condition code by its suffix (the part after j/set/cmov),
    // so jcc, setcc, and cmovcc all share one table.
    bool eval_cc(const std::string& cc, const CpuState& c) {
        bool zf = c.flag(flags::ZF), cf = c.flag(flags::CF), sf = c.flag(flags::SF);
        bool of = c.flag(flags::OF), pf = c.flag(flags::PF);
        if (cc == "e" || cc == "z") return zf;
        if (cc == "ne" || cc == "nz") return !zf;
        if (cc == "s") return sf;
        if (cc == "ns") return !sf;
        if (cc == "o") return of;
        if (cc == "no") return !of;
        if (cc == "p" || cc == "pe") return pf;
        if (cc == "np" || cc == "po") return !pf;
        if (cc == "b" || cc == "c" || cc == "nae") return cf;
        if (cc == "ae" || cc == "nc" || cc == "nb") return !cf;
        if (cc == "be" || cc == "na") return cf || zf;
        if (cc == "a" || cc == "nbe") return !cf && !zf;
        if (cc == "l" || cc == "nge") return sf != of;
        if (cc == "ge" || cc == "nl") return sf == of;
        if (cc == "le" || cc == "ng") return zf || (sf != of);
        if (cc == "g" || cc == "nle") return !zf && (sf == of);
        return false;
    }

    bool cond(const std::string& m, const CpuState& c) {
        return m.size() > 1 && eval_cc(m.substr(1), c);  // strip the leading 'j'
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
        if (m == "rdtscp") return do_rdtsc(e, /*p=*/true);

        // Anti-analysis probes the transparency layer forges -----------------
        if (m == "sidt") return store_dtr(e, ProbeRequest::Kind::Sidt);
        if (m == "sgdt") return store_dtr(e, ProbeRequest::Kind::Sgdt);
        if (m == "sldt") return store_status(e, ProbeRequest::Kind::Sldt);
        if (m == "str")  return store_status(e, ProbeRequest::Kind::Str);
        if (m == "smsw") return store_status(e, ProbeRequest::Kind::Smsw);
        if (m == "in")   return do_in(e);
        if (m == "out")  return do_out(e);

        // Flags / conditionals / misc ----------------------------------------
        if (m == "pushfq" || m == "pushf") {
            unsigned sz = (m == "pushfq") ? 8 : 2;
            u64 sp = e.cpu.get(Reg::Rsp) - sz;
            e.cpu.set(Reg::Rsp, sp);
            if (auto r = e.mem.write(sp, sz, e.cpu.rflags()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }
        if (m == "popfq" || m == "popf") {
            unsigned sz = (m == "popfq") ? 8 : 2;
            u64 sp = e.cpu.get(Reg::Rsp);
            auto v = e.mem.read(sp, sz);
            if (!v) return fault(e.sink, e.in.addr, e.tick, v.message());
            e.cpu.set(Reg::Rsp, sp + sz);
            // We never act on TF, so a sample cannot detect single-stepping via it.
            e.cpu.set_rflags(v.value());
            return ok();
        }
        if (m == "bt") return do_bt(e);
        if (m.rfind("set", 0) == 0 && m.size() > 3) {  // setcc r/m8
            bool c = eval_cc(m.substr(3), e.cpu);
            if (auto r = write_op(e, ops.at(0), c ? 1 : 0); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            return ok();
        }
        if (m.rfind("cmov", 0) == 0 && m.size() > 4) {  // cmovcc dst, src
            if (eval_cc(m.substr(4), e.cpu)) {
                auto s = read_op(e, ops.at(1));
                if (!s) return fault(e.sink, e.in.addr, e.tick, s.message());
                if (auto r = write_op(e, ops[0], s.value()); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            }
            return ok();
        }
        if (m == "rdrand" || m == "rdseed") {
            // Deterministic by construction so replay is exact; CF=1 (success).
            u64 x = e.tick + 0x9e3779b97f4a7c15ull;
            x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
            x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
            x ^= x >> 31;
            if (auto r = write_op(e, ops.at(0), x); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
            e.cpu.set_flag(flags::CF, true);
            return ok();
        }
        // Serialising / hint instructions with no architectural state effect.
        if (m == "lfence" || m == "mfence" || m == "sfence" || m == "pause" ||
            m == "cpuid_" /*never*/ || m == "clflush" || m == "clflushopt" ||
            m == "prefetch" || m == "prefetcht0" || m == "prefetcht1" ||
            m == "prefetcht2" || m == "prefetchnta" || m == "endbr64" || m == "endbr32") {
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
        if (ops.empty()) return unsupported(e.sink, e.in.addr, e.tick, "imul with no operands");
        unsigned bytes = opsize(ops[0]);
        __int128 lhs = 0, rhs = 0;

        if (ops.size() == 1) {  // one-operand: rdx:rax = rax * r/m
            auto s = read_op(e, ops[0]);
            if (!s) return fault(e.sink, e.in.addr, e.tick, s.message());
            lhs = (__int128)(i64)sign_extend(e.cpu.read(Reg::Rax, static_cast<Width>(bytes)), bytes);
            rhs = (__int128)(i64)sign_extend(s.value(), bytes);
            __int128 full = lhs * rhs;
            unsigned bits = bytes * 8;
            u64 lo = (u64)full & mask_bytes(bytes);
            u64 hi = (u64)(full >> bits) & mask_bytes(bytes);
            e.cpu.write(Reg::Rax, static_cast<Width>(bytes), lo);
            e.cpu.write(Reg::Rdx, static_cast<Width>(bytes), hi);
            bool of = (hi != ((i64)lo < 0 ? mask_bytes(bytes) : 0));
            e.cpu.set_flag(flags::CF, of);
            e.cpu.set_flag(flags::OF, of);
            return ok();
        }
        if (ops.size() == 3) {
            auto s = read_op(e, ops[1]); auto i = read_op(e, ops[2]);
            if (!s) return fault(e.sink, e.in.addr, e.tick, s.message());
            if (!i) return fault(e.sink, e.in.addr, e.tick, i.message());
            lhs = (__int128)(i64)sign_extend(s.value(), opsize(ops[1]));
            rhs = (__int128)(i64)sign_extend(i.value(), opsize(ops[2]));
        } else {  // 2-operand: dst *= src
            auto d = read_op(e, ops[0]); auto s = read_op(e, ops[1]);
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
        cnt &= (bytes == 8) ? 63u : 31u;  // x86 masks the count (0x1f / 0x3f)
        u64 av = a.value() & mask_bytes(bytes), res = av;
        if (cnt != 0) {
            if (m == "shl" || m == "sal") {
                res = (av << cnt);
                // The count can exceed the operand width (e.g. shl al, 31): all
                // bits then shift out and CF is 0. Guard bits-cnt against underflow.
                e.cpu.set_flag(flags::CF, cnt <= bits ? ((av >> (bits - cnt)) & 1) != 0 : false);
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

    StepOutcome do_rdtsc(Exec& e, bool p = false) {
        auto kind = p ? ProbeRequest::Kind::Rdtscp : ProbeRequest::Kind::Rdtsc;
        ProbeResult pr = e.tr.handle(ProbeRequest{kind, 0, 0, 0, e.tick});
        u64 lo, hi, aux = 0;
        if (pr.handled) {
            lo = pr.a; hi = pr.d; aux = pr.c;
        } else {
            u64 tsc = e.tick;  // deterministic by construction => replay-safe
            lo = tsc & 0xffffffff; hi = tsc >> 32;
        }
        e.cpu.write(Reg::Rax, Width::B4, lo);
        e.cpu.write(Reg::Rdx, Width::B4, hi);
        if (p) e.cpu.write(Reg::Rcx, Width::B4, aux);  // rdtscp also sets ecx
        e.sink.emit(Event{EventKind::Rdtsc, e.in.addr, 0, 0, 0, e.tick, p ? "rdtscp" : "rdtsc"});
        return ok();
    }

    // sidt/sgdt: store a 2-byte limit + 8-byte base (m16&64) to the destination.
    StepOutcome store_dtr(Exec& e, ProbeRequest::Kind kind) {
        auto& op = e.in.operands.at(0);
        if (op.kind != OpKind::Mem) return unsupported(e.sink, e.in.addr, e.tick, "sidt/sgdt needs a memory operand");
        auto a = effective_addr(e, op.mem);
        if (!a) return fault(e.sink, e.in.addr, e.tick, a.message());
        ProbeResult pr = e.tr.handle(ProbeRequest{kind, 0, 0, 0, e.tick});
        u16 limit = pr.handled ? static_cast<u16>(pr.a) : 0x0fff;
        u64 base = pr.handled ? ((pr.c << 32) | (pr.b & 0xffffffffull)) : 0xfffff80000000000ull;
        if (auto r = e.mem.write(a.value(), 2, limit); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        if (auto r = e.mem.write(a.value() + 2, 8, base); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        return ok();
    }

    // sldt/str/smsw: store a forged selector / machine-status word. Even with no
    // transparency chain, fall back to bare-metal-looking defaults.
    StepOutcome store_status(Exec& e, ProbeRequest::Kind kind) {
        ProbeResult pr = e.tr.handle(ProbeRequest{kind, 0, 0, 0, e.tick});
        u64 v;
        if (pr.handled) {
            v = pr.a;
        } else {
            v = (kind == ProbeRequest::Kind::Str)    ? 0x40
              : (kind == ProbeRequest::Kind::Smsw)   ? 0x80050033ull
              : 0;  // sldt
        }
        if (auto r = write_op(e, e.in.operands.at(0), v); !r) return fault(e.sink, e.in.addr, e.tick, r.message());
        return ok();
    }

    StepOutcome do_in(Exec& e) {
        auto& ops = e.in.operands;
        u64 port = (ops.size() >= 2) ? ((ops[1].kind == OpKind::Imm) ? static_cast<u64>(ops[1].imm)
                                                                     : e.cpu.get(Reg::Rdx) & 0xffff)
                                     : (e.cpu.get(Reg::Rdx) & 0xffff);
        ProbeResult pr = e.tr.handle(ProbeRequest{ProbeRequest::Kind::IoIn, 0, 0, port, e.tick});
        if (auto r = write_op(e, ops.at(0), pr.handled ? pr.a : 0); !r)
            return fault(e.sink, e.in.addr, e.tick, r.message());
        return ok();
    }

    StepOutcome do_out(Exec& e) {
        // Writes to a port: consulted for side effects only; nothing to store back.
        e.tr.handle(ProbeRequest{ProbeRequest::Kind::IoOut, 0, 0, e.cpu.get(Reg::Rdx) & 0xffff, e.tick});
        return ok();
    }

    // bt r/m, bit : set CF to the selected bit (no write-back).
    StepOutcome do_bt(Exec& e) {
        auto& ops = e.in.operands;
        unsigned bits = opsize(ops.at(0)) * 8;
        auto base = read_op(e, ops[0]);
        auto idx = read_op(e, ops.at(1));
        if (!base) return fault(e.sink, e.in.addr, e.tick, base.message());
        if (!idx) return fault(e.sink, e.in.addr, e.tick, idx.message());
        unsigned bit = static_cast<unsigned>(idx.value()) % (bits ? bits : 64);
        e.cpu.set_flag(flags::CF, ((base.value() >> bit) & 1) != 0);
        return ok();
    }

    DecodeCache cache_;  // Flyweight: shares decodes, versioned for SMC
};

}  // namespace

std::unique_ptr<IExecutionBackend> make_builtin_backend(IDisassembler& disasm) {
    return std::make_unique<BuiltinBackend>(disasm);
}

}  // namespace dede
