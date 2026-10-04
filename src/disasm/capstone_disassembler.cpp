// SPDX-License-Identifier: Apache-2.0
//
// Adapter over the Capstone C library. This translation unit is the only place
// in the whole project that includes <capstone/capstone.h>; everyone else sees
// the clean DecodedInsn/IDisassembler types.
#include <capstone/capstone.h>

#include <optional>
#include <stdexcept>
#include <utility>

#include "dede/disasm/disassembler.hpp"

namespace dede {
namespace {

// Map a Capstone x86 register id to our (Reg, Width). Returns nullopt for
// registers the interpreter does not model (high bytes, segment, FPU/SIMD).
std::optional<std::pair<Reg, Width>> map_reg(unsigned cr) {
    switch (cr) {
        case X86_REG_AL:  return {{Reg::Rax, Width::B1}};
        case X86_REG_AX:  return {{Reg::Rax, Width::B2}};
        case X86_REG_EAX: return {{Reg::Rax, Width::B4}};
        case X86_REG_RAX: return {{Reg::Rax, Width::B8}};
        case X86_REG_CL:  return {{Reg::Rcx, Width::B1}};
        case X86_REG_CX:  return {{Reg::Rcx, Width::B2}};
        case X86_REG_ECX: return {{Reg::Rcx, Width::B4}};
        case X86_REG_RCX: return {{Reg::Rcx, Width::B8}};
        case X86_REG_DL:  return {{Reg::Rdx, Width::B1}};
        case X86_REG_DX:  return {{Reg::Rdx, Width::B2}};
        case X86_REG_EDX: return {{Reg::Rdx, Width::B4}};
        case X86_REG_RDX: return {{Reg::Rdx, Width::B8}};
        case X86_REG_BL:  return {{Reg::Rbx, Width::B1}};
        case X86_REG_BX:  return {{Reg::Rbx, Width::B2}};
        case X86_REG_EBX: return {{Reg::Rbx, Width::B4}};
        case X86_REG_RBX: return {{Reg::Rbx, Width::B8}};
        case X86_REG_SPL: return {{Reg::Rsp, Width::B1}};
        case X86_REG_SP:  return {{Reg::Rsp, Width::B2}};
        case X86_REG_ESP: return {{Reg::Rsp, Width::B4}};
        case X86_REG_RSP: return {{Reg::Rsp, Width::B8}};
        case X86_REG_BPL: return {{Reg::Rbp, Width::B1}};
        case X86_REG_BP:  return {{Reg::Rbp, Width::B2}};
        case X86_REG_EBP: return {{Reg::Rbp, Width::B4}};
        case X86_REG_RBP: return {{Reg::Rbp, Width::B8}};
        case X86_REG_SIL: return {{Reg::Rsi, Width::B1}};
        case X86_REG_SI:  return {{Reg::Rsi, Width::B2}};
        case X86_REG_ESI: return {{Reg::Rsi, Width::B4}};
        case X86_REG_RSI: return {{Reg::Rsi, Width::B8}};
        case X86_REG_DIL: return {{Reg::Rdi, Width::B1}};
        case X86_REG_DI:  return {{Reg::Rdi, Width::B2}};
        case X86_REG_EDI: return {{Reg::Rdi, Width::B4}};
        case X86_REG_RDI: return {{Reg::Rdi, Width::B8}};
        case X86_REG_R8B: return {{Reg::R8, Width::B1}};
        case X86_REG_R8W: return {{Reg::R8, Width::B2}};
        case X86_REG_R8D: return {{Reg::R8, Width::B4}};
        case X86_REG_R8:  return {{Reg::R8, Width::B8}};
        case X86_REG_R9B: return {{Reg::R9, Width::B1}};
        case X86_REG_R9W: return {{Reg::R9, Width::B2}};
        case X86_REG_R9D: return {{Reg::R9, Width::B4}};
        case X86_REG_R9:  return {{Reg::R9, Width::B8}};
        case X86_REG_R10B: return {{Reg::R10, Width::B1}};
        case X86_REG_R10W: return {{Reg::R10, Width::B2}};
        case X86_REG_R10D: return {{Reg::R10, Width::B4}};
        case X86_REG_R10:  return {{Reg::R10, Width::B8}};
        case X86_REG_R11B: return {{Reg::R11, Width::B1}};
        case X86_REG_R11W: return {{Reg::R11, Width::B2}};
        case X86_REG_R11D: return {{Reg::R11, Width::B4}};
        case X86_REG_R11:  return {{Reg::R11, Width::B8}};
        case X86_REG_R12B: return {{Reg::R12, Width::B1}};
        case X86_REG_R12W: return {{Reg::R12, Width::B2}};
        case X86_REG_R12D: return {{Reg::R12, Width::B4}};
        case X86_REG_R12:  return {{Reg::R12, Width::B8}};
        case X86_REG_R13B: return {{Reg::R13, Width::B1}};
        case X86_REG_R13W: return {{Reg::R13, Width::B2}};
        case X86_REG_R13D: return {{Reg::R13, Width::B4}};
        case X86_REG_R13:  return {{Reg::R13, Width::B8}};
        case X86_REG_R14B: return {{Reg::R14, Width::B1}};
        case X86_REG_R14W: return {{Reg::R14, Width::B2}};
        case X86_REG_R14D: return {{Reg::R14, Width::B4}};
        case X86_REG_R14:  return {{Reg::R14, Width::B8}};
        case X86_REG_R15B: return {{Reg::R15, Width::B1}};
        case X86_REG_R15W: return {{Reg::R15, Width::B2}};
        case X86_REG_R15D: return {{Reg::R15, Width::B4}};
        case X86_REG_R15:  return {{Reg::R15, Width::B8}};
        case X86_REG_RIP: return {{Reg::Rip, Width::B8}};
        default: return std::nullopt;
    }
}

bool in_group(const cs_insn& ins, u8 grp) {
    for (u8 i = 0; i < ins.detail->groups_count; ++i) {
        if (ins.detail->groups[i] == grp) return true;
    }
    return false;
}

Operand convert_op(const cs_x86_op& op) {
    Operand out;
    out.size = op.size;
    switch (op.type) {
        case X86_OP_REG: {
            out.kind = OpKind::Reg;
            if (auto m = map_reg(op.reg)) {
                out.reg = m->first;
                out.width = m->second;
            } else {
                out.supported = false;
            }
            break;
        }
        case X86_OP_IMM:
            out.kind = OpKind::Imm;
            out.imm = op.imm;
            break;
        case X86_OP_MEM: {
            out.kind = OpKind::Mem;
            out.mem.size = op.size;
            out.mem.scale = static_cast<u32>(op.mem.scale);
            out.mem.disp = op.mem.disp;
            if (op.mem.base != X86_REG_INVALID) {
                if (auto m = map_reg(op.mem.base)) {
                    out.mem.has_base = true;
                    out.mem.base = m->first;
                } else {
                    out.supported = false;
                }
            }
            if (op.mem.index != X86_REG_INVALID) {
                if (auto m = map_reg(op.mem.index)) {
                    out.mem.has_index = true;
                    out.mem.index = m->first;
                } else {
                    out.supported = false;
                }
            }
            if (op.mem.segment != X86_REG_INVALID) {
                out.supported = false;  // segment overrides not modelled
            }
            break;
        }
        default:
            out.supported = false;
            break;
    }
    return out;
}

DecodedInsn convert(const cs_insn& ins) {
    DecodedInsn d;
    d.addr = ins.address;
    d.size = ins.size;
    d.bytes.assign(ins.bytes, ins.bytes + ins.size);
    d.mnemonic = ins.mnemonic;
    d.op_str = ins.op_str;
    d.id = ins.id;
    const cs_x86& x = ins.detail->x86;
    for (u8 i = 0; i < x.op_count; ++i) {
        d.operands.push_back(convert_op(x.operands[i]));
    }
    d.cf.is_call = in_group(ins, CS_GRP_CALL);
    d.cf.is_ret = in_group(ins, CS_GRP_RET);
    d.cf.is_branch = in_group(ins, CS_GRP_JUMP);
    d.cf.is_cond_branch = d.cf.is_branch && ins.id != X86_INS_JMP;
    return d;
}

class CapstoneDisassembler final : public IDisassembler {
public:
    CapstoneDisassembler() {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_) != CS_ERR_OK) {
            throw DedeError("capstone: cs_open failed");
        }
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    }
    ~CapstoneDisassembler() override { cs_close(&handle_); }

    Arch arch() const override { return Arch::X86_64; }

    Result<DecodedInsn> decode_one(const u8* code, std::size_t len, Addr addr) const override {
        cs_insn* insn = nullptr;
        std::size_t n = cs_disasm(handle_, code, len, addr, 1, &insn);
        if (n == 0) {
            if (insn) cs_free(insn, n);
            return make_error("capstone: cannot decode instruction");
        }
        DecodedInsn d = convert(insn[0]);
        cs_free(insn, n);
        return d;
    }

    std::vector<DecodedInsn> decode(const u8* code, std::size_t len, Addr addr,
                                    std::size_t max) const override {
        cs_insn* insn = nullptr;
        std::size_t count = (max == 0) ? 0 : max;  // 0 = decode all
        std::size_t n = cs_disasm(handle_, code, len, addr, count, &insn);
        std::vector<DecodedInsn> out;
        out.reserve(n);
        for (std::size_t i = 0; i < n; ++i) out.push_back(convert(insn[i]));
        if (insn) cs_free(insn, n);
        return out;
    }

private:
    csh handle_{};
};

}  // namespace

std::unique_ptr<IDisassembler> make_disassembler(Arch arch) {
    if (arch != Arch::X86_64) {
        throw DedeError("make_disassembler: only x86-64 is implemented");
    }
    return std::make_unique<CapstoneDisassembler>();
}

// ---- Flyweight decode cache ------------------------------------------------

namespace {
u64 tag_bytes(const u8* code, std::size_t len) {
    // FNV-1a over up to the first 16 bytes — enough to tell code versions apart.
    u64 h = 1469598103934665603ull;
    std::size_t n = len < 16 ? len : 16;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= code[i];
        h *= 1099511628211ull;
    }
    return h;
}
}  // namespace

std::shared_ptr<const DecodedInsn> DecodeCache::at(const u8* code, std::size_t len, Addr addr) {
    Key k{addr, tag_bytes(code, len)};
    auto it = cache_.find(k);
    if (it != cache_.end()) return it->second;
    auto r = disasm_.decode_one(code, len, addr);
    if (!r) return nullptr;
    auto sp = std::make_shared<const DecodedInsn>(std::move(r.value()));
    cache_.emplace(k, sp);
    return sp;
}

void DecodeCache::invalidate(Addr addr) {
    for (auto it = cache_.begin(); it != cache_.end();) {
        it = (it->first.addr == addr) ? cache_.erase(it) : std::next(it);
    }
}

}  // namespace dede
