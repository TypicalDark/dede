// SPDX-License-Identifier: Apache-2.0
//
// The forged environment the transparency layer presents to the guest. Every
// value here is chosen to look like ordinary bare-metal hardware, so a sample
// probing for a hypervisor, a debugger, or a sandbox sees nothing unusual.
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "dede/common/types.hpp"

namespace dede {

struct ForgedEnvironment {
    // cpuid leaf 0: vendor string (12 bytes across ebx, edx, ecx).
    std::string vendor = "GenuineIntel";
    u32 max_leaf = 0x16;

    // cpuid leaf 1: family/model/stepping in eax; feature bits.
    u32 leaf1_eax = 0x000906ea;   // a plausible Coffee Lake signature
    u32 leaf1_ecx = 0x7ffafbff;   // hypervisor-present bit (31) deliberately CLEAR
    u32 leaf1_edx = 0xbfebfbff;

    // Hide the hypervisor CPUID leaf range (0x40000000..) entirely.
    bool hide_hypervisor_leaf = true;

    // rdtsc: present a smooth, low-variance clock so timing checks (rdtsc deltas
    // around a suspected single-step) never see the giant gaps instrumentation
    // would otherwise introduce.
    u64 tsc_base = 0x0000'1000'0000'0000ull;
    u64 tsc_per_insn = 30;  // ~30 cycles per retired instruction

    // sidt / sgdt: a believable bare-metal descriptor-table base (a low kernel
    // address rather than the high addresses VMs are famous for), defeating the
    // Red Pill (sidt) and No Pill (sgdt) checks.
    u64 idt_base = 0xfffff800'00000000ull;
    u16 idt_limit = 0x0fff;
    u64 gdt_base = 0xfffff800'00001000ull;
    u16 gdt_limit = 0x007f;

    // sldt / str: LDT and task-register selectors that look like real Windows.
    u16 ldt_selector = 0x0000;
    u16 tr_selector = 0x0040;

    // smsw: a plausible CR0 (PE|MP|ET|NE|WP|AM|PG set).
    u64 cr0 = 0x80050033ull;

    // I/O: deny the VMware backdoor port so the classic `in eax, dx` with magic
    // 0x564D5868 returns nothing useful.
    u16 vmware_backdoor_port = 0x5658;
};

}  // namespace dede
