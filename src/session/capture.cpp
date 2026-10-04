// SPDX-License-Identifier: Apache-2.0
#include "dede/session/capture.hpp"

#include <sstream>
#include <unordered_map>

namespace dede {

std::string syscall_name(u64 n) {
    static const std::unordered_map<u64, const char*> t = {
        {0, "read"},     {1, "write"},    {2, "open"},     {3, "close"},
        {9, "mmap"},     {10, "mprotect"},{11, "munmap"},  {12, "brk"},
        {41, "socket"},  {42, "connect"}, {43, "accept"},  {44, "sendto"},
        {45, "recvfrom"},{46, "sendmsg"}, {47, "recvmsg"}, {49, "bind"},
        {50, "listen"},  {59, "execve"},  {60, "exit"},    {62, "kill"},
        {101, "ptrace"}, {102, "getuid"}, {186, "gettid"}, {201, "time"},
        {228, "clock_gettime"}, {231, "exit_group"}, {257, "openat"},
        {318, "getrandom"},
    };
    auto it = t.find(n);
    if (it != t.end()) return it->second;
    return "sys_" + std::to_string(n);
}

void CaptureTap::on_event(const Event& e) {
    if (!enabled_) return;
    CaptureEntry ce;
    ce.tick = e.tick;
    ce.pc = e.pc;
    if (e.kind == EventKind::Syscall) {
        ce.kind = CapKind::Syscall;
        ce.number = regs_(Reg::Rax);
        ce.name = syscall_name(ce.number);
        // SysV x86-64 argument order.
        ce.args = {regs_(Reg::Rdi), regs_(Reg::Rsi), regs_(Reg::Rdx),
                   regs_(Reg::R10), regs_(Reg::R8), regs_(Reg::R9)};
        std::ostringstream o;
        o << ce.name << "(0x" << std::hex << ce.args[0] << ", 0x" << ce.args[1]
          << ", 0x" << ce.args[2] << ")";
        ce.summary = o.str();
    } else if (e.kind == EventKind::Cpuid) {
        ce.kind = CapKind::Cpuid;
        ce.number = e.value;  // leaf
        ce.name = "cpuid";
        std::ostringstream o;
        o << "cpuid(leaf=0x" << std::hex << e.value << ")";
        ce.summary = o.str();
    } else if (e.kind == EventKind::Rdtsc) {
        ce.kind = CapKind::Rdtsc;
        ce.name = "rdtsc";
        ce.summary = "rdtsc";
    } else {
        return;  // not an external-interaction event
    }
    ce.seq = seq_++;
    entries_.push_back(std::move(ce));
}

std::string CaptureTap::to_text() const {
    std::ostringstream o;
    for (const auto& e : entries_)
        o << "#" << e.seq << " [t=" << e.tick << "] @0x" << std::hex << e.pc << std::dec
          << "  " << e.summary << "\n";
    return o.str();
}

std::string CaptureTap::to_json() const {
    std::ostringstream o;
    o << "[\n";
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const auto& e = entries_[i];
        o << "  {\"seq\":" << e.seq << ",\"tick\":" << e.tick << ",\"pc\":" << e.pc
          << ",\"name\":\"" << e.name << "\",\"number\":" << e.number
          << ",\"args\":[" << e.args[0] << "," << e.args[1] << "," << e.args[2] << ","
          << e.args[3] << "," << e.args[4] << "," << e.args[5] << "]}"
          << (i + 1 < entries_.size() ? "," : "") << "\n";
    }
    o << "]\n";
    return o.str();
}

}  // namespace dede
