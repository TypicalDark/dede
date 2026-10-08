// SPDX-License-Identifier: Apache-2.0
//
// Linux x86-64 user-mode environment (Batch 9, T9.L1/T9.L2). Models a core
// syscall surface so a statically-linked ELF runs to completion under dede's
// deterministic interpreter: memory (mmap/mprotect/munmap/brk), I/O
// (read/write/writev/close/openat), TLS (arch_prctl → fs base), and process
// control (exit/exit_group/getpid/nanosleep). Everything is forged in a
// pre-mapped arena — no host FS/network is touched — and I/O is MITM-able: bytes
// a program writes are captured (observable "stdout"), and bytes it reads come
// from a queue the analyst can pre-feed. All effects go through IDebugController,
// so the run is time-travel-correct and bit-for-bit replayable.
#pragma once

#include <map>
#include <string>
#include <vector>

#include "dede/os/os_env.hpp"

namespace dede::os {

class LinuxEnvironment : public IOsEnvironment {
public:
    struct Region { Addr addr; u64 size; Tick since; };

    // The arena [base, base+size) must already be mapped RWX by the caller; brk
    // grows from the low half, mmap bump-allocates from the high half.
    LinuxEnvironment(Addr arena_base, u64 arena_size)
        : base_(arena_base), mid_(arena_base + arena_size / 2),
          end_(arena_base + arena_size), brk_(arena_base + arena_size / 2),
          mmap_next_(arena_base + arena_size / 2) {}

    std::string name() const override { return "linux-x86_64"; }
    void on_syscall(IDebugController& c) override;
    const std::vector<SyscallEvent>& log() const override { return log_; }

    // --- MITM / observation --------------------------------------------------
    void feed_input(int fd, std::vector<u8> bytes);          // bytes a future read(fd,...) returns
    std::vector<u8> output(int fd) const;                    // bytes the guest wrote to fd (e.g. stdout=1)
    const std::vector<Region>& mmap_regions() const { return regions_; }
    bool exited() const { return exited_; }
    i64 exit_code() const { return exit_code_; }
    std::size_t syscall_count() const { return log_.size(); }

private:
    i64 dispatch(IDebugController& c, long nr, const std::array<u64, 6>& a, std::vector<u8>& data);
    std::string read_cstr(IDebugController& c, Addr p, std::size_t cap = 256) const;

    Addr base_, mid_, end_, brk_, mmap_next_;
    int next_fd_ = 3;
    bool exited_ = false;
    i64 exit_code_ = 0;
    std::map<int, std::vector<u8>> out_;    // captured writes per fd
    std::map<int, std::vector<u8>> in_;     // queued input per fd (consumed by read)
    std::map<int, std::string> fd_path_;    // open fd -> path
    std::vector<Region> regions_;
    std::vector<SyscallEvent> log_;
};

}  // namespace dede::os
