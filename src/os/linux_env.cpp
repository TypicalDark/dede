// SPDX-License-Identifier: Apache-2.0
#include "dede/os/linux_env.hpp"

#include <algorithm>

namespace dede::os {
namespace {
// Linux x86-64 syscall numbers (the subset we model).
enum : long {
    kRead = 0, kWrite = 1, kOpen = 2, kClose = 3,
    kMmap = 9, kMprotect = 10, kMunmap = 11, kBrk = 12,
    kWritev = 20, kNanosleep = 35, kGetpid = 39, kExit = 60,
    kArchprctl = 158, kExit_group = 231, kOpenat = 257,
};
constexpr u64 kPage = 0x1000;
u64 round_up(u64 v, u64 a) { return (v + a - 1) & ~(a - 1); }

const char* sys_name(long nr) {
    switch (nr) {
        case kRead: return "read"; case kWrite: return "write";
        case kOpen: return "open"; case kClose: return "close";
        case kMmap: return "mmap"; case kMprotect: return "mprotect";
        case kMunmap: return "munmap"; case kBrk: return "brk";
        case kWritev: return "writev"; case kNanosleep: return "nanosleep";
        case kGetpid: return "getpid"; case kExit: return "exit";
        case kArchprctl: return "arch_prctl"; case kExit_group: return "exit_group";
        case kOpenat: return "openat"; default: return "unknown";
    }
}
}  // namespace

std::string LinuxEnvironment::read_cstr(IDebugController& c, Addr p, std::size_t cap) const {
    std::string s;
    for (std::size_t i = 0; i < cap; ++i) {
        auto b = c.read_mem(p + i, 1);
        if (!b || b.value() == 0) break;
        s.push_back(static_cast<char>(b.value()));
    }
    return s;
}

void LinuxEnvironment::feed_input(int fd, std::vector<u8> bytes) {
    auto& q = in_[fd];
    q.insert(q.end(), bytes.begin(), bytes.end());
}

std::vector<u8> LinuxEnvironment::output(int fd) const {
    auto it = out_.find(fd);
    return it == out_.end() ? std::vector<u8>{} : it->second;
}

i64 LinuxEnvironment::dispatch(IDebugController& c, long nr, const std::array<u64, 6>& a,
                               std::vector<u8>& data) {
    switch (nr) {
        case kWrite: {
            Addr buf = a[1]; u64 n = a[2];
            if (auto b = c.read_bytes(buf, static_cast<unsigned>(std::min<u64>(n, 1u << 20)))) {
                data = b.value();
                auto& o = out_[static_cast<int>(a[0])];
                o.insert(o.end(), data.begin(), data.end());
                return static_cast<i64>(data.size());
            }
            return -14;  // -EFAULT
        }
        case kWritev: {
            int fd = static_cast<int>(a[0]);
            Addr iov = a[1]; u64 cnt = a[2];
            i64 total = 0;
            for (u64 i = 0; i < cnt && i < 1024; ++i) {
                auto base = c.read_mem(iov + 16 * i, 8);
                auto len = c.read_mem(iov + 16 * i + 8, 8);
                if (!base || !len) break;
                if (auto b = c.read_bytes(static_cast<Addr>(base.value()),
                                          static_cast<unsigned>(std::min<u64>(len.value(), 1u << 20)))) {
                    data.insert(data.end(), b.value().begin(), b.value().end());
                    auto& o = out_[fd];
                    o.insert(o.end(), b.value().begin(), b.value().end());
                    total += static_cast<i64>(b.value().size());
                }
            }
            return total;
        }
        case kRead: {
            int fd = static_cast<int>(a[0]);
            Addr buf = a[1]; u64 n = a[2];
            auto& q = in_[fd];
            u64 take = std::min<u64>(n, q.size());
            std::vector<u8> chunk(q.begin(), q.begin() + take);
            q.erase(q.begin(), q.begin() + take);
            if (take) c.write_bytes(buf, chunk, "linux read");
            data = chunk;
            return static_cast<i64>(take);  // 0 => EOF
        }
        case kOpen: { fd_path_[next_fd_] = read_cstr(c, a[0]); return next_fd_++; }
        case kOpenat: { fd_path_[next_fd_] = read_cstr(c, a[1]); return next_fd_++; }
        case kClose: return 0;
        case kMmap: {
            u64 len = round_up(a[1] ? a[1] : kPage, kPage);
            if (mmap_next_ + len > end_) return -12;  // -ENOMEM
            Addr r = mmap_next_;
            mmap_next_ += len;
            regions_.push_back({r, len, c.now()});
            return static_cast<i64>(r);
        }
        case kMprotect: return 0;  // perms not enforced in the sandbox
        case kMunmap: return 0;
        case kBrk: {
            Addr want = static_cast<Addr>(a[0]);
            if (want == 0) return static_cast<i64>(brk_);
            brk_ = std::clamp<Addr>(want, base_, mid_);
            return static_cast<i64>(brk_);
        }
        case kArchprctl: {
            constexpr u64 SET_FS = 0x1002, SET_GS = 0x1001, GET_FS = 0x1003, GET_GS = 0x1004;
            switch (a[0]) {
                case SET_FS: c.set_fs_base(a[1]); return 0;
                case SET_GS: c.set_gs_base(a[1]); return 0;
                case GET_FS: c.write_bytes(a[1], {}, "arch_prctl get_fs"); return 0;
                case GET_GS: return 0;
                default: return -22;  // -EINVAL
            }
        }
        case kGetpid: return 1000;
        case kNanosleep: return 0;  // deterministic: no real wait
        case kExit:
        case kExit_group:
            exited_ = true;
            exit_code_ = static_cast<i64>(a[0]);
            return 0;
        default:
            return 0;  // unknown: logged, safe default (per the sandbox policy)
    }
}

void LinuxEnvironment::on_syscall(IDebugController& c) {
    long nr = static_cast<long>(c.read_reg(Reg::Rax));
    std::array<u64, 6> a = {c.read_reg(Reg::Rdi), c.read_reg(Reg::Rsi), c.read_reg(Reg::Rdx),
                            c.read_reg(Reg::R10), c.read_reg(Reg::R8), c.read_reg(Reg::R9)};
    std::vector<u8> data;
    i64 ret = dispatch(c, nr, a, data);
    c.write_reg(Reg::Rax, static_cast<u64>(ret), std::string("linux ") + sys_name(nr));
    log_.push_back({nr, sys_name(nr), a, ret, std::move(data), c.now()});
}

}  // namespace dede::os
