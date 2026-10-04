// SPDX-License-Identifier: Apache-2.0
//
// Guest physical/linear memory as copy-on-write pages.
//
// This is the substrate that makes the Memento pattern cheap: a snapshot copies
// a map of shared_ptr<Page> (O(resident pages) pointer bumps, no byte copy). A
// later write to a page that is still shared with a snapshot clones just that
// one page before mutating it, so snapshots never see each other's writes. This
// is the "full memory image captured with copy-on-write pages" from the design.
#pragma once

#include <array>
#include <map>
#include <memory>
#include <vector>

#include "dede/common/status.hpp"
#include "dede/common/types.hpp"

namespace dede {

inline constexpr u64 kPageSize = 0x1000;              // 4 KiB
inline constexpr u64 kPageMask = ~(kPageSize - 1);

// Page permissions, tracked so the W^X / "written then executed" detection in
// the transparency and run-point layers has something to observe.
namespace perm {
inline constexpr u8 R = 1 << 0;
inline constexpr u8 W = 1 << 1;
inline constexpr u8 X = 1 << 2;
inline constexpr u8 RW = R | W;
inline constexpr u8 RX = R | X;
inline constexpr u8 RWX = R | W | X;
}  // namespace perm

// One physical page of guest memory. Shared between the live map and any number
// of snapshots until someone writes to it (copy-on-write).
struct GuestPage {
    std::array<u8, kPageSize> bytes{};
};

// A snapshot handle. Opaque to everyone except GuestMemory itself; the timeline
// layer only stores one and hands it back. Internally it is just the shared
// page map plus the permissions captured at snapshot time.
class MemorySnapshot {
public:
    MemorySnapshot() = default;
    std::size_t page_count() const noexcept { return pages_.size(); }

private:
    friend class GuestMemory;
    std::map<u64, std::shared_ptr<GuestPage>> pages_;
    std::map<u64, u8> perms_;
};

class GuestMemory {
public:
    GuestMemory() = default;

    // Reserve/allocate a region [base, base+size) with the given permissions.
    void map(Addr base, u64 size, u8 permissions);

    bool is_mapped(Addr a) const;
    u8 permissions(Addr page_base) const;
    void set_permissions(Addr page_base, u8 p);

    // Byte-granular access. read/write fail (Result error) on unmapped pages.
    Result<u8> read8(Addr a) const;
    Result<void> write8(Addr a, u8 v);

    Result<std::vector<u8>> read(Addr a, u64 len) const;
    Result<void> write(Addr a, const std::vector<u8>& data);
    Result<void> write_raw(Addr a, const u8* data, u64 len);

    // Little-endian helpers for operand-sized access.
    Result<u64> read_int(Addr a, unsigned bytes) const;
    Result<void> write_int(Addr a, unsigned bytes, u64 v);

    // --- Copy-on-write snapshot/restore (used by the Memento layer) ----------
    MemorySnapshot snapshot() const;
    void restore(const MemorySnapshot& s);

    // Pages written since construction or the last clear_dirty(), oldest first.
    const std::vector<u64>& dirty_pages() const noexcept { return dirty_; }
    void clear_dirty() { dirty_.clear(); }

    std::size_t resident_pages() const noexcept { return pages_.size(); }

    // Base addresses of all mapped pages, ascending (for session save / region
    // enumeration).
    std::vector<u64> mapped_pages() const {
        std::vector<u64> out;
        out.reserve(pages_.size());
        for (const auto& [base, _] : pages_) out.push_back(base);
        return out;
    }

private:
    GuestPage* page_for_write(Addr a);
    const GuestPage* page_for_read(Addr a) const;
    void mark_dirty(u64 page_base);

    std::map<u64, std::shared_ptr<GuestPage>> pages_;  // page_base -> shared page
    std::map<u64, u8> perms_;                          // page_base -> permissions
    std::vector<u64> dirty_;                            // recently written pages
};

}  // namespace dede
