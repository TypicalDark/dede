// SPDX-License-Identifier: Apache-2.0
#include "dede/common/memory.hpp"

#include <algorithm>

namespace dede {

namespace {
inline u64 page_base(Addr a) { return a & kPageMask; }
inline u64 page_off(Addr a) { return a & (kPageSize - 1); }
}  // namespace

void GuestMemory::map(Addr base, u64 size, u8 permissions) {
    u64 first = page_base(base);
    u64 last = page_base(base + size - 1);
    for (u64 p = first; p <= last; p += kPageSize) {
        if (pages_.find(p) == pages_.end()) {
            pages_[p] = std::make_shared<GuestPage>();
        }
        perms_[p] = permissions;
    }
}

bool GuestMemory::is_mapped(Addr a) const {
    return pages_.find(page_base(a)) != pages_.end();
}

u8 GuestMemory::permissions(Addr pb) const {
    auto it = perms_.find(page_base(pb));
    return it == perms_.end() ? 0 : it->second;
}

void GuestMemory::set_permissions(Addr pb, u8 p) { perms_[page_base(pb)] = p; }

const GuestPage* GuestMemory::page_for_read(Addr a) const {
    auto it = pages_.find(page_base(a));
    return it == pages_.end() ? nullptr : it->second.get();
}

GuestPage* GuestMemory::page_for_write(Addr a) {
    u64 pb = page_base(a);
    auto it = pages_.find(pb);
    if (it == pages_.end()) return nullptr;
    // Copy-on-write: if this page is still shared with a snapshot, clone it so
    // the snapshot keeps the old bytes and we mutate a private copy.
    if (it->second.use_count() > 1) {
        it->second = std::make_shared<GuestPage>(*it->second);
    }
    return it->second.get();
}

void GuestMemory::mark_dirty(u64 pb) {
    if (dirty_.empty() || dirty_.back() != pb) {
        // keep it cheap: dedupe only consecutive repeats of the same page
        if (std::find(dirty_.begin(), dirty_.end(), pb) == dirty_.end()) {
            dirty_.push_back(pb);
        }
    }
}

Result<u8> GuestMemory::read8(Addr a) const {
    const GuestPage* pg = page_for_read(a);
    if (!pg) return make_error("read8: unmapped address");
    return pg->bytes[page_off(a)];
}

Result<void> GuestMemory::write8(Addr a, u8 v) {
    GuestPage* pg = page_for_write(a);
    if (!pg) return make_error("write8: unmapped address");
    pg->bytes[page_off(a)] = v;
    mark_dirty(page_base(a));
    return {};
}

Result<std::vector<u8>> GuestMemory::read(Addr a, u64 len) const {
    std::vector<u8> out;
    out.reserve(len);
    for (u64 i = 0; i < len; ++i) {
        auto b = read8(a + i);
        if (!b) return b.error();
        out.push_back(b.value());
    }
    return out;
}

Result<void> GuestMemory::write(Addr a, const std::vector<u8>& data) {
    return write_raw(a, data.data(), data.size());
}

Result<void> GuestMemory::write_raw(Addr a, const u8* data, u64 len) {
    for (u64 i = 0; i < len; ++i) {
        auto r = write8(a + i, data[i]);
        if (!r) return r.error();
    }
    return {};
}

Result<u64> GuestMemory::read_int(Addr a, unsigned bytes) const {
    u64 v = 0;
    for (unsigned i = 0; i < bytes; ++i) {
        auto b = read8(a + i);
        if (!b) return b.error();
        v |= static_cast<u64>(b.value()) << (8 * i);
    }
    return v;
}

Result<void> GuestMemory::write_int(Addr a, unsigned bytes, u64 v) {
    for (unsigned i = 0; i < bytes; ++i) {
        auto r = write8(a + i, static_cast<u8>((v >> (8 * i)) & 0xff));
        if (!r) return r.error();
    }
    return {};
}

MemorySnapshot GuestMemory::snapshot() const {
    MemorySnapshot s;
    s.pages_ = pages_;  // shares every page by pointer; no byte copy
    s.perms_ = perms_;
    return s;
}

void GuestMemory::restore(const MemorySnapshot& s) {
    pages_ = s.pages_;  // re-shares the snapshot's pages; future writes COW them
    perms_ = s.perms_;
    dirty_.clear();
}

}  // namespace dede
