// SPDX-License-Identifier: Apache-2.0
#include "dede/core/memory_proxy.hpp"

namespace dede {

namespace {
inline u64 page_of(Addr a) { return a & kPageMask; }
}  // namespace

Result<u64> MemoryProxy::read(Addr a, unsigned bytes) {
    auto v = mem_.read_int(a, bytes);
    if (!v) return v.error();
    sink_->emit(Event{EventKind::MemRead, ctx_.pc, a, v.value(), bytes, ctx_.tick, {}});
    return v;
}

Result<void> MemoryProxy::write(Addr a, unsigned bytes, u64 v) {
    auto r = mem_.write_int(a, bytes, v);
    if (!r) return r.error();
    // Any page touched by this write is now a W^X candidate.
    for (u64 p = page_of(a); p <= page_of(a + bytes - 1); p += kPageSize) {
        written_pages_.insert(p);
    }
    sink_->emit(Event{EventKind::MemWrite, ctx_.pc, a, v, bytes, ctx_.tick, {}});
    return {};
}

Result<std::vector<u8>> MemoryProxy::fetch(Addr a, unsigned len) {
    u64 pg = page_of(a);
    if (auto it = written_pages_.find(pg); it != written_pages_.end()) {
        written_pages_.erase(it);  // re-arms only after the next write
        sink_->emit(Event{EventKind::ExecWrittenPage, a, pg, 0, 0, ctx_.tick,
                         "executing a page previously written as data"});
    }
    // Fetch may run off the end of mapped memory near a boundary; read what we
    // can (at least one byte) so the decoder gets a chance.
    std::vector<u8> out;
    for (unsigned i = 0; i < len; ++i) {
        auto b = mem_.read8(a + i);
        if (!b) break;
        out.push_back(b.value());
    }
    if (out.empty()) return make_error("fetch: unmapped instruction pointer");
    return out;
}

}  // namespace dede
