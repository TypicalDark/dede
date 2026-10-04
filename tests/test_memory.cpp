// SPDX-License-Identifier: Apache-2.0
#include "check.hpp"
#include "dede/common/memory.hpp"

using namespace dede;

TEST("map, read, and write round-trip") {
    GuestMemory m;
    m.map(0x1000, 0x1000, perm::RW);
    CHECK(m.is_mapped(0x1000));
    CHECK(!m.is_mapped(0x3000));
    CHECK(m.write8(0x1234, 0xAB).ok());
    CHECK_EQ(m.read8(0x1234).value(), 0xABu);
    CHECK(m.write_int(0x1240, 8, 0x1122334455667788ull).ok());
    CHECK_EQ(m.read_int(0x1240, 8).value(), 0x1122334455667788ull);
}

TEST("reads and writes to unmapped memory fail") {
    GuestMemory m;
    CHECK(!m.read8(0x5000).ok());
    CHECK(!m.write8(0x5000, 1).ok());
}

TEST("copy-on-write snapshot is independent of later writes") {
    GuestMemory m;
    m.map(0x1000, 0x1000, perm::RW);
    m.write8(0x1000, 0x11);
    MemorySnapshot snap = m.snapshot();  // shares the page by pointer
    m.write8(0x1000, 0x22);              // must COW-clone, not touch the snapshot
    CHECK_EQ(m.read8(0x1000).value(), 0x22u);
    m.restore(snap);
    CHECK_EQ(m.read8(0x1000).value(), 0x11u);
}

TEST("snapshot shares pages cheaply (no eager copy)") {
    GuestMemory m;
    m.map(0x1000, 0x4000, perm::RW);  // 4 pages
    for (int i = 0; i < 4; ++i) m.write8(0x1000 + i * 0x1000, static_cast<u8>(i));
    MemorySnapshot s = m.snapshot();
    CHECK_EQ(s.page_count(), 4u);  // it references all four, but copied none
}

TEST("dirty-page tracking records writes") {
    GuestMemory m;
    m.map(0x1000, 0x2000, perm::RW);
    m.clear_dirty();
    m.write8(0x1500, 1);
    m.write8(0x1700, 2);  // same page
    CHECK_EQ(m.dirty_pages().size(), 1u);
    m.write8(0x2500, 3);  // next page
    CHECK_EQ(m.dirty_pages().size(), 2u);
}

int main() { return dede::test::run_all(); }
