// SPDX-License-Identifier: Apache-2.0
//
// A dependency-free test harness. Each test file defines cases with CHECK/
// CHECK_EQ and calls dede::test::run_all() from main(). Keeping it in-tree means
// the whole project builds and tests with nothing but a C++20 compiler and
// Capstone — no test framework to fetch.
#pragma once

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace dede::test {

struct Case {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

inline int& failures() {
    static int f = 0;
    return f;
}

struct Registrar {
    Registrar(std::string name, std::function<void()> fn) {
        registry().push_back({std::move(name), std::move(fn)});
    }
};

// Stream a value for a diagnostic: single-byte integers are promoted so they
// print as numbers, everything else streams as-is (strings, enums-with-op<<, …).
template <typename T>
void show(std::ostream& os, const T& v) {
    if constexpr (std::is_arithmetic_v<T> && sizeof(T) == 1) {
        os << +v;
    } else {
        os << v;
    }
}

inline void fail(const std::string& where, const std::string& msg) {
    ++failures();
    std::fprintf(stderr, "  FAIL %s: %s\n", where.c_str(), msg.c_str());
}

inline int run_all() {
    int passed = 0;
    for (auto& c : registry()) {
        int before = failures();
        try {
            c.fn();
        } catch (const std::exception& ex) {
            fail(c.name, std::string("threw: ") + ex.what());
        }
        if (failures() == before) {
            ++passed;
            std::fprintf(stderr, "  ok   %s\n", c.name.c_str());
        }
    }
    std::fprintf(stderr, "\n%d passed, %d failed\n", passed,
                 static_cast<int>(registry().size()) - passed);
    return failures() == 0 ? 0 : 1;
}

}  // namespace dede::test

#define DEDE_CONCAT2(a, b) a##b
#define DEDE_CONCAT(a, b) DEDE_CONCAT2(a, b)

#define TEST(name)                                                          \
    static void DEDE_CONCAT(dede_test_fn_, __LINE__)();                     \
    static ::dede::test::Registrar DEDE_CONCAT(dede_test_reg_, __LINE__)(   \
        name, &DEDE_CONCAT(dede_test_fn_, __LINE__));                       \
    static void DEDE_CONCAT(dede_test_fn_, __LINE__)()

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) ::dede::test::fail(__func__, "CHECK(" #cond ")");      \
    } while (0)

#define CHECK_EQ(a, b)                                                      \
    do {                                                                    \
        auto _va = (a);                                                     \
        auto _vb = (b);                                                     \
        if (!(_va == _vb)) {                                                \
            std::ostringstream _os;                                         \
            _os << "CHECK_EQ(" #a ", " #b ") got ";                         \
            ::dede::test::show(_os, _va);                                   \
            _os << " != ";                                                  \
            ::dede::test::show(_os, _vb);                                   \
            ::dede::test::fail(__func__, _os.str());                        \
        }                                                                   \
    } while (0)

#define CHECK_MSG(cond, msg)                                                \
    do {                                                                    \
        if (!(cond)) ::dede::test::fail(__func__, msg);                     \
    } while (0)
