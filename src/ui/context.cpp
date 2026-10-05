// SPDX-License-Identifier: Apache-2.0
#include "dede/ui/context.hpp"

namespace dede::ui {

namespace {
std::vector<std::string> split(const std::string& s, const std::string& sep) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        auto n = s.find(sep, pos);
        if (n == std::string::npos) { out.push_back(s.substr(pos)); break; }
        out.push_back(s.substr(pos, n - pos));
        pos = n + sep.size();
    }
    return out;
}
std::string trim(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    return s;
}
bool term(const std::string& t, const Context& ctx) {
    std::string x = trim(t);
    if (x.empty() || x == "true") return true;
    if (x == "false") return false;
    if (x[0] == '!') return !ctx.flag(trim(x.substr(1)));
    return ctx.flag(x);
}
}  // namespace

bool evaluate_when(const std::string& when, const Context& ctx) {
    std::string w = trim(when);
    if (w.empty()) return true;
    // OR of ANDs.
    for (const auto& clause : split(w, " || ")) {
        bool all = true;
        for (const auto& t : split(clause, " && "))
            if (!term(t, ctx)) { all = false; break; }
        if (all) return true;
    }
    return false;
}

}  // namespace dede::ui
