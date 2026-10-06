// SPDX-License-Identifier: Apache-2.0
#include "dede/symbols/demangle.hpp"

#include <cctype>
#include <cstdlib>
#include <vector>

namespace dede::sym {
namespace {

// A recursive-descent Itanium demangler over a cursor into the mangled string.
struct Itanium {
    const std::string& s;
    std::size_t p = 0;
    bool ok = true;
    std::vector<std::string> subs;  // substitution table (S_, S0_, ...)

    explicit Itanium(const std::string& m) : s(m) {}

    bool eof() const { return p >= s.size(); }
    char peek() const { return eof() ? '\0' : s[p]; }
    char get() { return eof() ? '\0' : s[p++]; }
    void fail() { ok = false; }

    // <number> (decimal)
    long num() {
        long n = 0;
        bool any = false;
        while (!eof() && std::isdigit((unsigned char)peek())) { n = n * 10 + (get() - '0'); any = true; }
        if (!any) fail();
        return n;
    }

    // <source-name> ::= <len> <chars>
    std::string source_name() {
        long n = num();
        if (!ok || n < 0 || p + (std::size_t)n > s.size()) { fail(); return ""; }
        std::string r = s.substr(p, (std::size_t)n);
        p += (std::size_t)n;
        return r;
    }

    // operator / ctor-dtor / source-name as an unqualified name component.
    std::string unqualified(const std::string& cls_tail) {
        char c = peek();
        if (c == 'C') { get(); if (!eof()) get(); return cls_tail; }          // C1/C2/C3 ctor
        if (c == 'D') { get(); if (!eof()) get(); return "~" + cls_tail; }    // D0/D1/D2 dtor
        if (std::isdigit((unsigned char)c)) return source_name();
        if (std::isalpha((unsigned char)c)) {                                 // operator?
            std::string op = std::string(1, get());
            if (!eof()) op += get();
            return operator_name(op);
        }
        fail();
        return "";
    }

    std::string operator_name(const std::string& code) {
        struct O { const char* k; const char* v; };
        static const O ops[] = {
            {"ps", "operator+"}, {"ng", "operator-"}, {"ad", "operator&"}, {"de", "operator*"},
            {"pl", "operator+"}, {"mi", "operator-"}, {"ml", "operator*"}, {"dv", "operator/"},
            {"rm", "operator%"}, {"eq", "operator=="}, {"ne", "operator!="}, {"lt", "operator<"},
            {"gt", "operator>"}, {"le", "operator<="}, {"ge", "operator>="}, {"aS", "operator="},
            {"ix", "operator[]"}, {"cl", "operator()"}, {"nw", "operator new"}, {"dl", "operator delete"},
            {"na", "operator new[]"}, {"da", "operator delete[]"}, {"ls", "operator<<"}, {"rs", "operator>>"},
        };
        for (const auto& o : ops) if (code == o.k) return o.v;
        return "operator?";
    }

    // <name> ::= N [CV] <prefix> E  |  St <unqualified>  |  <unqualified>
    std::string name() {
        if (peek() == 'N') {
            get();
            // ignore CV qualifiers on the implicit object
            while (peek() == 'r' || peek() == 'V' || peek() == 'K') get();
            std::string full, last_comp;
            while (ok && !eof() && peek() != 'E') {
                if (peek() == 'S') { std::string sub = substitution(); if (!ok) break; last_comp = tail(sub); full = full.empty() ? sub : full + "::" + sub; if (ok) subs.push_back(full); continue; }
                if (peek() == 'I') { std::string targs = template_args(); full += targs; if (ok) { subs.push_back(full); } continue; }
                std::string comp = unqualified(last_comp);
                last_comp = comp;
                full = full.empty() ? comp : full + "::" + comp;
                if (ok) subs.push_back(full);
            }
            if (peek() == 'E') get(); else fail();
            return full;
        }
        if (peek() == 'S') return substitution_or_std();
        return unqualified("");
    }

    std::string tail(const std::string& qualified) {
        auto pos = qualified.rfind("::");
        return pos == std::string::npos ? qualified : qualified.substr(pos + 2);
    }

    // St -> "std", or a std:: abbreviation; Sx_ substitutions.
    std::string substitution_or_std() {
        if (p + 1 < s.size() && s[p + 1] == 't') { p += 2; std::string u = unqualified(""); return "std::" + u; }
        return substitution();
    }

    std::string substitution() {
        if (peek() != 'S') { fail(); return ""; }
        get();
        // std abbreviations
        char c = peek();
        if (c == 't') { get(); return "std"; }
        if (c == 'a') { get(); return "std::allocator"; }
        if (c == 'b') { get(); return "std::basic_string"; }
        if (c == 's') { get(); return "std::string"; }
        if (c == 'i') { get(); return "std::istream"; }
        if (c == 'o') { get(); return "std::ostream"; }
        if (c == 'd') { get(); return "std::iostream"; }
        // S_ or S<base36>_
        long idx = 0;
        bool have = false;
        if (c == '_') { get(); idx = 0; have = true; }
        else {
            while (!eof() && (std::isdigit((unsigned char)peek()) || (peek() >= 'A' && peek() <= 'Z'))) {
                char d = get();
                int v = std::isdigit((unsigned char)d) ? d - '0' : d - 'A' + 10;
                idx = idx * 36 + v;
                have = true;
            }
            if (peek() == '_') get(); else { fail(); return ""; }
            idx += 1;  // S_ is 0, S0_ is 1, ...
        }
        if (!have) { fail(); return ""; }
        if (idx < 0 || (std::size_t)idx >= subs.size()) { fail(); return ""; }
        return subs[(std::size_t)idx];
    }

    // <template-args> ::= I <type>+ E   -> "<a, b, ...>"
    std::string template_args() {
        if (peek() != 'I') { fail(); return ""; }
        get();
        std::string out = "<";
        bool first = true;
        while (ok && !eof() && peek() != 'E') {
            std::string t = type();
            if (!ok) break;
            out += (first ? "" : ", ") + t;
            first = false;
        }
        if (peek() == 'E') get(); else fail();
        out += ">";
        return out;
    }

    std::string builtin(char c) {
        switch (c) {
            case 'v': return "void";   case 'b': return "bool";   case 'c': return "char";
            case 'a': return "signed char"; case 'h': return "unsigned char";
            case 's': return "short";  case 't': return "unsigned short";
            case 'i': return "int";    case 'j': return "unsigned int";
            case 'l': return "long";   case 'm': return "unsigned long";
            case 'x': return "long long"; case 'y': return "unsigned long long";
            case 'f': return "float";  case 'd': return "double"; case 'e': return "long double";
            case 'w': return "wchar_t"; case 'n': return "__int128"; case 'o': return "unsigned __int128";
            default: return "";
        }
    }

    // <type> with pointer/ref/const prefixes.
    std::string type() {
        char c = peek();
        if (c == 'P') { get(); return type() + " *"; }
        if (c == 'R') { get(); return type() + " &"; }
        if (c == 'O') { get(); return type() + " &&"; }
        if (c == 'K') { get(); return "const " + type(); }
        if (c == 'V') { get(); return "volatile " + type(); }
        if (c == 'r') { get(); return type(); }  // restrict: drop
        if (c == 'F') { get(); return function_type(); }
        if (c == 'N') { std::string n = name(); return n; }
        if (c == 'S') { std::string sub = substitution_or_std(); if (peek() == 'I') sub += template_args(); return sub; }
        if (std::isdigit((unsigned char)c)) { std::string n = source_name(); if (peek() == 'I') n += template_args(); if (ok) subs.push_back(n); return n; }
        std::string b = builtin(c);
        if (!b.empty()) { get(); return b; }
        fail();
        return "";
    }

    std::string function_type() {
        // Fv E or F <ret> <params> E -> render as "ret (*)(params)" loosely.
        std::string ret = type();
        std::string params;
        bool first = true;
        while (ok && !eof() && peek() != 'E') { std::string t = type(); if (!ok) break; params += (first ? "" : ", ") + t; first = false; }
        if (peek() == 'E') get();
        return ret + " (*)(" + params + ")";
    }

    // Top level: _Z <name> [<bare-function-type>]
    std::string run() {
        if (s.rfind("_Z", 0) != 0) { fail(); return ""; }
        p = 2;
        std::string nm = name();
        if (!ok) return "";
        // function parameters (if any remain)
        std::string params;
        bool any = false, first = true;
        while (ok && !eof()) {
            if (peek() == 'v' && !any) { get(); any = true; break; }  // (void)
            std::string t = type();
            if (!ok) break;
            params += (first ? "" : ", ") + t;
            first = false;
            any = true;
        }
        if (!ok) return "";
        if (!any) return nm;                 // a data symbol, no parameter list
        return nm + "(" + params + ")";
    }
};

}  // namespace

std::string demangle_itanium(const std::string& m) {
    if (m.rfind("_Z", 0) != 0) return m;
    Itanium it(m);
    std::string r = it.run();
    return (it.ok && !r.empty()) ? r : m;
}

std::string demangle_msvc(const std::string& m) {
    // Minimal: ?name@scope@@... -> scope::name (reversed @-separated components).
    if (m.empty() || m[0] != '?') return m;
    std::size_t at = m.find('@', 1);
    if (at == std::string::npos) return m;
    std::string fn = m.substr(1, at - 1);
    std::string rest = m.substr(at + 1);
    std::size_t end = rest.find("@@");
    std::string scope = end == std::string::npos ? rest : rest.substr(0, end);
    std::vector<std::string> comps;
    std::size_t start = 0;
    while (start <= scope.size()) {
        std::size_t a = scope.find('@', start);
        std::string c = scope.substr(start, a == std::string::npos ? std::string::npos : a - start);
        if (!c.empty()) comps.push_back(c);
        if (a == std::string::npos) break;
        start = a + 1;
    }
    std::string out;
    for (auto rit = comps.rbegin(); rit != comps.rend(); ++rit) out += *rit + "::";
    out += fn;
    return out.empty() ? m : out;
}

std::string demangle(const std::string& m) {
    if (m.rfind("_Z", 0) == 0) return demangle_itanium(m);
    if (!m.empty() && m[0] == '?') return demangle_msvc(m);
    return m;
}

}  // namespace dede::sym
