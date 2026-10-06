// SPDX-License-Identifier: Apache-2.0
#include "dede/interchange/interchange.hpp"

#include <cctype>
#include <cstdlib>
#include <map>
#include <memory>
#include <sstream>

namespace dede::interchange {
namespace {

// --- a tiny JSON value tree + recursive-descent parser ----------------------
struct JVal {
    enum class T { Null, Bool, Num, Str, Arr, Obj } t = T::Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<JVal> arr;
    std::map<std::string, JVal> obj;
};

struct Parser {
    const std::string& s;
    std::size_t p = 0;
    bool ok = true;
    explicit Parser(const std::string& t) : s(t) {}

    void ws() { while (p < s.size() && std::isspace((unsigned char)s[p])) ++p; }
    char peek() { ws(); return p < s.size() ? s[p] : '\0'; }

    bool lit(const char* w) {
        ws();
        std::size_t n = 0;
        while (w[n]) { if (p + n >= s.size() || s[p + n] != w[n]) return false; ++n; }
        p += n;
        return true;
    }

    std::string str() {
        ws();
        std::string out;
        if (p >= s.size() || s[p] != '"') { ok = false; return out; }
        ++p;
        while (p < s.size() && s[p] != '"') {
            char c = s[p++];
            if (c == '\\' && p < s.size()) {
                char e = s[p++];
                switch (e) {
                    case 'n': out += '\n'; break; case 't': out += '\t'; break;
                    case 'r': out += '\r'; break; case '"': out += '"'; break;
                    case '\\': out += '\\'; break; case '/': out += '/'; break;
                    case 'b': out += '\b'; break; case 'f': out += '\f'; break;
                    case 'u': if (p + 4 <= s.size()) { // keep ASCII; emit '?' for non-ASCII
                                  int v = (int)std::strtol(s.substr(p, 4).c_str(), nullptr, 16);
                                  out += (v < 128 ? (char)v : '?'); p += 4;
                              } break;
                    default: out += e; break;
                }
            } else {
                out += c;
            }
        }
        if (p < s.size() && s[p] == '"') ++p; else ok = false;
        return out;
    }

    JVal value() {
        char c = peek();
        if (c == '"') { JVal v; v.t = JVal::T::Str; v.str = str(); return v; }
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == 't') { JVal v; v.t = JVal::T::Bool; v.b = true; ok &= lit("true"); return v; }
        if (c == 'f') { JVal v; v.t = JVal::T::Bool; v.b = false; ok &= lit("false"); return v; }
        if (c == 'n') { JVal v; ok &= lit("null"); return v; }
        // number
        ws();
        std::size_t start = p;
        while (p < s.size() && (std::isdigit((unsigned char)s[p]) || s[p] == '-' || s[p] == '+' ||
                                s[p] == '.' || s[p] == 'e' || s[p] == 'E' || s[p] == 'x' ||
                                (s[p] >= 'a' && s[p] <= 'f') || (s[p] >= 'A' && s[p] <= 'F')))
            ++p;
        if (p == start) { ok = false; return {}; }
        JVal v; v.t = JVal::T::Num; v.str = s.substr(start, p - start);
        v.num = std::strtod(v.str.c_str(), nullptr);
        return v;
    }

    JVal object() {
        JVal v; v.t = JVal::T::Obj;
        if (peek() != '{') { ok = false; return v; }
        ++p;
        if (peek() == '}') { ++p; return v; }
        for (;;) {
            std::string key = str();
            if (peek() != ':') { ok = false; return v; }
            ++p;
            v.obj[key] = value();
            char c = peek();
            if (c == ',') { ++p; continue; }
            if (c == '}') { ++p; break; }
            ok = false; return v;
        }
        return v;
    }

    JVal array() {
        JVal v; v.t = JVal::T::Arr;
        if (peek() != '[') { ok = false; return v; }
        ++p;
        if (peek() == ']') { ++p; return v; }
        for (;;) {
            v.arr.push_back(value());
            char c = peek();
            if (c == ',') { ++p; continue; }
            if (c == ']') { ++p; break; }
            ok = false; return v;
        }
        return v;
    }
};

// A number from either a JSON number or a "0x.."/decimal string field.
long long as_int(const JVal& v) {
    if (v.t == JVal::T::Num) {
        if (v.str.find('x') != std::string::npos || v.str.find('X') != std::string::npos)
            return (long long)std::strtoull(v.str.c_str(), nullptr, 16);
        return (long long)v.num;
    }
    if (v.t == JVal::T::Str) {
        const std::string& s = v.str;
        int base = (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) ? 16 : 10;
        return (long long)std::strtoull(s.c_str(), nullptr, base);
    }
    return 0;
}

const JVal* find(const JVal& o, const char* k) {
    if (o.t != JVal::T::Obj) return nullptr;
    auto it = o.obj.find(k);
    return it == o.obj.end() ? nullptr : &it->second;
}

std::string esc(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"': o += "\\\""; break; case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break; case '\t': o += "\\t"; break;
            case '\r': o += "\\r"; break;
            default: o += c;
        }
    }
    return o;
}

std::string hex(Addr a) { std::ostringstream o; o << "0x" << std::hex << a; return o.str(); }

}  // namespace

std::string to_json(const AnalysisDoc& doc) {
    std::ostringstream o;
    o << "{\n  \"symbols\": [";
    for (std::size_t i = 0; i < doc.symbols.size(); ++i)
        o << (i ? "," : "") << "\n    {\"addr\": \"" << hex(doc.symbols[i].addr) << "\", \"name\": \"" << esc(doc.symbols[i].name) << "\"}";
    o << (doc.symbols.empty() ? "" : "\n  ") << "],\n  \"comments\": [";
    for (std::size_t i = 0; i < doc.comments.size(); ++i)
        o << (i ? "," : "") << "\n    {\"addr\": \"" << hex(doc.comments[i].addr) << "\", \"text\": \"" << esc(doc.comments[i].text) << "\"}";
    o << (doc.comments.empty() ? "" : "\n  ") << "],\n  \"functions\": [";
    for (std::size_t i = 0; i < doc.functions.size(); ++i)
        o << (i ? "," : "") << "\n    {\"addr\": \"" << hex(doc.functions[i].addr) << "\", \"name\": \"" << esc(doc.functions[i].name)
          << "\", \"size\": " << doc.functions[i].size << "}";
    o << (doc.functions.empty() ? "" : "\n  ") << "],\n  \"structs\": [";
    for (std::size_t i = 0; i < doc.structs.size(); ++i) {
        o << (i ? "," : "") << "\n    {\"tag\": \"" << esc(doc.structs[i].tag) << "\", \"fields\": [";
        for (std::size_t j = 0; j < doc.structs[i].fields.size(); ++j)
            o << (j ? ", " : "") << "{\"offset\": " << doc.structs[i].fields[j].offset
              << ", \"width\": " << doc.structs[i].fields[j].width << "}";
        o << "]}";
    }
    o << (doc.structs.empty() ? "" : "\n  ") << "]\n}\n";
    return o.str();
}

std::optional<AnalysisDoc> parse_json(const std::string& text) {
    Parser pr(text);
    JVal root = pr.value();
    if (!pr.ok || root.t != JVal::T::Obj) return std::nullopt;
    AnalysisDoc doc;
    if (const JVal* a = find(root, "symbols"); a && a->t == JVal::T::Arr)
        for (const auto& e : a->arr) {
            SymbolEnt s;
            if (const JVal* v = find(e, "addr")) s.addr = (Addr)as_int(*v);
            if (const JVal* v = find(e, "name"); v && v->t == JVal::T::Str) s.name = v->str;
            doc.symbols.push_back(std::move(s));
        }
    if (const JVal* a = find(root, "comments"); a && a->t == JVal::T::Arr)
        for (const auto& e : a->arr) {
            CommentEnt c;
            if (const JVal* v = find(e, "addr")) c.addr = (Addr)as_int(*v);
            if (const JVal* v = find(e, "text"); v && v->t == JVal::T::Str) c.text = v->str;
            doc.comments.push_back(std::move(c));
        }
    if (const JVal* a = find(root, "functions"); a && a->t == JVal::T::Arr)
        for (const auto& e : a->arr) {
            FunctionEnt f;
            if (const JVal* v = find(e, "addr")) f.addr = (Addr)as_int(*v);
            if (const JVal* v = find(e, "name"); v && v->t == JVal::T::Str) f.name = v->str;
            if (const JVal* v = find(e, "size")) f.size = (u64)as_int(*v);
            doc.functions.push_back(std::move(f));
        }
    if (const JVal* a = find(root, "structs"); a && a->t == JVal::T::Arr)
        for (const auto& e : a->arr) {
            StructEnt st;
            if (const JVal* v = find(e, "tag"); v && v->t == JVal::T::Str) st.tag = v->str;
            if (const JVal* fs = find(e, "fields"); fs && fs->t == JVal::T::Arr)
                for (const auto& fe : fs->arr) {
                    FieldEnt fd;
                    if (const JVal* v = find(fe, "offset")) fd.offset = (i64)as_int(*v);
                    if (const JVal* v = find(fe, "width")) fd.width = (unsigned)as_int(*v);
                    st.fields.push_back(fd);
                }
            doc.structs.push_back(std::move(st));
        }
    return doc;
}

}  // namespace dede::interchange
