#pragma once

#include <cctype>
#include <cstdint>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace paper {

// A small dependency-free JSON value used by the local AI protocol. It is
// intentionally strict enough for JSON-RPC and keeps the core build portable.
class Json {
public:
    using Object = std::map<std::string, Json, std::less<>>;
    using Array = std::vector<Json>;

    Json() : value_(nullptr) {}
    Json(std::nullptr_t) : value_(nullptr) {}
    Json(bool value) : value_(value) {}
    template <typename T, std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
    Json(T value) : value_(static_cast<double>(value)) {}
    Json(double value) : value_(value) {}
    Json(const char* value) : value_(std::string(value)) {}
    Json(std::string value) : value_(std::move(value)) {}
    Json(std::string_view value) : value_(std::string(value)) {}
    Json(Object value) : value_(std::move(value)) {}
    Json(Array value) : value_(std::move(value)) {}

    static Json object() { return Json(Object{}); }
    static Json array() { return Json(Array{}); }

    bool is_null() const { return std::holds_alternative<std::nullptr_t>(value_); }
    bool is_bool() const { return std::holds_alternative<bool>(value_); }
    bool is_number() const { return std::holds_alternative<double>(value_); }
    bool is_string() const { return std::holds_alternative<std::string>(value_); }
    bool is_object() const { return std::holds_alternative<Object>(value_); }
    bool is_array() const { return std::holds_alternative<Array>(value_); }

    bool as_bool(bool fallback = false) const {
        return is_bool() ? std::get<bool>(value_) : fallback;
    }
    double as_number(double fallback = 0.0) const {
        return is_number() ? std::get<double>(value_) : fallback;
    }
    std::uint64_t as_u64(std::uint64_t fallback = 0) const {
        if (!is_number()) return fallback;
        const double n = std::get<double>(value_);
        return n < 0 ? fallback : static_cast<std::uint64_t>(n);
    }
    const std::string& as_string() const {
        static const std::string empty;
        return is_string() ? std::get<std::string>(value_) : empty;
    }
    std::string string_or(std::string fallback) const {
        return is_string() ? std::get<std::string>(value_) : std::move(fallback);
    }

    Object& object_items() {
        if (!is_object()) value_ = Object{};
        return std::get<Object>(value_);
    }
    const Object& object_items() const {
        static const Object empty;
        return is_object() ? std::get<Object>(value_) : empty;
    }
    Array& array_items() {
        if (!is_array()) value_ = Array{};
        return std::get<Array>(value_);
    }
    const Array& array_items() const {
        static const Array empty;
        return is_array() ? std::get<Array>(value_) : empty;
    }

    Json& operator[](std::string_view key) {
        return object_items()[std::string(key)];
    }
    const Json* find(std::string_view key) const {
        if (!is_object()) return nullptr;
        const auto& object = std::get<Object>(value_);
        const auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }
    Json* find(std::string_view key) {
        if (!is_object()) return nullptr;
        auto& object = std::get<Object>(value_);
        const auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }

    void push_back(Json value) { array_items().push_back(std::move(value)); }

    static Json parse(std::string_view text) {
        Parser parser{text};
        Json result = parser.value();
        parser.ws();
        if (!parser.at_end()) throw std::runtime_error("trailing JSON data");
        return result;
    }

    std::string dump() const {
        std::string out;
        dump_into(out);
        return out;
    }

private:
    using Value = std::variant<std::nullptr_t, bool, double, std::string, Object, Array>;
    Value value_;

    class Parser {
    public:
        explicit Parser(std::string_view input) : input_(input) {}

        Json value() {
            ws();
            if (at_end()) fail("unexpected end of JSON");
            switch (peek()) {
            case 'n': literal("null"); return Json(nullptr);
            case 't': literal("true"); return Json(true);
            case 'f': literal("false"); return Json(false);
            case '"': return Json(string());
            case '{': return object();
            case '[': return array();
            default: return Json(number());
            }
        }

        void ws() {
            while (!at_end() && std::isspace(static_cast<unsigned char>(peek()))) ++pos_;
        }
        bool at_end() const { return pos_ >= input_.size(); }

    private:
        char peek() const { return input_[pos_]; }
        char take() { return input_[pos_++]; }
        void expect(char expected) {
            if (at_end() || take() != expected) fail("unexpected JSON character");
        }
        void fail(const char* message) const { throw std::runtime_error(message); }

        void literal(std::string_view word) {
            if (input_.substr(pos_, word.size()) != word) fail("invalid JSON literal");
            pos_ += word.size();
        }

        std::string string() {
            expect('"');
            std::string result;
            while (!at_end()) {
                const char c = take();
                if (c == '"') return result;
                if (c != '\\') {
                    result.push_back(c);
                    continue;
                }
                if (at_end()) fail("unterminated JSON escape");
                switch (take()) {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'u':
                    // Tool requests are UTF-8 in practice. Preserve a unicode
                    // escape as a replacement marker instead of accepting bad
                    // bytes silently.
                    for (int i = 0; i < 4; ++i) {
                        if (at_end() || !std::isxdigit(static_cast<unsigned char>(peek())))
                            fail("invalid unicode escape");
                        ++pos_;
                    }
                    result.push_back('?');
                    break;
                default: fail("invalid JSON escape");
                }
            }
            fail("unterminated JSON string");
            return {};
        }

        double number() {
            const auto start = pos_;
            if (peek() == '-') ++pos_;
            if (at_end() || !std::isdigit(static_cast<unsigned char>(peek()))) fail("invalid JSON number");
            if (peek() == '0') ++pos_;
            else while (!at_end() && std::isdigit(static_cast<unsigned char>(peek()))) ++pos_;
            if (!at_end() && peek() == '.') {
                ++pos_;
                if (at_end() || !std::isdigit(static_cast<unsigned char>(peek()))) fail("invalid JSON fraction");
                while (!at_end() && std::isdigit(static_cast<unsigned char>(peek()))) ++pos_;
            }
            if (!at_end() && (peek() == 'e' || peek() == 'E')) {
                ++pos_;
                if (!at_end() && (peek() == '+' || peek() == '-')) ++pos_;
                if (at_end() || !std::isdigit(static_cast<unsigned char>(peek()))) fail("invalid JSON exponent");
                while (!at_end() && std::isdigit(static_cast<unsigned char>(peek()))) ++pos_;
            }
            try {
                return std::stod(std::string(input_.substr(start, pos_ - start)));
            } catch (...) {
                fail("invalid JSON number");
                return 0;
            }
        }

        Json object() {
            expect('{');
            Json::Object result;
            ws();
            if (!at_end() && peek() == '}') { ++pos_; return Json(std::move(result)); }
            while (true) {
                ws();
                if (at_end() || peek() != '"') fail("JSON object key must be a string");
                const auto key = string();
                ws();
                expect(':');
                result.emplace(key, value());
                ws();
                if (at_end()) fail("unterminated JSON object");
                if (take() == '}') break;
                if (input_[pos_ - 1] != ',') fail("expected comma in JSON object");
            }
            return Json(std::move(result));
        }

        Json array() {
            expect('[');
            Json::Array result;
            ws();
            if (!at_end() && peek() == ']') { ++pos_; return Json(std::move(result)); }
            while (true) {
                result.push_back(value());
                ws();
                if (at_end()) fail("unterminated JSON array");
                if (take() == ']') break;
                if (input_[pos_ - 1] != ',') fail("expected comma in JSON array");
                ws();
            }
            return Json(std::move(result));
        }

        std::string_view input_;
        std::size_t pos_ = 0;
    };

    static void append_escaped(std::string& out, std::string_view text) {
        out.push_back('"');
        for (const char c : text) {
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::ostringstream stream;
                    stream << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<int>(static_cast<unsigned char>(c));
                    out += stream.str();
                } else out.push_back(c);
            }
        }
        out.push_back('"');
    }

    void dump_into(std::string& out) const {
        if (is_null()) { out += "null"; return; }
        if (is_bool()) { out += as_bool() ? "true" : "false"; return; }
        if (is_number()) {
            std::ostringstream stream;
            stream << std::setprecision(17) << as_number();
            out += stream.str();
            return;
        }
        if (is_string()) { append_escaped(out, as_string()); return; }
        if (is_array()) {
            out.push_back('[');
            bool first = true;
            for (const auto& item : array_items()) {
                if (!first) out.push_back(',');
                first = false;
                item.dump_into(out);
            }
            out.push_back(']');
            return;
        }
        out.push_back('{');
        bool first = true;
        for (const auto& [key, value] : object_items()) {
            if (!first) out.push_back(',');
            first = false;
            append_escaped(out, key);
            out.push_back(':');
            value.dump_into(out);
        }
        out.push_back('}');
    }
};

} // namespace paper

