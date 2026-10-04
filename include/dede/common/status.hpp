// SPDX-License-Identifier: Apache-2.0
//
// A tiny Result<T> so subsystems can report expected failures (bad address,
// unsupported instruction, parse error) without exceptions on the hot path,
// while genuinely exceptional conditions still throw DedeError.
#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace dede {

// Thrown only for programmer errors and unrecoverable states; expected failures
// travel through Result<T> instead.
class DedeError : public std::runtime_error {
public:
    explicit DedeError(std::string what) : std::runtime_error(std::move(what)) {}
};

struct Error {
    std::string message;
};

// A minimal std::expected stand-in (we target C++20, where std::expected is not
// yet guaranteed). Holds either a T or an Error.
template <typename T>
class Result {
public:
    Result(T value) : store_(std::move(value)) {}            // NOLINT: implicit by design
    Result(Error err) : store_(std::move(err)) {}            // NOLINT: implicit by design

    bool ok() const noexcept { return std::holds_alternative<T>(store_); }
    explicit operator bool() const noexcept { return ok(); }

    T& value() { return std::get<T>(store_); }
    const T& value() const { return std::get<T>(store_); }

    const Error& error() const { return std::get<Error>(store_); }
    const std::string& message() const { return std::get<Error>(store_).message; }

    // Convenience: value if present, otherwise the supplied fallback.
    T value_or(T fallback) const {
        return ok() ? std::get<T>(store_) : std::move(fallback);
    }

private:
    std::variant<T, Error> store_;
};

// Specialisation for operations that return nothing on success.
template <>
class Result<void> {
public:
    Result() = default;                                       // success
    Result(Error err) : err_(std::move(err)) {}              // NOLINT: implicit by design

    bool ok() const noexcept { return !err_.has_value(); }
    explicit operator bool() const noexcept { return ok(); }
    const Error& error() const { return *err_; }
    const std::string& message() const { return err_->message; }

private:
    std::optional<Error> err_;
};

inline Error make_error(std::string msg) { return Error{std::move(msg)}; }

}  // namespace dede
