/// @file
/// @brief Shared encoding, erasing ownership and public-result adaptation.

#ifndef desfire_console_command_support_hpp
#define desfire_console_command_support_hpp

#include <desfire/card.hpp>
#include <exception>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <utility>

namespace desfire_console::detail {
  using json = nlohmann::json;
  using desfire::bytes;

  /// Overwrite live elements before releasing their storage. Capacity is not inspected.
  template <class Range> void erase(Range &value) noexcept {
    if (!value.empty()) {
      volatile auto *position = value.data();
      for (std::size_t i = 0; i < value.size(); ++i) {
        position[i] = 0;
      }
    }
    value.clear();
  }

  /// Own an already-sized key or command payload and erase it on every exit path.
  /// Do not grow value after filling it: a reallocation could release an unwiped copy.
  struct secret_bytes final {
    bytes value;
    secret_bytes() = default;

    explicit secret_bytes(bytes input) : value(std::move(input)) {}

    secret_bytes(const secret_bytes &) = delete;
    secret_bytes &operator=(const secret_bytes &) = delete;

    ~secret_bytes() { erase(value); }
  };

  /// Preserve delivery and protocol details while unwinding command handlers.
  struct operation_failure final : std::exception {
    desfire::operation_error error;
    std::string message;

    explicit operation_failure(
      desfire::operation_error detail,
      std::string description = {}
    )
        : error(detail),
          message(std::move(description)) {}

    const char *what() const noexcept override { return message.c_str(); }
  };

  template <class T> T take(desfire::result<T> result) {
    if (!result) {
      throw operation_failure(result.get_error());
    }
    return std::move(result.value());
  }

  inline void take(desfire::result<void> result) {
    if (!result) {
      throw operation_failure(result.get_error());
    }
  }

  int nibble(char value) noexcept;
  bytes unhex(std::string_view value);

  template <class Range> std::string hex(const Range &value) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string output(value.size() * 2, '0');
    std::size_t position = 0;
    for (const auto byte : value) {
      const auto octet = static_cast<std::uint8_t>(byte);
      output[position++] = digits[octet >> 4];
      output[position++] = digits[octet & 15];
    }
    return output;
  }

  std::string hex_number(
    std::uint32_t value,
    unsigned width
  );
  bool valid_utf8(std::string_view value) noexcept;
  std::int64_t decimal(std::string_view value);
  desfire::key_type key_type(std::string_view name);
  std::size_t key_width(std::string_view name);
  bool same_key_family(
    std::string_view first,
    std::string_view second
  ) noexcept;
  void validate_key(
    std::string_view value,
    std::string_view type
  );
  const char *error_name(desfire::error_code code) noexcept;
  const char *delivery_name(desfire::delivery_outcome outcome) noexcept;
  json payload(const bytes &value);
  json iso_payload(const desfire::iso7816_response &value);
  json file_json(const desfire::file_settings &value);
}

#endif
