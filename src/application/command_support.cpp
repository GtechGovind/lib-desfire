/// @file
/// @brief Bounded text/byte conversions and metadata-only result serialization.

#include "command_support.hpp"
#include <charconv>
#include <stdexcept>

namespace desfire_console::detail {
  int nibble(char value) noexcept {
    if (value >= '0' && value <= '9') {
      return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
      return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
      return value - 'A' + 10;
    }
    return -1;
  }

  bytes unhex(std::string_view value) {
    if ((value.size() & 1) != 0) {
      throw std::invalid_argument("Hex input must contain complete bytes");
    }
    secret_bytes output(bytes(value.size() / 2));
    for (std::size_t i = 0; i < output.value.size(); ++i) {
      const auto high = nibble(value[2 * i]);
      const auto low = nibble(value[2 * i + 1]);
      if (high < 0 || low < 0) {
        throw std::invalid_argument("Hex input contains a non-hex character");
      }
      output.value[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return std::move(output.value);
  }

  std::string hex_number(
    std::uint32_t value,
    unsigned width
  ) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string output(width, '0');
    for (unsigned i = 0; i < width; ++i) {
      output[width - 1 - i] = digits[value & 15];
      value >>= 4;
    }
    return output;
  }

  bool valid_utf8(std::string_view value) noexcept {
    std::size_t i = 0;
    while (i < value.size()) {
      const auto first = static_cast<unsigned char>(value[i++]);
      if (first < 0x80) {
        if (first == 0) {
          return false;
        }
        continue;
      }
      unsigned count = 0;
      std::uint32_t point = 0;
      std::uint32_t minimum = 0;
      if (first >= 0xc2 && first <= 0xdf) {
        count = 1;
        point = first & 31;
        minimum = 0x80;
      } else if (first >= 0xe0 && first <= 0xef) {
        count = 2;
        point = first & 15;
        minimum = 0x800;
      } else if (first >= 0xf0 && first <= 0xf4) {
        count = 3;
        point = first & 7;
        minimum = 0x10000;
      } else {
        return false;
      }
      if (count > value.size() - i) {
        return false;
      }
      for (unsigned n = 0; n < count; ++n) {
        const auto next = static_cast<unsigned char>(value[i++]);
        if ((next & 0xc0) != 0x80) {
          return false;
        }
        point = (point << 6) | (next & 63);
      }
      if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
        return false;
      }
    }
    return true;
  }

  std::int64_t decimal(std::string_view value) {
    if (value.empty()) {
      throw std::invalid_argument("A decimal integer is required");
    }
    std::int64_t output{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), output);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
      throw std::invalid_argument("Invalid or overflowing decimal integer");
    }
    return output;
  }

  desfire::key_type key_type(std::string_view name) {
    if (name == "des") {
      return desfire::key_type::des;
    }
    if (name == "tdes_2k") {
      return desfire::key_type::tdes_2k;
    }
    if (name == "tdes_3k") {
      return desfire::key_type::tdes_3k;
    }
    if (name == "aes_128") {
      return desfire::key_type::aes_128;
    }
    throw std::invalid_argument("Unknown key type");
  }

  std::size_t key_width(std::string_view name) {
    switch (key_type(name)) {
    case desfire::key_type::des:
      return 8;
    case desfire::key_type::tdes_2k:
    case desfire::key_type::aes_128:
      return 16;
    case desfire::key_type::tdes_3k:
      return 24;
    }
    throw std::invalid_argument("Unknown key type");
  }

  bool same_key_family(
    std::string_view first,
    std::string_view second
  ) noexcept {
    return first == second ||
           ((first == "des" || first == "tdes_2k") && (second == "des" || second == "tdes_2k"));
  }

  void validate_key(
    std::string_view value,
    std::string_view type
  ) {
    if (value.size() != 2 * key_width(type)) {
      throw std::invalid_argument("Key length does not match key type");
    }
  }

  const char *error_name(desfire::error_code code) noexcept {
    switch (code) {
    case desfire::error_code::invalid_argument:
      return "invalid_argument";
    case desfire::error_code::invalid_state:
      return "invalid_state";
    case desfire::error_code::busy:
      return "busy";
    case desfire::error_code::unsupported:
      return "unsupported";
    case desfire::error_code::transport_error:
      return "transport_error";
    case desfire::error_code::timeout:
      return "timeout";
    case desfire::error_code::card_rejected:
      return "card_rejected";
    case desfire::error_code::authentication_failed:
      return "authentication_failed";
    case desfire::error_code::mac_mismatch:
      return "mac_mismatch";
    case desfire::error_code::crc_mismatch:
      return "crc_mismatch";
    case desfire::error_code::invalid_padding:
      return "invalid_padding";
    case desfire::error_code::malformed_response:
      return "malformed_response";
    case desfire::error_code::response_too_large:
      return "response_too_large";
    case desfire::error_code::buffer_too_small:
      return "buffer_too_small";
    case desfire::error_code::continuation_limit:
      return "continuation_limit";
    case desfire::error_code::crypto_error:
      return "crypto_error";
    case desfire::error_code::allocation_failed:
      return "allocation_failed";
    case desfire::error_code::callback_failed:
      return "callback_failed";
    }
    return "invalid_state";
  }

  const char *delivery_name(desfire::delivery_outcome outcome) noexcept {
    switch (outcome) {
    case desfire::delivery_outcome::not_sent:
      return "not_sent";
    case desfire::delivery_outcome::rejected:
      return "rejected";
    case desfire::delivery_outcome::succeeded:
      return "succeeded";
    case desfire::delivery_outcome::unknown:
      return "unknown";
    }
    return "unknown";
  }

  json payload(const bytes &value) {
    return {{"data", hex(value)}, {"length", value.size()}};
  }

  json iso_payload(const desfire::iso7816_response &value) {
    auto output = payload(value.data);
    output["iso_status"] = hex_number(value.status_word, 4);
    return output;
  }

  namespace {
    const char *communication_name(desfire::communication_mode mode) noexcept {
      switch (mode) {
      case desfire::communication_mode::plain:
        return "plain";
      case desfire::communication_mode::mac:
        return "mac";
      case desfire::communication_mode::encrypted:
        return "encrypted";
      }
      return "plain";
    }

    const char *file_type_name(desfire::file_type type) noexcept {
      switch (type) {
      case desfire::file_type::standard_data:
        return "standard_data";
      case desfire::file_type::backup_data:
        return "backup_data";
      case desfire::file_type::value:
        return "value";
      case desfire::file_type::linear_record:
        return "linear_record";
      case desfire::file_type::cyclic_record:
        return "cyclic_record";
      }
      return "standard_data";
    }
  }

  json file_json(const desfire::file_settings &value) {
    json output = {
      {"type", file_type_name(value.type)},
      {"mode", communication_name(value.mode)},
      {"access",
       {{"read", value.access.read},
        {"write", value.access.write},
        {"read_write", value.access.read_write},
        {"change", value.access.change}}}
    };
    if (const auto *data = std::get_if<desfire::data_file_info>(&value.information)) {
      output["information"] = {{"size", data->size}};
    } else if (const auto *amount = std::get_if<desfire::value_file_info>(&value.information)) {
      output["information"] = {
        {"lower_limit", amount->lower_limit},
        {"upper_limit", amount->upper_limit},
        {"limited_credit_value", amount->limited_credit_value},
        {"limited_credit_enabled", amount->limited_credit_enabled}
      };
    } else if (const auto *record = std::get_if<desfire::record_file_info>(&value.information)) {
      output["information"] = {
        {"record_size", record->record_size},
        {"max_records", record->max_records},
        {"current_records", record->current_records}
      };
    }
    return output;
  }
}
