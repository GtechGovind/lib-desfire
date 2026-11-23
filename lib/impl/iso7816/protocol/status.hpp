/// @file
/// @brief Standard response status extraction, validation and delivery classification.
#pragma once

#include <desfire/common/result.hpp>
#include <desfire/iso7816/status.hpp>

namespace desfire::detail {
  /// Read the trailing status bytes as wire evidence. Absence means fewer than two bytes arrived.
  std::optional<std::uint16_t> read_iso7816_status_word(byte_view raw) noexcept;

  /// Separate the trailing two-byte ISO status. Invalid SW1 or truncated data is uncertain.
  /// Preserve the exact word when available, including wrong-path native 91xx.
  result<iso7816_response> parse_iso7816_response(byte_view raw);

  /// Decide whether a terminal status permits the instruction's payload to escape.
  result<void> accept_iso7816_status(
    std::uint8_t instruction,
    std::uint16_t word
  );

  /// Build an error preserving both bytes, independently of any native status.
  operation_error iso7816_error(
    error_code code,
    delivery_outcome outcome,
    std::uint16_t word
  ) noexcept;
}
