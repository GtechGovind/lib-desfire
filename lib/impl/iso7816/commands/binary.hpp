/// @file
/// @brief Shared ISO binary and record dispatch with clear-response bounds.
#pragma once

#include "../protocol/exchange.hpp"
#include <desfire/iso7816/binary.hpp>

namespace desfire::detail {
  /// Read once under ISO admission, verify protection and enforce both requested and clear limits.
  result<iso7816_response> read_iso7816_file(
    card_state &state,
    std::uint8_t instruction,
    std::uint8_t p1,
    std::uint8_t p2,
    std::uint16_t length,
    const std::optional<std::uint8_t> &short_file_id
  );

  /// Send one plain mutation APDU and reject unexpected response payload before reporting success.
  result<void> write_iso7816_file(
    card_state &state,
    std::uint8_t instruction,
    std::uint8_t p1,
    std::uint8_t p2,
    byte_view data,
    const std::optional<std::uint8_t> &short_file_id
  );
}
