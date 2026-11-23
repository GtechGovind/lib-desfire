/// @file
/// @brief Preserve exact ISO response status and distinguish malformed status from rejection.

#include "status.hpp"

namespace desfire::detail {
  /// Preserve both ISO status bytes alongside the supplied host error and delivery outcome.
  operation_error iso7816_error(
    error_code code,
    delivery_outcome outcome,
    std::uint16_t word
  ) noexcept {
    return {code, outcome, {}, {}, word};
  }

  /// Extract the last two bytes as a numeric status word before validating their meaning.
  std::optional<std::uint16_t> read_iso7816_status_word(byte_view raw) noexcept {
    if (raw.size() < 2) {
      return {};
    }
    const auto size = raw.size();
    return static_cast<std::uint16_t>((raw[size - 2] << 8) | raw[size - 1]);
  }

  /// Split a complete response APDU into owned data and numeric status.
  /// Wrong-path native status and abort status accompanied by data leave delivery uncertain.
  result<iso7816_response> parse_iso7816_response(byte_view raw) {
    const auto status = read_iso7816_status_word(raw);
    if (!status) {
      return result<iso7816_response>::failure(
        {error_code::malformed_response, delivery_outcome::unknown}
      );
    }
    const auto size = raw.size() - 2;
    const auto word = *status;
    const auto sw1 = word >> 8;
    if (
      (word != 0x9000 && (sw1 < 0x61 || sw1 > 0x6f)) || (sw1 >= 0x64 && sw1 <= 0x6f && size != 0)
    ) {
      return result<iso7816_response>::failure(
        iso7816_error(error_code::malformed_response, delivery_outcome::unknown, word)
      );
    }
    return result<iso7816_response>::success({bytes(raw.begin(), raw.begin() + size), word});
  }

  /// Classify a terminal status for the command instruction.
  /// Allow normal success and the supported read or selection warnings. Other warning responses
  /// and state-changing errors leave execution uncertain.
  result<void> accept_iso7816_status(
    std::uint8_t instruction,
    std::uint16_t word
  ) {
    if (
      word == 0x9000 || (word == 0x6282 && (instruction == 0xb0 || instruction == 0xb2)) ||
      (word == 0x6283 && instruction == 0xa4)
    ) {
      return result<void>::success();
    }
    // Unsupported warnings and state-changing execution errors cannot establish rejection.
    const auto sw1 = word >> 8;
    const auto outcome = (sw1 >= 0x61 && sw1 <= 0x63) || sw1 == 0x65 ? delivery_outcome::unknown
                                                                     : delivery_outcome::rejected;
    return result<void>::failure(iso7816_error(error_code::card_rejected, outcome, word));
  }
}
