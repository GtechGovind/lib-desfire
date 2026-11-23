/// @file
/// @brief Encode basic-channel short command APDUs and reject unsupported framing before I/O.

#include "apdu_codec.hpp"

namespace desfire::detail {
  /// Encode an owned case 1 through 4 basic-channel command from borrowed payload.
  /// Include Lc only for nonempty data. An expected count of 256 becomes a wire Le of zero.
  result<bytes> encode_short_apdu(
    std::uint8_t instruction,
    std::uint8_t p1,
    std::uint8_t p2,
    byte_view data,
    const std::optional<std::uint16_t> &expected
  ) {
    if (data.size() > 255 || (expected && *expected > 256)) {
      return result<bytes>::failure({error_code::unsupported});
    }
    if (expected && *expected == 0) {
      return result<bytes>::failure({error_code::invalid_argument});
    }
    bytes command;
    command.reserve(5 + data.size() + (expected ? 1u : 0u));
    command.insert(command.end(), {0, instruction, p1, p2});
    if (!data.empty()) {
      command.push_back(static_cast<std::uint8_t>(data.size()));
      command.insert(command.end(), data.begin(), data.end());
    }
    if (expected) {
      command.push_back(static_cast<std::uint8_t>(*expected));
    }
    return result<bytes>::success(std::move(command));
  }

  /// Check the borrowed wire command's channel and length fields before transmission.
  /// Distinguish unsupported channel or extended framing from an invalid short extent.
  result<void> validate_short_apdu(byte_view command) {
    if (command.size() < 4) {
      return result<void>::failure({error_code::invalid_argument});
    }
    if (command[0] != 0 || (command.size() > 5 && command[4] == 0)) {
      return result<void>::failure({error_code::unsupported});
    }
    if (command.size() > 5) {
      const auto count = static_cast<std::size_t>(command[4]);
      if (command.size() != 5 + count && command.size() != 6 + count) {
        return result<void>::failure({error_code::invalid_argument});
      }
    }
    return result<void>::success();
  }
}
