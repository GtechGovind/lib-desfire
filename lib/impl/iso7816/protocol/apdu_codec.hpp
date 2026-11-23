/// @file
/// @brief Basic-channel command encoding and short APDU framing validation.
#pragma once

#include <desfire/buffer/byte_view.hpp>
#include <desfire/common/result.hpp>

namespace desfire::detail {
  /// Encode one case 1, 2, 3 or 4 short command at basic channel CLA=00.
  /// Data is copied into the transmitted command and limited to 255 bytes. Optional Le is a host
  /// length 1..256. The wire represents 256 as zero.
  result<bytes> encode_short_apdu(
    std::uint8_t instruction,
    std::uint8_t p1,
    std::uint8_t p2,
    byte_view data = {},
    const std::optional<std::uint16_t> &expected = {}
  );

  /// Validate the basic-channel header and short Lc/Le consistency before any transmission.
  result<void> validate_short_apdu(byte_view command);
}
