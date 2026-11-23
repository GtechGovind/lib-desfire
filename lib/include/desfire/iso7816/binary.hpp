/// @file
/// @brief Address and length models for standard binary file operations.
#pragma once

#include <cstdint>
#include <optional>

namespace desfire {
  /// Binary address. Without a short ID the selected EF accepts offsets 0..32767.
  /// Short IDs 1..30 address a file of the current DF and accept offsets 0..255.
  struct iso7816_binary_address {
    /// Byte offset from file start. Defaults to zero.
    std::uint16_t offset{};
    /// Explicit short ID 1..30. When absent, the card uses its selected EF.
    std::optional<std::uint8_t> short_file_id;
  };

  /// Read up to length bytes. Length 1..256 is encoded as a short Le (256 uses 00).
  struct iso7816_binary_read {
    /// Binary target and byte offset.
    iso7816_binary_address address;
    /// Maximum clear byte count. Use 1..256, or 1..248 for an authenticated EV1 read.
    std::uint16_t length{};
  };
}
