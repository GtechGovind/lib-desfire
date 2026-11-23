/// @file
/// Native CRC-A and DESFire CRC32 calculation, storage and verification.
/// CRC coverage is chosen by command/response policy; these helpers consume exactly
/// the supplied bytes and never add an opcode, status byte, padding or final XOR.

#include "crc.hpp"

namespace desfire::detail {

  /// Calculate legacy CRC-A with seed 0x6363 and reflected polynomial 0x8408.
  /// @param data Borrowed covered bytes, possibly empty; no input is retained or modified.
  /// @return Uncomplemented 16-bit residue, matching native GetCrc16 at 0x15320.
  std::uint16_t calculate_crc16(byte_view data) noexcept {
    std::uint16_t crc = 0x6363;
    for (auto byte : data) {
      byte ^= static_cast<std::uint8_t>(crc);
      byte ^= static_cast<std::uint8_t>(byte << 4);
      crc = static_cast<std::uint16_t>(
        (crc >> 8) ^ (static_cast<std::uint16_t>(byte) << 8) ^
        (static_cast<std::uint16_t>(byte) << 3) ^ (byte >> 4)
      );
    }
    return crc;
  }

  /// Calculate ISO/AES CRC32 with seed 0xFFFFFFFF and reflected polynomial 0xEDB88320.
  /// @param data Borrowed covered bytes, including any policy-selected status/opcode bytes.
  /// @return Uncomplemented 32-bit residue, matching native GetCrc32 at 0x152C0.
  std::uint32_t calculate_crc32(byte_view data) noexcept {
    std::uint32_t crc = 0xffffffff;
    for (auto byte : data) {
      crc ^= byte;
      for (unsigned bit = 0; bit < 8; ++bit) {
        crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320u : 0u);
      }
    }
    return crc;
  }

  /// Append a legacy checksum in two-byte little-endian wire order.
  /// @param output Owned destination, extended by two bytes.
  /// @param data Borrowed covered bytes; may alias output because calculation finishes before
  /// growth.
  /// @throws std::bad_alloc If the destination cannot grow.
  void append_crc16(
    bytes &output,
    byte_view data
  ) {
    const auto crc = calculate_crc16(data);
    output.push_back(static_cast<std::uint8_t>(crc));
    output.push_back(static_cast<std::uint8_t>(crc >> 8));
  }

  /// Append a modern checksum in four-byte little-endian wire order.
  /// @param output Owned destination, extended by four bytes.
  /// @param data Borrowed covered bytes; may alias output because calculation finishes before
  /// growth.
  /// @throws std::bad_alloc If the destination cannot grow.
  void append_crc32(
    bytes &output,
    byte_view data
  ) {
    const auto crc = calculate_crc32(data);
    for (unsigned shift = 0; shift < 32; shift += 8) {
      output.push_back(static_cast<std::uint8_t>(crc >> shift));
    }
  }

  /// Require an exact two-byte stored CRC-A and compare with the covered input.
  /// @param data Borrowed bytes selected by the legacy message policy.
  /// @param stored Borrowed little-endian checksum; no prefix/suffix is ignored.
  /// @return True only for exact length and matching checksum; performs no allocation or session
  /// update.
  bool verify_crc16(
    byte_view data,
    byte_view stored
  ) noexcept {
    const auto crc = calculate_crc16(data);
    return stored.size() == 2 && stored[0] == static_cast<std::uint8_t>(crc) &&
           stored[1] == static_cast<std::uint8_t>(crc >> 8);
  }

  /// Compare an exact four-byte stored modern CRC without a byte-mismatch early exit.
  /// @param data Borrowed bytes selected by ISO/AES policy, including status when required.
  /// @param stored Borrowed little-endian checksum; its length must be exactly four.
  /// @return True only when every stored byte matches; performs no allocation or session update.
  bool verify_crc32(
    byte_view data,
    byte_view stored
  ) noexcept {
    if (stored.size() != 4) {
      return false;
    }
    const auto crc = calculate_crc32(data);
    std::uint8_t different = 0;
    for (unsigned index = 0; index < 4; ++index) {
      different = static_cast<std::uint8_t>(different | (stored[index] ^ (crc >> (8 * index))));
    }
    return different == 0;
  }
} // namespace desfire::detail
