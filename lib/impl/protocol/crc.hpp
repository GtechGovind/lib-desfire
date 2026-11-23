/// @file
/// Native legacy/modern checksums over caller-selected byte coverage.
/// The command/response layer decides whether opcode, status or key bytes are included;
/// these functions never append padding or apply a final XOR to either CRC.

#pragma once

#include <desfire/buffer/byte_view.hpp>

namespace desfire::detail {

  /// DESFire legacy CRC-A: initial 0x6363, reflected polynomial 0x8408, no final XOR.
  std::uint16_t calculate_crc16(byte_view data) noexcept;

  /// DESFire ISO/AES CRC32: initial 0xFFFFFFFF, reflected 0xEDB88320, no final XOR.
  std::uint32_t calculate_crc32(byte_view data) noexcept;

  /// Append a legacy CRC in native little-endian order.
  /// data may alias output: the checksum is calculated before any destination growth.
  void append_crc16(
    bytes &output,
    byte_view data
  );

  /// Append a modern CRC in native little-endian order.
  /// data may alias output: the checksum is calculated before any destination growth.
  void append_crc32(
    bytes &output,
    byte_view data
  );

  /// Require exactly two stored bytes and compare with the CRC of data.
  bool verify_crc16(
    byte_view data,
    byte_view stored
  ) noexcept;

  /// Require exactly four stored bytes and compare without an early byte mismatch exit.
  bool verify_crc32(
    byte_view data,
    byte_view stored
  ) noexcept;

} // namespace desfire::detail
