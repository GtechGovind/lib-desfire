/// @file
/// Internal host-independent native field encoders, bounded parsers and creation validators.
/// Borrowed inputs are consumed synchronously; successful compound parsers return owned values.
/// Structural failures return malformed_response with unknown delivery for session invalidation.

#pragma once

#include <desfire/common/result.hpp>
#include <desfire/model/application.hpp>
#include <desfire/model/file.hpp>
#include <desfire/model/version.hpp>

namespace desfire::detail {

  /// Append the low two bytes, least-significant first.
  void append_u16_le(
    bytes &output,
    std::uint16_t value
  );

  /// Append the low three bytes; callers validate the native 24-bit field limit.
  void append_u24_le(
    bytes &output,
    std::uint32_t value
  );

  /// Append all four bytes, least-significant first.
  void append_u32_le(
    bytes &output,
    std::uint32_t value
  );

  /// Read a two-byte little-endian prefix; throws out_of_range if truncated.
  std::uint16_t read_u16_le(byte_view input);

  /// Read a three-byte little-endian prefix; throws out_of_range if truncated.
  std::uint32_t read_u24_le(byte_view input);

  /// Read a four-byte little-endian prefix; throws out_of_range if truncated.
  std::uint32_t read_u32_le(byte_view input);

  /// Read the card's signed two's-complement 32-bit prefix without an out-of-range cast.
  /// Throws out_of_range for fewer than four bytes; supported targets use two's complement.
  std::int32_t read_i32_le(byte_view input);

  /// Encode a validated numeric AID in native little-endian order.
  void append_application_id(
    bytes &output,
    std::uint32_t value
  );

  /// Encode read/write + change nibbles, then read + write nibbles.
  void append_access_rights(
    bytes &output,
    const access_rights &access
  );

  /// Decode two native access bytes; throws out_of_range if truncated.
  access_rights read_access_rights(byte_view input);

  /// Accept only the three supported on-card communication encodings.
  [[nodiscard]] bool valid_mode(communication_mode mode) noexcept;

  /// Require all four access selectors to fit a nibble, including free/denied selectors.
  [[nodiscard]] bool valid_access(const access_rights &access) noexcept;

  /// Decode complete three-byte AIDs; a partial trailing AID is malformed_response/unknown.
  result<std::vector<std::uint32_t>> parse_application_ids(byte_view input);

  /// Decode native file numbers, rejecting values outside 0..31.
  result<std::vector<std::uint8_t>> parse_file_ids(byte_view input);

  /// Decode complete two-byte ISO file identifiers; reject an odd payload length.
  result<std::vector<std::uint16_t>> parse_iso_file_ids(byte_view input);

  /// Parse exactly one physical GetDFNames frame: AID, ISO identifier and up to 16 name bytes.
  result<df_name_entry> parse_df_name_frame(byte_view input);

  /// Decode the exact 28-byte concatenated GetVersion response.
  result<version_info> parse_version_info(byte_view input);

  /// Decode a complete type-specific GetFileSettings payload, rejecting unknown layouts.
  result<file_settings> parse_file_settings(byte_view input);

  /// Check AID, key settings and consistency of optional ISO fields before serialization.
  [[nodiscard]] bool validate_application_config(
    const application_config &config,
    byte_view name
  ) noexcept;

  /// Validate mode, access and nonzero 24-bit size.
  [[nodiscard]] bool validate_data_file_config(const data_file_config &config) noexcept;

  /// Validate mode/access and that the initial signed value lies within ordered limits.
  [[nodiscard]] bool validate_value_file_config(const value_file_config &config) noexcept;

  /// Validate mode/access and nonzero 24-bit record width and capacity.
  [[nodiscard]] bool validate_record_file_config(const record_file_config &config) noexcept;

} // namespace desfire::detail
