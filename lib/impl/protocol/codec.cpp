/// @file
/// Explicit native integer encoding and bounded response-structure parsing.
/// Parsers return owned values and mark malformed payloads as unknown delivery; they
/// never mutate the live session. Their callers clear authentication on parse failure.

#include "codec.hpp"
#include <algorithm>
#include <cstring>

namespace desfire::detail {

  namespace {

    /// Read a bounded little-endian integer prefix without alignment or host-endian assumptions.
    /// @param input Borrowed bytes; only the requested prefix is consumed.
    /// @param size Internal byte width, always 2, 3 or 4; at most 4 keeps every shift within
    /// uint32_t.
    /// @return Unsigned numeric value.
    /// @throws std::out_of_range If the input prefix is truncated.
    std::uint32_t read_integer(
      byte_view input,
      std::size_t size
    ) {
      if (input.size() < size) {
        throw std::out_of_range("truncated integer");
      }
      std::uint32_t value = 0;
      for (std::size_t index = 0; index < size; ++index) {
        value |= static_cast<std::uint32_t>(input[index]) << (index * 8);
      }
      return value;
    }

    /// Construct a structural response failure after the card may already have executed a command.
    /// @tparam type Parsed result type; no partial value is returned.
    /// @return malformed_response with unknown delivery, allowing run_command to invalidate the
    /// session.
    template <class type> result<type> malformed() {
      return result<type>::failure({error_code::malformed_response, delivery_outcome::unknown});
    }
  } // namespace

  /// Append exactly two little-endian bytes, independently of host representation.
  /// @param output Owned destination, extended without modifying its existing prefix.
  /// @param value Numeric 16-bit field; allocation failure propagates to the operation boundary.
  void append_u16_le(
    bytes &output,
    std::uint16_t value
  ) {
    for (unsigned index = 0; index < 2; ++index) {
      output.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }
  }

  /// Append the low three bytes of a native 24-bit numeric field.
  /// @param output Owned destination, extended by three bytes.
  /// @param value Caller-validated value at most 0xFFFFFF; high bits would otherwise be omitted.
  /// @throws std::bad_alloc If extending the destination cannot allocate.
  void append_u24_le(
    bytes &output,
    std::uint32_t value
  ) {
    for (unsigned index = 0; index < 3; ++index) {
      output.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }
  }

  /// Append a complete 32-bit field in native least-significant-byte-first order.
  /// @param output Owned destination, extended by four bytes.
  /// @param value Unsigned value, or the modulo-2^32 representation of a signed value.
  /// @throws std::bad_alloc If destination growth cannot allocate.
  void append_u32_le(
    bytes &output,
    std::uint32_t value
  ) {
    for (unsigned index = 0; index < 4; ++index) {
      output.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }
  }

  /// Decode a two-byte prefix as an unsigned native numeric field.
  /// @param input Borrowed bytes; trailing bytes are ignored.
  /// @return Numeric 16-bit value.
  /// @throws std::out_of_range If fewer than two bytes are present.
  std::uint16_t read_u16_le(byte_view input) {
    return static_cast<std::uint16_t>(read_integer(input, 2));
  }

  /// Decode a three-byte prefix without host padding or sign extension.
  /// @param input Borrowed bytes; trailing bytes are ignored.
  /// @return Numeric value in 0..0xFFFFFF.
  /// @throws std::out_of_range If fewer than three bytes are present.
  std::uint32_t read_u24_le(byte_view input) {
    return read_integer(input, 3);
  }

  /// Decode all four bytes of a native unsigned integer prefix.
  /// @param input Borrowed bytes; trailing bytes are ignored.
  /// @return Numeric 32-bit value.
  /// @throws std::out_of_range If fewer than four bytes are present.
  std::uint32_t read_u32_le(byte_view input) {
    return read_integer(input, 4);
  }

  /// Preserve the card's two's-complement signed 32-bit bit pattern.
  /// @param input Borrowed bytes; the four-byte little-endian prefix is decoded first.
  /// @return Signed native value; memcpy avoids an out-of-range unsigned-to-signed cast on the
  /// supported two's-complement targets.
  /// @throws std::out_of_range If fewer than four bytes are present.
  std::int32_t read_i32_le(byte_view input) {
    auto value = read_u32_le(input);
    std::int32_t signed_value;
    std::memcpy(&signed_value, &value, sizeof(value));
    return signed_value;
  }

  /// Encode a caller-validated numeric application identifier, including zero for PICC scope.
  /// @param output Owned destination, extended by three bytes.
  /// @param value AID in 0..0xFFFFFF; validation belongs to the specific command policy.
  void append_application_id(
    bytes &output,
    std::uint32_t value
  ) {
    append_u24_le(output, value);
  }

  /// Pack validated access selectors into the card's two-byte nibble order.
  /// @param output Owned destination, extended by two bytes.
  /// @param access Four selectors in 0..15; read_write/change precede read/write.
  /// @pre valid_access(access); this low-level encoder deliberately does not mask invalid
  /// selectors.
  void append_access_rights(
    bytes &output,
    const access_rights &access
  ) {
    output.push_back(static_cast<std::uint8_t>((access.read_write << 4) | access.change));
    output.push_back(static_cast<std::uint8_t>((access.read << 4) | access.write));
  }

  /// Unpack two native access bytes into named read/write/read_write/change selectors.
  /// @param input Borrowed two-byte prefix; every possible nibble is a valid raw selector.
  /// @return Independent numeric selectors, without retaining the input.
  /// @throws std::out_of_range If fewer than two bytes are present.
  access_rights read_access_rights(byte_view input) {
    if (input.size() < 2) {
      throw std::out_of_range("truncated access rights");
    }
    return {
      static_cast<std::uint8_t>(input[1] >> 4),
      static_cast<std::uint8_t>(input[1] & 15),
      static_cast<std::uint8_t>(input[0] >> 4),
      static_cast<std::uint8_t>(input[0] & 15)
    };
  }

  /// Recognize only plain (0), MAC (1) and encrypted (3) communication encodings.
  /// @param mode Candidate enum, possibly formed from untrusted response bytes.
  /// @return False for reserved or unknown encodings; no allocation or state mutation occurs.
  bool valid_mode(communication_mode mode) noexcept {
    return mode == communication_mode::plain || mode == communication_mode::mac ||
           mode == communication_mode::encrypted;
  }

  /// Check that all four access selectors fit one native nibble.
  /// @param access Candidate key/free-access/denied selectors.
  /// @return True for 0..15, including 0xE and 0xF; application-specific key counts remain card
  /// policy.
  bool valid_access(const access_rights &access) noexcept {
    return access.read <= 15 && access.write <= 15 && access.read_write <= 15 &&
           access.change <= 15;
  }

  /// Decode a complete concatenation of native three-byte application IDs.
  /// @param input Borrowed verified response bytes, possibly empty.
  /// @return Owned numeric IDs, or malformed_response/unknown for a partial final ID.
  /// No partial result is exposed; allocation failure propagates to the operation boundary.
  result<std::vector<std::uint32_t>> parse_application_ids(byte_view input) {
    if (input.size() % 3) {
      return malformed<std::vector<std::uint32_t>>();
    }
    std::vector<std::uint32_t> output;
    for (std::size_t offset = 0; offset < input.size(); offset += 3) {
      output.push_back(read_u24_le(input.subview(offset, 3)));
    }
    return result<std::vector<std::uint32_t>>::success(std::move(output));
  }

  /// Copy native file numbers while rejecting values outside the card's 0..31 range.
  /// @param input Borrowed verified response bytes; an empty enumeration is valid.
  /// @return Owned file IDs or malformed_response/unknown; no partial output escapes on rejection.
  result<std::vector<std::uint8_t>> parse_file_ids(byte_view input) {
    bytes output;
    for (auto file : input) {
      if (file > 31) {
        return malformed<bytes>();
      }
      output.push_back(file);
    }
    return result<bytes>::success(std::move(output));
  }

  /// Decode a complete concatenation of little-endian ISO file identifiers.
  /// @param input Borrowed verified response bytes; length must be even, including zero.
  /// @return Owned numeric 16-bit IDs or malformed_response/unknown for a partial identifier.
  result<std::vector<std::uint16_t>> parse_iso_file_ids(byte_view input) {
    if (input.size() % 2) {
      return malformed<std::vector<std::uint16_t>>();
    }
    std::vector<std::uint16_t> output;
    for (std::size_t offset = 0; offset < input.size(); offset += 2) {
      output.push_back(read_u16_le(input.subview(offset, 2)));
    }
    return result<std::vector<std::uint16_t>>::success(std::move(output));
  }

  /// Parse one physical DF-name record after trailing authentication bytes are removed.
  /// @param input Borrowed frame payload: three-byte AID, two-byte ISO ID and 0..16 name bytes.
  /// @return One fully owned entry, or malformed_response/unknown for lengths outside 5..21.
  /// Physical frame boundaries are significant and must not be reconstructed from concatenated
  /// names.
  result<df_name_entry> parse_df_name_frame(byte_view input) {
    if (input.size() < 5 || input.size() > 21) {
      return malformed<df_name_entry>();
    }
    return result<df_name_entry>::success(
      {read_u24_le(input), read_u16_le(input.subview(3, 2)), bytes(input.begin() + 5, input.end())}
    );
  }

  /// Decode the exact aggregate GetVersion layout without depending on physical chaining.
  /// @param input Borrowed verified 28-byte payload: 7 hardware, 7 software, 7 UID, 5 batch and 2
  /// date bytes.
  /// @return Owned version fields or malformed_response/unknown for any other size.
  result<version_info> parse_version_info(byte_view input) {
    if (input.size() != 28) {
      return malformed<version_info>();
    }
    version_info output;
    std::copy_n(input.begin(), 7, output.hardware.begin());
    std::copy_n(input.begin() + 7, 7, output.software.begin());
    std::copy_n(input.begin() + 14, 7, output.uid.begin());
    std::copy_n(input.begin() + 21, 5, output.batch.begin());
    output.production_week = input[26];
    output.production_year = input[27];
    return result<version_info>::success(output);
  }

  /// Decode one complete settings variant selected by the native file-type byte.
  /// @param input Borrowed verified payload; valid sizes are 7 data, 17 value or 13 record bytes.
  /// @return Owned settings with signed value fields and unsigned 24-bit geometry, or
  /// malformed_response/unknown for an unknown type/mode, wrong length or nonboolean limited-credit
  /// flag. Card-reported numeric limits and occupancy are preserved without inventing host-side
  /// policy.
  result<file_settings> parse_file_settings(byte_view input) {
    if (
      input.size() < 4 || input[0] > 4 || !valid_mode(static_cast<communication_mode>(input[1]))
    ) {
      return malformed<file_settings>();
    }
    file_settings output;
    output.type = static_cast<file_type>(input[0]);
    output.mode = static_cast<communication_mode>(input[1]);
    output.access = read_access_rights(input.subview(2, 2));
    if (input[0] <= 1) {
      if (input.size() != 7) {
        return malformed<file_settings>();
      }
      output.information = data_file_info{read_u24_le(input.subview(4, 3))};
    } else if (input[0] == 2) {
      if (input.size() != 17 || input[16] > 1) {
        return malformed<file_settings>();
      }
      output.information = value_file_info{
        read_i32_le(input.subview(4, 4)),
        read_i32_le(input.subview(8, 4)),
        read_i32_le(input.subview(12, 4)),
        input[16] != 0
      };
    } else {
      if (input.size() != 13) {
        return malformed<file_settings>();
      }
      output.information = record_file_info{
        read_u24_le(input.subview(4, 3)),
        read_u24_le(input.subview(7, 3)),
        read_u24_le(input.subview(10, 3))
      };
    }
    return result<file_settings>::success(std::move(output));
  }

  /// Validate application fields before any bytes are serialized or authentication advances.
  /// @param config Nonzero 24-bit AID, raw key settings and optional numeric ISO identifier.
  /// @param name Borrowed 0..16 raw name bytes; a nonempty name requires the ISO fields.
  /// @return True when key count/family and ISO-presence flag agree with the supplied fields;
  /// no input is retained, copied or mutated.
  bool validate_application_config(
    const application_config &config,
    byte_view name
  ) noexcept {
    const auto family = config.keys.settings_2 & 0xc0;
    return config.id > 0 && config.id <= 0xffffff && (config.keys.settings_2 & 15) <= 14 &&
           family != 0xc0 && name.size() <= 16 &&
           (((config.keys.settings_2 & 0x20) != 0) == config.iso_id.has_value()) &&
           (name.empty() || config.iso_id.has_value());
  }

  /// Validate a data-file creation policy without touching session state.
  /// @param config Mode, nibble access selectors and a nonzero size in bytes.
  /// @return True only for supported mode/access and a size in 1..0xFFFFFF.
  bool validate_data_file_config(const data_file_config &config) noexcept {
    return valid_mode(config.mode) && valid_access(config.access) && config.size > 0 &&
           config.size <= 0xffffff;
  }

  /// Check inclusive signed value limits and the initial value without arithmetic narrowing.
  /// @param config File mode/access plus amounts in caller-defined units.
  /// @return True for supported mode/access, ordered limits and an initial value inside both
  /// bounds.
  bool validate_value_file_config(const value_file_config &config) noexcept {
    return valid_mode(config.mode) && valid_access(config.access) &&
           config.lower_limit <= config.upper_limit && config.initial_value >= config.lower_limit &&
           config.initial_value <= config.upper_limit;
  }

  /// Validate independent record width and capacity fields without multiplying them.
  /// @param config File mode/access, record_size in bytes and max_records in records.
  /// @return True for supported mode/access and both geometry fields in 1..0xFFFFFF;
  /// card capacity determines whether that geometry can actually be allocated.
  bool validate_record_file_config(const record_file_config &config) noexcept {
    return valid_mode(config.mode) && valid_access(config.access) && config.record_size > 0 &&
           config.record_size <= 0xffffff && config.max_records > 0 &&
           config.max_records <= 0xffffff;
  }
} // namespace desfire::detail
