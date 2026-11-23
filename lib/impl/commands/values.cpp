/// @file
/// Signed value decoding and nonnegative value-mutation request policies.
/// Amounts use the caller's units, encoded as four little-endian bytes without
/// scaling; transaction completion is always a separate explicit operation.

#include "../protocol/codec.hpp"
#include "builders.hpp"

namespace desfire::detail {

  /// Build a four-byte signed value read with file-selected response protection.
  /// @param file Native file number, 0..31.
  /// @param mode Expected response mode; MAC/encrypted reads require authentication.
  /// @return Exact-size policy or invalid_argument. Legacy MAC is requested only for MAC mode;
  /// modern sessions authenticate plain responses as well.
  command_result build_get_value(
    std::uint8_t file,
    communication_mode mode
  ) {
    if (file > 31 || !valid_mode(mode)) {
      return invalid_command();
    }
    auto request = management_command(0x6c, {file}, 4);
    request.response_mode = mode;
    request.legacy_mac_response = mode == communication_mode::mac;
    request.requires_authentication = mode != communication_mode::plain;
    return command_result::success(std::move(request));
  }

  /// Encode Credit, Debit or LimitedCredit with a nonnegative signed amount.
  /// @param opcode Caller-supplied native opcode 0x0C, 0xDC or 0x1C.
  /// @param file Native file number, 0..31.
  /// @param mode Outgoing payload protection.
  /// @param amount Nonnegative amount in caller-defined units, serialized as four little-endian
  /// bytes.
  /// @return Status-only policy or invalid_argument. Legacy CRC/MAC excludes opcode and file;
  /// modern coverage includes them. No transaction completion is implied.
  command_result build_value_mutation(
    std::uint8_t opcode,
    std::uint8_t file,
    communication_mode mode,
    std::int32_t amount
  ) {
    if (file > 31 || !valid_mode(mode) || amount < 0) {
      return invalid_command();
    }
    auto request = management_command(opcode, {file});
    bytes payload;
    append_u32_le(payload, static_cast<std::uint32_t>(amount));
    request.data = secret_buffer(std::move(payload));
    request.request_mode = mode;
    request.legacy_crc_skip = 2;
    return command_result::success(std::move(request));
  }
} // namespace desfire::detail

namespace desfire {

  /// Read and decode a signed 32-bit value after exact-length and integrity checks.
  /// @param file Native file number, 0..31.
  /// @param mode Expected file communication mode.
  /// @return Signed value in caller-defined units or an operation error; all two's-complement bits
  /// are preserved without an out-of-range unsigned-to-signed conversion.
  result<std::int32_t> card::get_value(
    std::uint8_t file,
    communication_mode mode
  ) {
    return detail::run_command<std::int32_t>(
      mutable_state(),
      [&] {
        return detail::build_get_value(file, mode);
      },
      [](detail::byte_view data) {
        return result<std::int32_t>::success(detail::read_i32_le(data));
      }
    );
  }

  /// Stage crediting a nonnegative amount to the selected value file.
  /// @param file Native file number, 0..31.
  /// @param mode Outgoing payload protection.
  /// @param amount Nonnegative amount in caller-defined units.
  /// @return Verified status-only result; invalid input fails before I/O and commit remains
  /// explicit.
  result<void> card::credit(
    std::uint8_t file,
    communication_mode mode,
    std::int32_t amount
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_value_mutation(0x0c, file, mode, amount);
    });
  }

  /// Stage debiting a nonnegative amount from the selected value file.
  /// @param file Native file number, 0..31.
  /// @param mode Outgoing payload protection.
  /// @param amount Nonnegative amount in caller-defined units.
  /// @return Verified status-only result; delivery uncertainty is reported without automatic retry.
  result<void> card::debit(
    std::uint8_t file,
    communication_mode mode,
    std::int32_t amount
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_value_mutation(0xdc, file, mode, amount);
    });
  }

  /// Stage one native limited-credit mutation, leaving card-specific limits to the card.
  /// @param file Native file number, 0..31.
  /// @param mode Outgoing payload protection.
  /// @param amount Nonnegative amount in caller-defined units.
  /// @return Verified status-only result; negative amounts fail before I/O and commit remains
  /// explicit.
  result<void> card::limited_credit(
    std::uint8_t file,
    communication_mode mode,
    std::int32_t amount
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_value_mutation(0x1c, file, mode, amount);
    });
  }
} // namespace desfire
