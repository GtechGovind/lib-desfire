/// @file
/// Data-file request policies and byte-oriented read/write entry points.
/// Offsets and lengths use bytes. Encryption leaves the native seven-byte parameter
/// header clear and protects the payload with profile-specific CRC and padding.

#include "../protocol/codec.hpp"
#include "builders.hpp"

namespace desfire::detail {

  /// Build ReadData with a bounded 24-bit byte range and explicit response protection.
  /// @param file Native file number, 0..31.
  /// @param mode File communication mode; MAC/encrypted reads require authentication.
  /// @param offset Starting byte offset; offset plus length must fit the file-size field.
  /// @param length Clear response bytes, or zero for plain/MAC read-all only.
  /// @return Read policy, or invalid_argument before preparation. Encrypted reads require an exact
  /// clear length because CRC-A residues cannot safely identify trailing zero data.
  command_result build_read_data(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    std::uint32_t length
  ) {
    // Native read helper 0x16404 locates the encrypted CRC at the caller's exact length.
    // Legacy CRC residue also validates data+CRC followed by zeros, so guessing is ambiguous.
    if (
      file > 31 || !valid_mode(mode) || offset > 0xffffff || length > 0xffffff ||
      static_cast<std::uint64_t>(offset) + length > 0xffffff ||
      (mode == communication_mode::encrypted && length == 0)
    ) {
      return invalid_command();
    }
    auto request =
      management_command(0xbd, {file}, length ? std::optional<std::size_t>(length) : std::nullopt);
    append_u24_le(request.header, offset);
    append_u24_le(request.header, length);
    request.response_mode = mode;
    request.legacy_mac_response = mode == communication_mode::mac;
    request.requires_authentication = mode != communication_mode::plain;
    return command_result::success(std::move(request));
  }

  /// Build an owned WriteData payload suitable for native AF upload continuation.
  /// @param file Native file number, 0..31.
  /// @param mode Protection of the copied outgoing data; nonplain execution requires
  /// authentication.
  /// @param offset Starting byte offset; offset plus data size must fit 24 bits.
  /// @param data Borrowed payload, copied into erasing storage; its length becomes the wire length.
  /// @return Status-only write policy, or invalid_argument. Legacy CRC/MAC skips opcode plus the
  /// seven-byte header; modern coverage includes those bytes before encryption.
  command_result build_write_data(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    byte_view data
  ) {
    if (
      file > 31 || !valid_mode(mode) || offset > 0xffffff || data.size() > 0xffffff ||
      static_cast<std::uint64_t>(offset) + data.size() > 0xffffff
    ) {
      return invalid_command();
    }
    auto request = management_command(0x3d, {file});
    append_u24_le(request.header, offset);
    append_u24_le(request.header, static_cast<std::uint32_t>(data.size()));
    request.data = secret_buffer(data);
    request.allow_upload_chaining = true;
    request.request_mode = mode;
    request.legacy_crc_skip = 8;
    return command_result::success(std::move(request));
  }
} // namespace desfire::detail

namespace desfire {

  /// Read bytes only after operation admission, preflight limits and response verification.
  /// @param file Native file number, 0..31.
  /// @param mode Expected file communication mode.
  /// @param offset Starting byte offset in the selected file.
  /// @param length Exact clear byte count, or zero for plain/MAC read-all within max_response_size.
  /// @return Owned verified data or an operation error; no partial plaintext escapes on failure.
  result<bytes> card::read_data(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    std::uint32_t length
  ) {
    return detail::run_command<bytes>(
      mutable_state(),
      [&] {
        if (length > mutable_state().options.max_response_size) {
          return detail::invalid_command();
        }
        return detail::build_read_data(file, mode, offset, length);
      },
      [](detail::byte_view data) {
        return result<bytes>::success(bytes(data.begin(), data.end()));
      }
    );
  }

  /// Write a borrowed byte sequence through one serialized, possibly chained operation.
  /// @param file Native file number, 0..31.
  /// @param mode Outgoing payload protection.
  /// @param offset Starting byte offset; range must fit 24 bits.
  /// @param data Bytes valid for this call; copied into the request before transport callbacks run.
  /// @return Verified status-only success or an error; uncertain delivery never causes a retry.
  result<void> card::write_data_bytes(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    detail::byte_view data
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_write_data(file, mode, offset, data);
    });
  }
} // namespace desfire
