/// @file
/// PICC management and device-identification command policies.
/// Retained SetConfiguration behavior is intentional: option 0 masks its first byte,
/// option 2 preserves raw data and marker padding, and option 3 transmits no data.

#include "../protocol/codec.hpp"
#include "builders.hpp"

namespace desfire::detail {

  /// Build authenticated PICC formatting with status-only completion.
  /// @return Management policy that requires authentication and clears it after verified success;
  /// the card entry point separately checks PICC selection.
  command_result build_format_picc() {
    auto request = management_command(0xfc);
    request.requires_authentication = true;
    request.clear_after = true;
    return command_result::success(std::move(request));
  }

  /// Build GetVersion expecting exactly 28 aggregated clear bytes.
  /// @return Management policy; transport may collect its native three physical response parts.
  command_result build_get_version() {
    return command_result::success(management_command(0x60, {}, 28));
  }

  /// Build FreeMemory expecting a three-byte little-endian byte count.
  /// @return Exact-size management policy; a modern session authenticates the response.
  command_result build_free_memory() {
    return command_result::success(management_command(0x6e, {}, 3));
  }

  /// Build the supported SetConfiguration option layouts.
  /// @param option Supported selector 0, 2 or 3; selector 1 is unsupported.
  /// @param data Nonempty borrowed input: option 0 uses its low two flag bits, option 2 copies all
  /// bytes, and option 3 requires input but emits no payload.
  /// @return Authenticated encrypted policy, or invalid_argument before I/O. Legacy CRC excludes
  /// the opcode/option; modern CRC includes them. Only option 2 requests a conditional 0x80 marker.
  command_result build_set_configuration(
    std::uint8_t option,
    byte_view data
  ) {
    if (option > 3 || option == 1 || data.empty()) {
      return invalid_command();
    }
    auto request = management_command(0x5c, {option});
    request.request_mode = communication_mode::encrypted;
    request.requires_authentication = true;
    request.legacy_crc_skip = 2;
    if (option == 0) {
      request.data = secret_buffer(bytes{static_cast<std::uint8_t>(data[0] & 3)});
    } else if (option == 2) {
      request.data = secret_buffer(data);
      request.padding_marker = true;
    }
    // The retained option-3 policy emits no payload. Do not assume a newer generation's layout.
    return command_result::success(std::move(request));
  }

  /// Build an authenticated encrypted UID query with exactly seven clear response bytes.
  /// @return Policy requiring session CRC/decryption before any UID bytes can escape.
  command_result build_get_card_uid() {
    auto request = management_command(0x51, {}, 7);
    request.requires_authentication = true;
    request.response_mode = communication_mode::encrypted;
    return command_result::success(std::move(request));
  }
} // namespace desfire::detail

namespace desfire {

  /// Format PICC scope once after checking the selected application under admission.
  /// @return Verified status-only result; non-PICC scope or absent authentication fails before I/O.
  /// Success ends authentication; uncertain delivery is surfaced without automatic replay.
  result<void> card::format_picc() {
    return detail::run_void_command(mutable_state(), [&] {
      if (!detail::is_picc_selected(mutable_state().selection)) {
        return detail::invalid_command();
      }
      return detail::build_format_picc();
    });
  }

  /// Collect, verify and parse all native hardware/software/manufacturing version bytes.
  /// @return Owned version information from exactly 28 bytes, or an operation/structure error.
  result<version_info> card::get_version() {
    return detail::run_command<version_info>(
      mutable_state(), detail::build_get_version, detail::parse_version_info
    );
  }

  /// Read the card's remaining free-memory count without host-endian assumptions.
  /// @return Verified numeric count in bytes; exact three-byte validation precedes decoding.
  result<std::uint32_t> card::free_memory() {
    return detail::run_command<std::uint32_t>(
      mutable_state(), detail::build_free_memory, [](detail::byte_view data) {
        return result<std::uint32_t>::success(detail::read_u24_le(data));
      }
    );
  }

  /// Apply a supported native configuration layout through the authenticated command path.
  /// @param option Native selector 0, 2 or 3.
  /// @param data Borrowed nonempty configuration bytes, interpreted by the selected layout.
  /// @return Verified status-only result; invalid input fails before preparation and transmission.
  result<void> card::set_configuration_bytes(
    std::uint8_t option,
    detail::byte_view data
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_set_configuration(option, data);
    });
  }

  /// Read seven UID bytes only after authenticated decryption and CRC/padding checks.
  /// @return Owned UID bytes or an operation error; absent authentication is rejected before I/O.
  result<bytes> card::get_card_uid() {
    return detail::run_command<bytes>(
      mutable_state(), detail::build_get_card_uid, [](detail::byte_view data) {
        return result<bytes>::success(bytes(data.begin(), data.end()));
      }
    );
  }
} // namespace desfire
