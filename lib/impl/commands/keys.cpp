/// @file
/// Key query and encrypted key-mutation policies.
/// Replacement key material is copied into erasing storage. Modern CRC covers the
/// complete command; legacy ChangeKey CRC excludes its opcode and key selector.

#include "../protocol/crc.hpp"
#include "builders.hpp"
#include <algorithm>

namespace desfire::detail {

  /// Build encrypted ChangeKeySettings with one raw settings byte.
  /// @param settings New native key-settings byte; no host-side interpretation is applied.
  /// @return Authenticated status-only policy. Legacy CRC skips only the opcode, whereas modern
  /// CRC covers opcode plus settings; execution rejects an absent authenticated session.
  command_result build_change_key_settings(std::uint8_t settings) {
    auto request = management_command(0x54);
    request.data = secret_buffer(bytes{settings});
    request.request_mode = communication_mode::encrypted;
    request.legacy_crc_skip = 1;
    request.requires_authentication = true;
    return command_result::success(std::move(request));
  }

  /// Build the exact two-byte GetKeySettings query.
  /// @return Management policy retaining raw settings and key-family/count flag bytes.
  command_result build_get_key_settings() {
    return command_result::success(management_command(0x45, {}, 2));
  }

  /// Build a one-byte key-version query for a native application key selector.
  /// @param number Key number, 0..13.
  /// @return Exact one-byte management policy, or invalid_argument before I/O.
  command_result build_get_key_version(std::uint8_t number) {
    if (number > 13) {
      return invalid_command();
    }
    return command_result::success(management_command(0x64, {number}, 1));
  }

  namespace {

    /// Normalize validated key bytes to the native ChangeKey wire width.
    /// @param key Borrowed key matching key_size(type); DES requires eight bytes.
    /// @param type Valid DES, 2K/3K TDES or AES family established by the caller.
    /// @return Owned erasing buffer; DES duplicates its eight bytes to form the native 16-byte key,
    /// while the other families preserve all input bytes. Does not update session state.
    secret_buffer key_wire_bytes(
      byte_view key,
      key_type type
    ) {
      secret_buffer normalized(key);
      if (type == key_type::des) {
        normalized.resize(16);
        std::copy_n(normalized.data(), 8, normalized.data() + 8);
      }
      return normalized;
    }

    /// Compare application families independently of the effective cipher width.
    /// DES and 2K3DES use the same native application type and wire width.
    bool same_application_key_family(
      key_type first,
      key_type second
    ) noexcept {
      return first == second || ((first == key_type::des || first == key_type::tdes_2k) &&
                                 (second == key_type::des || second == key_type::tdes_2k));
    }
  } // namespace

  /// Build an encrypted PICC master-key family replacement under the existing session.
  /// @param session Consistent authenticated state; the caller separately enforces PICC selection.
  /// @param type New key family, encoded in the clear selector's high bits.
  /// @param key Borrowed new key with exactly the new family's size; copied into erasing storage.
  /// @param version Version byte appended only for AES replacements.
  /// @return Status-only untagged-response policy that clears authentication after success,
  /// or invalid_argument for invalid authentication, family or key width.
  command_result build_change_picc_master_key(
    const session_state &session,
    key_type type,
    byte_view key,
    std::uint8_t version
  ) {
    const auto required_key_size = key_size(type);
    if (
      !require_authentication(session) || required_key_size == 0 || key.size() != required_key_size
    ) {
      return invalid_command();
    }
    const std::uint8_t selector = type == key_type::aes_128   ? 0x80
                                  : type == key_type::tdes_3k ? 0x40
                                                              : 0;
    auto request = management_command(0xc4, {selector});
    request.data = key_wire_bytes(key, type);
    if (type == key_type::aes_128) {
      const auto size = request.data.size();
      request.data.resize(size + 1);
      request.data.data()[size] = version;
    }
    request.request_mode = communication_mode::encrypted;
    request.legacy_crc_skip = 2;
    request.requires_authentication = true;
    request.unprotected_response = true;
    request.clear_after = true;
    return command_result::success(std::move(request));
  }

  /// Compatibility builder that retains exact effective-cipher width validation for old callers.
  command_result build_change_app_key(
    const session_state &session,
    std::uint8_t number,
    byte_view old_key,
    byte_view new_key,
    std::uint8_t version
  ) {
    return build_change_app_key(
      session, number, session.cipher, old_key, session.cipher, new_key, version
    );
  }

  /// Build an explicitly typed application ChangeKey with current-key or other-key semantics.
  /// @param session Live cipher, protocol and key number determine request/response protection.
  /// @param number Replacement key number, 0..13.
  /// @param old_type Previous key material type within the authenticated application family.
  /// @param old_key Borrowed previous key with exactly key_size(old_type) bytes.
  /// @param new_type Replacement key material type within the authenticated application family.
  /// @param new_key Borrowed replacement with exactly key_size(new_type) bytes.
  /// @param version Appended only for AES and excluded from the separate new-key CRC.
  /// @return Encrypted policy or invalid_argument. Other-key payload is old XOR new followed by
  /// the command CRC then new-key CRC (0x173E0); current-key success is untagged and clears the
  /// session.
  command_result build_change_app_key(
    const session_state &session,
    std::uint8_t number,
    key_type old_type,
    byte_view old_key,
    key_type new_type,
    byte_view new_key,
    std::uint8_t version
  ) {
    if (
      number > 13 || !require_authentication(session) ||
      !same_application_key_family(old_type, session.cipher) ||
      !same_application_key_family(new_type, session.cipher) ||
      old_key.size() != key_size(old_type) || new_key.size() != key_size(new_type)
    ) {
      return invalid_command();
    }
    auto new_normalized = key_wire_bytes(new_key, new_type);
    const bool current = number == session.authenticated_key;
    auto request = management_command(0xc4, {number});
    request.data = secret_buffer(new_normalized.view());
    if (!current) {
      auto old_normalized = key_wire_bytes(old_key, old_type);
      for (std::size_t index = 0; index < request.data.size(); ++index) {
        request.data.data()[index] =
          static_cast<std::uint8_t>(request.data.data()[index] ^ old_normalized.data()[index]);
      }
    }
    if (new_type == key_type::aes_128) {
      const auto size = request.data.size();
      request.data.resize(size + 1);
      request.data.data()[size] = version;
    }
    if (!current) {
      // The second checksum is derived from unmasked key bytes, so keep its wire bytes in
      // erasing storage too; an ordinary growing vector could leave residues after reallocation.
      const bool legacy = session.authentication == authentication_type::legacy;
      const std::size_t checksum_size = legacy ? 2 : 4;
      request.extra_crc = secret_buffer(bytes(checksum_size));
      auto checksum = legacy ? static_cast<std::uint32_t>(calculate_crc16(new_normalized.view()))
                             : calculate_crc32(new_normalized.view());
      for (std::size_t index = 0; index < checksum_size; ++index) {
        request.extra_crc.data()[index] = static_cast<std::uint8_t>(checksum >> (index * 8));
      }
      secure_zero(&checksum, sizeof(checksum));
    }
    request.request_mode = communication_mode::encrypted;
    request.legacy_crc_skip = 2;
    request.requires_authentication = true;
    request.unprotected_response = current;
    request.clear_after = current;
    return command_result::success(std::move(request));
  }
} // namespace desfire::detail

namespace desfire {

  /// Encrypt and submit one key-settings change under the authenticated session.
  /// @param settings Raw native settings byte.
  /// @return Verified status-only result; absent authentication is rejected before transmission.
  result<void> card::change_key_settings(std::uint8_t settings) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_change_key_settings(settings);
    });
  }

  /// Decode the verified, exactly two-byte key-settings response without masking flags.
  /// @return Raw settings bytes or an operation error; length checks precede indexed access.
  result<key_settings> card::get_key_settings() {
    return detail::run_command<key_settings>(
      mutable_state(), detail::build_get_key_settings, [](detail::byte_view data) {
        return result<key_settings>::success({data[0], data[1]});
      }
    );
  }

  /// Read one key-version byte using a validated native selector.
  /// @param number Key number, 0..13.
  /// @return Verified byte or an operation error; the builder enforces exact response length.
  result<std::uint8_t> card::get_key_version(std::uint8_t number) {
    return detail::run_command<std::uint8_t>(
      mutable_state(),
      [&] {
        return detail::build_get_key_version(number);
      },
      [](detail::byte_view data) {
        return result<std::uint8_t>::success(data[0]);
      }
    );
  }

  /// Replace the PICC master key after checking selected scope under the operation lock.
  /// @param type New key family, independent of the currently authenticated family.
  /// @param key Borrowed replacement bytes, copied before transport callbacks run.
  /// @param version AES replacement version; ignored for DES/TDES.
  /// @return Status-only result; successful replacement ends authentication, and uncertain delivery
  /// is reported without retry. Non-PICC selection fails before preparation.
  result<void> card::change_picc_master_key_bytes(
    key_type type,
    detail::byte_view key,
    std::uint8_t version
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      if (!detail::is_picc_selected(mutable_state().selection)) {
        return detail::invalid_command();
      }
      return detail::build_change_picc_master_key(mutable_state().session, type, key, version);
    });
  }

  /// Replace one application key using the live session family and authenticated selector.
  /// @param number Target native key number, 0..13.
  /// @param old_key Borrowed old key, sized for the session family.
  /// @param new_key Borrowed replacement key of the same size.
  /// @param version Version used only for AES sessions.
  /// @return Verified result; replacing the authenticated key ends the session. Inputs are copied
  /// into erasing storage during this synchronous serialized operation.
  result<void> card::change_app_key_bytes(
    std::uint8_t number,
    detail::byte_view old_key,
    detail::byte_view new_key,
    std::uint8_t version
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      const auto aid = mutable_state().selection.native_application;
      if (!aid || *aid == 0) {
        return detail::invalid_command();
      }
      return detail::build_change_app_key(
        mutable_state().session, number, old_key, new_key, version
      );
    });
  }

  /// Replace explicitly typed material under one admission using the installed session cipher.
  /// @param number Target native key number, 0..13.
  /// @param old_type Type defining the previous key width and application family.
  /// @param old_key Borrowed prior bytes, normalized into erasing storage when needed for XOR.
  /// @param new_type Type defining the replacement width and application family.
  /// @param new_key Borrowed replacement bytes copied into erasing storage before transport.
  /// @param version AES replacement version. DES-family callers supply version bits in new_key.
  /// @return Verified status, local validation failure or a delivery-aware operation error.
  /// A verified replacement of the authenticated key clears the session.
  result<void> card::change_app_key_bytes(
    std::uint8_t number,
    key_type old_type,
    detail::byte_view old_key,
    key_type new_type,
    detail::byte_view new_key,
    std::uint8_t version
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      const auto aid = mutable_state().selection.native_application;
      if (!aid || *aid == 0) {
        return detail::invalid_command();
      }
      return detail::build_change_app_key(
        mutable_state().session, number, old_type, old_key, new_type, new_key, version
      );
    });
  }
} // namespace desfire
