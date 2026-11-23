/// @file
/// @brief Encode and verify complete logical commands before/after transport continuation framing.
/// Profile rules choose CRC coverage, padding and MAC truncation. Only integrity-checked clear
/// response bytes leave this layer; failed verification has unknown command-delivery outcome.

#include "messaging.hpp"

#include "../protocol/crc.hpp"
#include "aes.hpp"
#include "iso.hpp"
#include "legacy.hpp"

#include <algorithm>

namespace desfire::detail {
  /// Round a clear byte count up without adding a block when it is already aligned.
  /// Require nonzero width and representable size + width - 1/rounded output; current callers use
  /// validated DESFire lengths and the fixed eight-/sixteen-byte cipher widths.
  std::size_t calculate_padded_size(
    std::size_t size,
    std::size_t width
  ) {
    return ((size + width - 1) / width) * width;
  }

  /// Extend caller-owned clear bytes with the smallest number of zero padding bytes.
  /// Require the same representable nonzero-width bounds as calculate_padded_size; allocation
  /// failure propagates and the vector keeps its original contents.
  void append_zero_padding(
    bytes &data,
    std::size_t width
  ) {
    data.resize(calculate_padded_size(data.size(), width), 0);
  }

  /// Check all borrowed padding bytes, including an empty range, without a byte-value early exit.
  /// Padding length is public framing metadata; the accumulator rejects any nonzero value.
  bool verify_zero_padding(byte_view padding) noexcept {
    std::uint8_t accumulator = 0;
    for (auto value : padding) {
      accumulator |= value;
    }
    return accumulator == 0;
  }

  /// Enforce the command policy's exact clear extent, record alignment and configured maximum.
  /// All sizes are bytes; a missing expected size permits variable lengths and record_size zero
  /// disables record alignment. This check borrows policy only and has no session effects.
  bool validate_response_length(
    const command_request &request,
    std::size_t size,
    std::size_t maximum
  ) noexcept {
    return size <= maximum && (!request.expected_size || size == *request.expected_size) &&
           (!request.record_size || size % request.record_size == 0);
  }

  namespace {
    /// Identify profiles whose retained IV advances even for commands sent in plain text.
    /// Authentication metadata is read only; an unauthenticated/legacy state returns false.
    bool has_modern_authentication(const card_state &state) {
      return state.session.profile == messaging_profile::ev1;
    }

    /// Compute the selected profile's owned wire tag from borrowed complete authenticated bytes.
    /// Require a consistent session and live crypto context. ISO/AES retain the full tag as IV;
    /// legacy uses a per-call zero chain. Argument/provider errors propagate without a wire tag.
    result<bytes> profile_mac(
      card_state &state,
      byte_view input
    ) {
      switch (state.session.profile) {
      case messaging_profile::ev1:
        return state.session.cipher == key_type::aes_128 ? aes_cmac(state, input)
                                                         : iso_cmac(state, input);
      case messaging_profile::legacy:
        return legacy_mac(state, input);
      case messaging_profile::none:
        break;
      }
      return result<bytes>::failure({error_code::invalid_state});
    }

    /// Protect/unprotect borrowed whole blocks using the authenticated session's cipher policy.
    /// Legacy uses reversed send decryption with a zero chain; ISO/AES retain ciphertext as IV.
    /// Require a consistent session/context; return owned bytes or the primitive's error.
    result<bytes> profile_crypt(
      card_state &state,
      byte_view input,
      bool sending
    ) {
      switch (state.session.profile) {
      case messaging_profile::ev1:
        return sending ? iso_encipher(state, input) : iso_decipher(state, input);
      case messaging_profile::legacy:
        return sending ? legacy_encipher(state, input) : legacy_decipher(state, input);
      case messaging_profile::none:
        break;
      }
      return result<bytes>::failure({error_code::invalid_state});
    }

    /// Return a typed verification failure without releasing unauthenticated response bytes.
    /// The card may already have executed the command, so every such error has unknown delivery;
    /// the operation layer must discard advanced IV/session state and poison the connection.
    template <class type> result<type> invalid_response(error_code code) {
      return result<type>::failure({code, delivery_outcome::unknown});
    }
  } // namespace

  /// Encode one borrowed command policy into an owned opcode/header/protected-payload sequence.
  /// Require a builder-validated policy and consistent authentication when protection is requested;
  /// CRC/MAC cover logical bytes before AF splitting. Modern profiles may advance their retained
  /// IV, including on plain commands; the operation layer owns cleanup after preparation failure.
  result<bytes> prepare_profile_command(
    card_state &state,
    const command_request &request
  ) {
    bytes wire{request.opcode};
    wire.insert(wire.end(), request.header.begin(), request.header.end());
    const auto header_size = wire.size();

    secret_buffer cleartext(bytes(header_size + request.data.size()));
    std::copy(wire.begin(), wire.end(), cleartext.data());
    if (request.data.size()) {
      std::copy_n(request.data.data(), request.data.size(), cleartext.data() + header_size);
    }

    if (request.request_mode == communication_mode::encrypted) {
      const auto skip = has_modern_authentication(state) ? 0 : request.legacy_crc_skip;
      if (skip > cleartext.size()) {
        return result<bytes>::failure({error_code::invalid_argument});
      }
      // Modern CRC32 covers opcode, clear header and payload; legacy CRC16 excludes
      // the builder-selected prefix. Additional ChangeKey CRC bytes follow this checksum.
      const bool modern_session = has_modern_authentication(state);
      secret_buffer checksum(bytes(modern_session ? 4 : 2));
      const auto covered = cleartext.view().subview(skip, cleartext.size() - skip);
      auto checksum_value = modern_session ? calculate_crc32(covered) : calculate_crc16(covered);
      // A key-changing command's CRC leaks key-derived information too. Allocate its complete
      // erased storage first rather than growing an ordinary vector through uncleansed copies.
      for (std::size_t index = 0; index < checksum.size(); ++index) {
        checksum.data()[index] = static_cast<std::uint8_t>(checksum_value >> (8 * index));
      }
      secure_zero(&checksum_value, sizeof(checksum_value));

      const auto clear_payload_size =
        request.data.size() + checksum.size() + request.extra_crc.size();
      // SetConfiguration-style marker padding is additional to the CRC, and is omitted
      // when the complete encrypted cleartext is already aligned to the cipher width.
      const bool marker =
        request.padding_marker && clear_payload_size % block_size(state.session.cipher) != 0;
      const auto payload_size = clear_payload_size + (marker ? 1 : 0);
      secret_buffer payload(
        bytes(calculate_padded_size(payload_size, block_size(state.session.cipher)))
      );
      if (request.data.size()) {
        std::copy_n(request.data.data(), request.data.size(), payload.data());
      }
      std::copy_n(checksum.data(), checksum.size(), payload.data() + request.data.size());
      if (request.extra_crc.size()) {
        std::copy_n(
          request.extra_crc.data(),
          request.extra_crc.size(),
          payload.data() + request.data.size() + checksum.size()
        );
      }
      if (marker) {
        payload.data()[clear_payload_size] = 0x80;
      }

      auto encrypted = profile_crypt(state, payload.view(), true);
      if (!encrypted) {
        return encrypted;
      }
      wire.insert(wire.end(), encrypted.value().begin(), encrypted.value().end());
    } else {
      if (request.data.size()) {
        wire.insert(wire.end(), request.data.data(), request.data.data() + request.data.size());
      }
      if (has_modern_authentication(state) || request.request_mode == communication_mode::mac) {
        const auto skip = has_modern_authentication(state) ? 0 : request.legacy_crc_skip;
        auto tag = profile_mac(state, cleartext.view().subview(skip, cleartext.size() - skip));
        if (!tag) {
          return tag;
        }
        // Plain modern commands retain their CMAC as IV but do not transmit a tag.
        // Erase the temporary in both modes, including failure while appending wire bytes.
        secret_buffer prepared_tag(std::move(tag.value()));
        if (request.request_mode == communication_mode::mac) {
          const auto tag_view = prepared_tag.view();
          wire.insert(wire.end(), tag_view.begin(), tag_view.end());
        }
      }
    }
    return result<bytes>::success(std::move(wire));
  }

  /// Prepare the complete logical wire command and reject protected sends without authentication.
  /// Borrow the policy and session key; transfer the owned prepared bytes on success. Profile
  /// errors propagate, and modern preparation can advance IV state before transport begins.
  result<prepared_command> prepare_command(
    card_state &state,
    const command_request &request
  ) {
    if (
      request.request_mode != communication_mode::plain && !require_authentication(state.session)
    ) {
      return result<prepared_command>::failure({error_code::invalid_state});
    }

    auto wire = prepare_profile_command(state, request);
    if (!wire) {
      return result<prepared_command>::failure(wire.get_error());
    }
    return result<prepared_command>::success({std::move(wire.value())});
  }

  /// Determine whether a bare status lacks the response protection required by this command.
  bool requires_response_integrity(
    const card_state &state,
    const command_request &request
  ) noexcept {
    return !request.unprotected_response &&
           (request.response_mode == communication_mode::encrypted ||
            state.session.profile == messaging_profile::ev1 || request.legacy_mac_response);
  }

  /// Verify/decrypt a reassembled response under the borrowed command's exact protection policy.
  /// Require a consistent session for protected replies. Authenticate logical data plus modern
  /// status, validate CRC/padding/lengths, and return independently owned clear bytes only after
  /// success. Failure returns unknown delivery; callers clear any advanced IV/session state.
  result<bytes> verify_profile_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  ) {
    const auto input = byte_view(response.data);
    const bool modern_session = has_modern_authentication(state);

    if (request.unprotected_response) {
      if (!validate_response_length(request, input.size(), state.options.max_response_size)) {
        return invalid_response<bytes>(error_code::malformed_response);
      }
      return result<bytes>::success(response.data);
    }

    if (request.response_mode == communication_mode::encrypted) {
      if (
        !require_authentication(state.session) || input.empty() ||
        input.size() % block_size(state.session.cipher)
      ) {
        return invalid_response<bytes>(error_code::malformed_response);
      }

      auto decrypted = profile_crypt(state, input, false);
      if (!decrypted) {
        return invalid_response<bytes>(error_code::crypto_error);
      }

      secret_buffer cleartext(std::move(decrypted.value()));
      const std::size_t checksum_size = modern_session ? 4 : 2;
      const auto width = block_size(state.session.cipher);
      std::optional<std::size_t> verified_size;
      bool checksum_found = false;
      // The verified clear length locates the CRC: do not strip trailing zero data.
      // Test at most one block of padding and reject ambiguous CRC/padding boundaries.
      for (std::size_t padding = 0; padding < width && padding + checksum_size <= cleartext.size();
           ++padding) {
        const auto size = cleartext.size() - padding - checksum_size;
        if (!validate_response_length(request, size, state.options.max_response_size)) {
          continue;
        }
        secret_buffer crc_input(bytes(size + (modern_session ? 1 : 0)));
        if (size) {
          std::copy_n(cleartext.data(), size, crc_input.data());
        }
        // ISO/AES response CRC covers the final native status after the clear data.
        if (modern_session) {
          crc_input.data()[size] = response.status;
        }
        auto stored = cleartext.view().subview(size, checksum_size);
        const bool checksum_ok = modern_session ? verify_crc32(crc_input.view(), stored)
                                                : verify_crc16(crc_input.view(), stored);
        if (!checksum_ok) {
          continue;
        }
        checksum_found = true;
        if (!verify_zero_padding(cleartext.view().subview(size + checksum_size, padding))) {
          continue;
        }
        if (verified_size) {
          return invalid_response<bytes>(error_code::malformed_response);
        }
        verified_size = size;
      }

      if (!verified_size) {
        return invalid_response<bytes>(
          checksum_found ? error_code::invalid_padding : error_code::crc_mismatch
        );
      }
      return result<bytes>::success(bytes(cleartext.data(), cleartext.data() + *verified_size));
    }

    if (requires_response_integrity(state, request)) {
      const std::size_t tag_size = modern_session ? 8 : 4;
      if (input.size() < tag_size) {
        return invalid_response<bytes>(error_code::malformed_response);
      }
      const auto size = input.size() - tag_size;
      if (!validate_response_length(request, size, state.options.max_response_size)) {
        return invalid_response<bytes>(error_code::malformed_response);
      }
      // CMAC covers the reassembled payload and final status, without transport AF prefixes.
      bytes authenticated_input(input.begin(), input.begin() + size);
      if (modern_session) {
        authenticated_input.push_back(response.status);
      }
      auto tag = profile_mac(state, byte_view(authenticated_input));
      if (!tag) {
        return invalid_response<bytes>(error_code::crypto_error);
      }
      // A mismatched expected tag is untransmitted key-derived state; erase it after comparison.
      secret_buffer expected_tag(std::move(tag.value()));
      if (!constant_time_equal(expected_tag.view(), input.subview(size, tag_size))) {
        return invalid_response<bytes>(error_code::mac_mismatch);
      }
      return result<bytes>::success(bytes(input.begin(), input.begin() + size));
    }

    if (!validate_response_length(request, input.size(), state.options.max_response_size)) {
      return invalid_response<bytes>(error_code::malformed_response);
    }
    return result<bytes>::success(response.data);
  }

  /// Dispatch response integrity/length checks for a complete transport-reassembled reply.
  /// Inputs remain borrowed and unchanged; the profile can advance retained IV state. Transfer
  /// only verified owned clear bytes or a delivery-aware error for operation-level cleanup.
  result<bytes> verify_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  ) {
    return verify_profile_response(state, request, response);
  }
} // namespace desfire::detail
