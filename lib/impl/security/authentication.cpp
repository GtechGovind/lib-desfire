/// @file
/// @brief Mutual DESFire authentication and profile-specific session-key derivation.
/// Static keys protect the nonce exchange only. A verified card proof installs the derived key
/// with a fresh IV; incomplete handshakes erase temporary authentication state.

#include "authentication.hpp"

#include "iso.hpp"
#include "legacy.hpp"

#include <algorithm>

namespace desfire::detail {
  namespace {
    /// Preserve a real native rejection, but treat a phase marker in the wrong stage as uncertain.
    /// Neither success without a challenge nor an unfinished AF proof is a definite card error.
    operation_error unexpected_authentication_status(std::uint8_t status) noexcept {
      const bool phase_marker = status == 0 || status == 0xaf;
      return {
        phase_marker ? error_code::malformed_response : error_code::card_rejected,
        phase_marker ? delivery_outcome::unknown : delivery_outcome::rejected,
        status
      };
    }
  } // namespace

  /// Validate the borrowed static key's exact byte extent and its permitted authentication family.
  /// Legacy accepts DES/2K3DES, ISO additionally accepts 3K3DES, and AES accepts only AES-128.
  /// Unknown enum values fail locally without reading key contents or changing session state.
  bool validate_authentication_key(
    authentication_type family,
    key_type type,
    byte_view key
  ) noexcept {
    if (key_size(type) == 0 || key.size() != key_size(type)) {
      return false;
    }
    if (family == authentication_type::aes) {
      return type == key_type::aes_128;
    }
    if (family == authentication_type::legacy) {
      return type == key_type::des || type == key_type::tdes_2k;
    }
    return family == authentication_type::iso && type != key_type::aes_128;
  }

  /// Copy a borrowed nonce with its first byte moved to the final position.
  /// Empty input produces empty owned bytes; allocation failures propagate. Nonce callers must
  /// place the result in erasable storage because the rotation preserves secret nonce material.
  /// Allocate the final extent before copying to avoid freeing an uncleansed prefix during growth.
  bytes rotate_left(byte_view input) {
    bytes output(input.size());
    if (!input.empty()) {
      std::copy(input.begin() + 1, input.end(), output.begin());
      output.back() = input[0];
    }
    return output;
  }

  /// Verify that the borrowed card proof equals a one-byte left rotation of the host nonce.
  /// Equal-length comparisons use the constant-time primitive, including the wraparound byte;
  /// the temporary rotated nonce is erased on return or exception unwinding.
  bool verify_rotated_nonce(
    byte_view nonce,
    byte_view proof
  ) {
    secret_buffer rotated(rotate_left(nonce));
    return constant_time_equal(rotated.view(), proof);
  }

  /// Interleave host/card nonce slices into an owned, erasable DES-family session key.
  /// Require a supported DES-family type and complete nonces: eight bytes for DES/2K3DES,
  /// sixteen for 3K3DES. Inputs are borrowed and unchanged; allocation failures propagate.
  secret_buffer derive_iso_session_key(
    key_type type,
    byte_view host_nonce,
    byte_view card_nonce
  ) {
    secret_buffer output(bytes(key_size(type)));
    /// Copy matching nonce slices into consecutive host/card halves at a validated key offset.
    /// All offsets/counts below are fixed by the selected profile and fit both complete nonces.
    auto append_pair = [&](
                         std::size_t destination, ///< Destination key offset in bytes.
                         std::size_t source,      ///< Common offset in the two complete nonces.
                         std::size_t count        ///< Bytes copied from each nonce.
                       ) {
      std::copy_n(host_nonce.begin() + source, count, output.data() + destination);
      std::copy_n(card_nonce.begin() + source, count, output.data() + destination + count);
    };

    // Native ISO session derivation interleaves four-byte nonce slices.
    // 3K3DES uses offsets 0, 6 and 12 rather than three adjacent four-byte groups.
    append_pair(0, 0, 4);
    if (type == key_type::tdes_2k) {
      append_pair(8, 4, 4);
    } else if (type == key_type::tdes_3k) {
      append_pair(8, 6, 4);
      append_pair(16, 12, 4);
    }
    return output;
  }

  /// Derive the legacy DES/2K3DES session key using the common eight-byte nonce layout.
  /// Require a validated legacy type and two complete eight-byte borrowed nonces; transfer the
  /// independently owned, erasable result without retaining either input.
  secret_buffer derive_legacy_session_key(
    key_type type,
    byte_view host_nonce,
    byte_view card_nonce
  ) {
    return derive_iso_session_key(type, host_nonce, card_nonce);
  }

  /// Derive an owned AES-128 session key from two complete sixteen-byte borrowed nonces.
  /// Take each nonce's first and last four bytes, matching the native protocol rather than
  /// concatenating their adjacent halves; allocation failure leaves both inputs unchanged.
  secret_buffer derive_aes_session_key(
    byte_view host_nonce,
    byte_view card_nonce
  ) {
    // DesfireAuthenticateAES (0x16e94) selects offsets 0 and 12 from each nonce.
    secret_buffer output(bytes(16));
    std::copy_n(host_nonce.begin(), 4, output.data());
    std::copy_n(card_nonce.begin(), 4, output.data() + 4);
    std::copy_n(host_nonce.begin() + 12, 4, output.data() + 8);
    std::copy_n(card_nonce.begin() + 12, 4, output.data() + 12);
    return output;
  }

  namespace {
    /// Run one mutual-authentication exchange under the admitted operation's shared deadline.
    /// Validate key/frame metadata before transmission, then temporarily install the borrowed
    /// static key for nonce processing. Promote only a verified proof to an owned session key.
    /// Transport, card-status, length and proof failures retain their delivery meaning; the public
    /// facade must erase an incomplete session and poison the connection on unknown delivery.
    result<void> authenticate_session(
      card_state &state,
      authentication_type family,
      std::uint8_t key_number,
      key_type type,
      byte_view key,
      const operation_context &operation
    ) {
      if (key_number > 13 || !validate_authentication_key(family, type, key)) {
        return result<void>::failure({error_code::invalid_argument});
      }

      const std::size_t nonce_size =
        type == key_type::aes_128 || type == key_type::tdes_3k ? 16 : 8;
      // The AF proof carries both complete nonces in one native frame (17 or 33 bytes).
      // Reject an impossible frame bound before the initial request changes card state.
      if (nonce_size * 2 + 1 > state.options.max_frame_size) {
        return result<void>::failure({error_code::invalid_argument});
      }

      auto context = state.crypto ? result<std::shared_ptr<crypto_context>>::success(state.crypto)
                                  : create_crypto_context();
      if (!context) {
        return result<void>::failure(context.get_error());
      }
      state.crypto = context.value();

      // DesfireAuthenticate (0x16aa0) and DesfireAuthenticateISO (0x16c2c) treat equal
      // 2K3DES halves as single DES, including nonce length and derived-key selection.
      const auto declared_type = type;
      if (type == key_type::tdes_2k && constant_time_equal(key.subview(0, 8), key.subview(8, 8))) {
        type = key_type::des;
        key = key.subview(0, 8);
      }
      auto generated_nonce = generate_random_bytes(nonce_size);
      if (!generated_nonce) {
        return result<void>::failure(generated_nonce.get_error());
      }
      secret_buffer host_nonce(std::move(generated_nonce.value()));

      clear_session(state.session);
      const std::uint8_t opcode = family == authentication_type::legacy ? 0x0a
                                  : family == authentication_type::iso  ? 0x1a
                                                                        : 0xaa;
      const bytes initial{opcode, key_number};
      auto challenge = exchange_frame(state, byte_view(initial), operation);
      if (!challenge) {
        return result<void>::failure(challenge.get_error());
      }
      if (challenge.value().status != 0xaf) {
        return result<void>::failure(unexpected_authentication_status(challenge.value().status));
      }
      if (challenge.value().data.size() != nonce_size) {
        return result<void>::failure({error_code::malformed_response, delivery_outcome::unknown});
      }

      // Static-key CBC starts with a zero IV. ISO/AES retain the challenge's final
      // ciphertext block for the host proof; legacy processing resets its chain per call.
      install_authentication(state.session, family, type, key_number, secret_buffer(key));
      auto decrypted = family == authentication_type::legacy
                         ? legacy_decipher(state, byte_view(challenge.value().data))
                         : iso_decipher(state, byte_view(challenge.value().data));
      if (!decrypted) {
        return result<void>::failure({error_code::crypto_error, delivery_outcome::unknown});
      }

      secret_buffer card_nonce(std::move(decrypted.value()));
      secret_buffer proof(bytes(nonce_size * 2));
      std::copy_n(host_nonce.data(), nonce_size, proof.data());
      secret_buffer rotated(rotate_left(card_nonce.view()));
      std::copy_n(rotated.data(), nonce_size, proof.data() + nonce_size);
      auto encrypted = family == authentication_type::legacy ? legacy_encipher(state, proof.view())
                                                             : iso_encipher(state, proof.view());
      if (!encrypted) {
        return result<void>::failure({error_code::crypto_error, delivery_outcome::unknown});
      }

      bytes continuation{0xaf};
      continuation.insert(continuation.end(), encrypted.value().begin(), encrypted.value().end());
      auto reply = exchange_frame(state, byte_view(continuation), operation);
      if (!reply) {
        return result<void>::failure(reply.get_error());
      }
      if (reply.value().status != 0) {
        return result<void>::failure(unexpected_authentication_status(reply.value().status));
      }
      if (reply.value().data.size() != nonce_size) {
        return result<void>::failure({error_code::malformed_response, delivery_outcome::unknown});
      }

      auto decrypted_proof = family == authentication_type::legacy
                               ? legacy_decipher(state, byte_view(reply.value().data))
                               : iso_decipher(state, byte_view(reply.value().data));
      if (!decrypted_proof) {
        return result<void>::failure({error_code::crypto_error, delivery_outcome::unknown});
      }
      secret_buffer returned_nonce(std::move(decrypted_proof.value()));
      if (!verify_rotated_nonce(host_nonce.view(), returned_nonce.view())) {
        return result<void>::failure(
          {error_code::authentication_failed, delivery_outcome::unknown}
        );
      }

      auto session_key = family == authentication_type::aes
                           ? derive_aes_session_key(host_nonce.view(), card_nonce.view())
                           : derive_iso_session_key(type, host_nonce.view(), card_nonce.view());
      // Only a verified card proof promotes the derived key. Installing it discards
      // the static-key handshake IV and starts command protection from an all-zero IV.
      install_authentication(
        state.session, family, type, key_number, std::move(session_key), declared_type
      );
      return result<void>::success();
    }
  } // namespace

  /// Authenticate with the legacy 0x0a exchange under the caller's admitted operation.
  /// Require a validated DES/2K3DES key; use reversed send decryption and a fresh zero chain per
  /// cryptographic stage. Shared handshake errors propagate for public cleanup.
  result<void> authenticate_legacy_session(
    card_state &state,
    std::uint8_t key_number,
    key_type type,
    byte_view key,
    const operation_context &operation
  ) {
    return authenticate_session(
      state, authentication_type::legacy, key_number, type, key, operation
    );
  }

  /// Authenticate with ISO 0x1a and a borrowed DES/2K3DES/3K3DES key.
  /// Retain the final ciphertext block across challenge, host proof and card proof; only a verified
  /// result installs a fresh session IV. Shared handshake errors propagate for public cleanup.
  result<void> authenticate_iso_session(
    card_state &state,
    std::uint8_t key_number,
    key_type type,
    byte_view key,
    const operation_context &operation
  ) {
    return authenticate_session(state, authentication_type::iso, key_number, type, key, operation);
  }

  /// Authenticate with AES 0xaa using a borrowed sixteen-byte static key and two full nonces.
  /// Reuse ordinary retained-IV CBC for the handshake and reset the IV after verified derivation;
  /// propagate delivery-aware errors without exposing nonce/key intermediates.
  result<void> authenticate_aes_session(
    card_state &state,
    std::uint8_t key_number,
    byte_view key,
    const operation_context &operation
  ) {
    return authenticate_session(
      state, authentication_type::aes, key_number, key_type::aes_128, key, operation
    );
  }
} // namespace desfire::detail

namespace desfire {
  /// Admit one public handshake, validate the borrowed key and dispatch the selected family.
  /// The caller keeps key bytes alive throughout synchronous execution. An incomplete handshake
  /// erases the session; unknown delivery poisons the connection until reset. A host timeout after
  /// verified completion reports succeeded delivery and retains the aligned derived session.
  /// run_operation supplies exclusion, one deadline and exception-to-result conversion.
  result<void> card::authenticate_bytes(
    authentication_type family,
    std::uint8_t number,
    key_type type,
    detail::byte_view key
  ) {
    /// Execute validation, handshake and failure cleanup while holding one operation admission.
    /// Local key validation leaves any preceding session untouched because no exchange has begun.
    return detail::run_operation<void>(mutable_state(), [&](const auto &operation) {
      if (!detail::validate_authentication_key(family, type, key) || number > 13) {
        return result<void>::failure({error_code::invalid_argument});
      }
      auto authenticated =
        family == authentication_type::legacy
          ? detail::authenticate_legacy_session(mutable_state(), number, type, key, operation)
        : family == authentication_type::iso
          ? detail::authenticate_iso_session(mutable_state(), number, type, key, operation)
          : detail::authenticate_aes_session(mutable_state(), number, key, operation);
      if (!authenticated) {
        detail::clear_session(mutable_state().session);
        mutable_state().poisoned = authenticated.get_error().outcome == delivery_outcome::unknown;
      }
      return authenticated;
    });
  }
} // namespace desfire
