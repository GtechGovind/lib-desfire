/// @file
/// @brief Ordinary CBC and full-block CMAC with DESFire ISO/AES retained chaining state.
/// A successful primitive retains a full ciphertext/tag block; failure leaves the previous IV.

#include "iso.hpp"

#include <algorithm>

namespace desfire::detail {
  namespace {
    /// Apply ordinary CBC to borrowed whole blocks using a consistent installed session/context.
    /// Return owned ciphertext/plaintext and advance the session IV only after primitive success.
    /// Empty input preserves the IV; malformed key/block/IV metadata and provider errors propagate.
    /// Callers verify decrypted CRC/padding separately and erase plaintext they do not return.
    result<bytes> chained_cbc(
      card_state &state,
      byte_view input,
      bool encrypt
    ) {
      auto output = encrypt ? encrypt_cbc(
                                *state.crypto,
                                state.session.cipher,
                                state.session.key.view(),
                                state.session.iv.view(),
                                input
                              )
                            : decrypt_cbc(
                                *state.crypto,
                                state.session.cipher,
                                state.session.key.view(),
                                state.session.iv.view(),
                                input
                              );
      if (output && !input.empty()) {
        const auto width = block_size(state.session.cipher);
        const byte_view ciphertext = encrypt ? byte_view(output.value()) : input;
        // Native StandardTdesEncipher/Decipher (0x15990/0x15ab0) and AesEncipher/Decipher
        // (0x15bd0/0x15c1c) retain the last ciphertext block in both directions.
        std::copy_n(ciphertext.end() - width, width, state.session.iv.data());
      }
      return output;
    }
  } // namespace

  /// Encrypt complete borrowed DES-family/AES blocks from the session's retained IV.
  /// Require a consistent session/context; return owned ciphertext, retain its last block on
  /// success, and propagate primitive errors without changing the previous IV.
  result<bytes> iso_encipher(
    card_state &state,
    byte_view input
  ) {
    return chained_cbc(state, input, true);
  }

  /// Decrypt complete borrowed blocks and retain the final input ciphertext block on success.
  /// Require a consistent session/context; return owned unchecked plaintext or a primitive error.
  /// The caller supplies profile integrity checks and owns plaintext erasure after use.
  result<bytes> iso_decipher(
    card_state &state,
    byte_view input
  ) {
    return chained_cbc(state, input, false);
  }

  /// Compute a full owned CMAC from borrowed logical bytes using the session's retained IV.
  /// Require key/cipher/IV consistency and a live crypto context. On success retain the complete
  /// tag before any wire truncation; on primitive failure preserve the preceding IV.
  result<bytes> iso_cmac(
    card_state &state,
    byte_view input
  ) {
    auto tag = calculate_cmac(
      *state.crypto, state.session.cipher, state.session.key.view(), input, state.session.iv.view()
    );
    if (!tag) {
      return tag;
    }
    // Keep the full final block as chaining state; the AES wire wrapper truncates its tag.
    std::copy(tag.value().begin(), tag.value().end(), state.session.iv.data());
    return tag;
  }

  /// Encode a builder-validated ISO policy into owned logical wire bytes before AF framing.
  /// Consistent authentication/context is required for protection. Shared encoding owns CRC/MAC
  /// boundaries and IV advancement; errors propagate for operation-level cleanup.
  result<bytes> prepare_iso_command(
    card_state &state,
    const command_request &request
  ) {
    return prepare_profile_command(state, request);
  }

  /// Verify a complete borrowed ISO reply and return owned clear bytes after integrity/length
  /// checks. Shared verification uses full eight-byte CMAC tags and can advance the IV before
  /// detecting tampering; every verification failure is delivery-unknown and requires session
  /// cleanup.
  result<bytes> verify_iso_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  ) {
    return verify_profile_response(state, request, response);
  }
} // namespace desfire::detail
