/// @file
/// @brief AES profile adapters for ordinary retained-IV CBC and native eight-byte CMAC tags.
/// AES shares CBC/CMAC chaining with ISO; wire truncation preserves the full sixteen-byte IV.

#include "aes.hpp"

#include "iso.hpp"

namespace desfire::detail {
  /// Encrypt borrowed complete AES blocks with an installed AES session and live crypto context.
  /// Return owned ciphertext and retain its last block as IV only on success; primitive metadata
  /// or provider errors propagate, leaving the caller responsible for failed-session cleanup.
  result<bytes> aes_encipher(
    card_state &state,
    byte_view input
  ) {
    return iso_encipher(state, input);
  }

  /// Decrypt borrowed complete AES blocks and return owned plaintext for subsequent verification.
  /// Require an installed AES session/context; retain the final input block as IV only on success.
  /// No padding/integrity checks occur here and primitive errors propagate.
  result<bytes> aes_decipher(
    card_state &state,
    byte_view input
  ) {
    return iso_decipher(state, input);
  }

  /// Authenticate borrowed logical bytes with a consistent AES session and live crypto context.
  /// Keep the full sixteen-byte CMAC in session state, then return its leading eight wire bytes.
  /// Erase the untransmitted tail before shrinking ordinary output storage.
  /// Propagate primitive errors without updating the IV or exposing a partial tag.
  result<bytes> aes_cmac(
    card_state &state,
    byte_view input
  ) {
    auto tag = iso_cmac(state, input);
    if (tag) {
      // Transmit the leading eight bytes after iso_cmac retained the full chaining block.
      // Erase the untransmitted chaining bytes before vector shrink ends their live extent.
      secure_zero(tag.value().data() + 8, tag.value().size() - 8);
      tag.value().resize(8);
    }
    return tag;
  }

  /// Encode a builder-validated AES command policy into owned logical wire bytes.
  /// Require consistent session/context for protection; shared profile encoding controls CRC
  /// coverage and retained-IV updates, and propagates preparation errors to the operation owner.
  result<bytes> prepare_aes_command(
    card_state &state,
    const command_request &request
  ) {
    return prepare_profile_command(state, request);
  }

  /// Verify a complete AES reply and transfer owned clear data only after integrity/length checks.
  /// Borrow request/response; shared verification checks leading-eight-byte tags while retaining
  /// the full IV. Delivery-unknown failures require session cleanup by the operation owner.
  result<bytes> verify_aes_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  ) {
    return verify_profile_response(state, request, response);
  }
} // namespace desfire::detail
