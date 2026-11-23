#pragma once

#include "messaging.hpp"

namespace desfire::detail {
  /// XOR-chain outgoing blocks with primitive DES/2K3DES decryption, starting from a zero IV.
  /// Require a valid legacy session and whole blocks; session IV is never retained.
  result<bytes> legacy_encipher(
    const card_state &state,
    byte_view input
  );

  /// Decrypt incoming blocks then XOR the preceding ciphertext; begin each call with a zero IV.
  result<bytes> legacy_decipher(
    const card_state &state,
    byte_view input
  );

  /// Zero-pad to whole blocks and return the first four bytes of the final CBC-encryption block.
  /// Empty input produces four zero bytes, matching the native zero-iteration MAC loop.
  result<bytes> legacy_mac(
    const card_state &state,
    byte_view input
  );
} // namespace desfire::detail
