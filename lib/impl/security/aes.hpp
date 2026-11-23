#pragma once

#include "messaging.hpp"

namespace desfire::detail {
  /// Encrypt complete AES blocks and retain the last ciphertext block as the next session IV.
  result<bytes> aes_encipher(
    card_state &state,
    byte_view input
  );

  /// Decrypt complete AES blocks and retain the last input block as the next session IV.
  result<bytes> aes_decipher(
    card_state &state,
    byte_view input
  );

  /// Advance the full sixteen-byte CMAC IV, then return its leading eight transmitted bytes.
  result<bytes> aes_cmac(
    card_state &state,
    byte_view input
  );
} // namespace desfire::detail
