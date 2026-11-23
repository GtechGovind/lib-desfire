#pragma once

#include "messaging.hpp"

namespace desfire::detail {
  /// Encrypt complete DES-family or AES blocks using the retained session IV.
  /// On success, retain the last ciphertext block; failures leave the IV unchanged.
  result<bytes> iso_encipher(
    card_state &state,
    byte_view input
  );

  /// Decrypt complete blocks and retain the last input ciphertext block only on success.
  result<bytes> iso_decipher(
    card_state &state,
    byte_view input
  );

  /// Compute a full-block CMAC from the retained IV and replace it with the full resulting tag.
  result<bytes> iso_cmac(
    card_state &state,
    byte_view input
  );
} // namespace desfire::detail
