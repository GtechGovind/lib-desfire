/// @file
/// @brief Nonce widths and key derivation for the standard 84/82/88 handshake.
#pragma once
#include "../../crypto/openssl_crypto.hpp"
#include "../../crypto/secret_buffer.hpp"

namespace desfire::detail {
  /// Return zero for unknown algorithms. Long randoms are used by AES and three-key TDEA.
  std::size_t iso7816_nonce_size(key_type type) noexcept;

  /// Interleave the first reader random (External) and second card random (Internal).
  /// Both borrowed inputs must have the full profile width. Equal-halves TDEA uses effective DES.
  result<secret_buffer> derive_iso7816_session_key(
    key_type effective,
    byte_view reader_first,
    byte_view card_second
  );
}
