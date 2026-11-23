/// @file
/// @brief Standard DESFire authentication selects EV1 nonce slices from two different APDUs.
#include "session_derivation.hpp"
#include "../../security/authentication.hpp"

namespace desfire::detail {
  /// Get the nonce width shared by all three handshake phases. Unknown algorithms return zero.
  std::size_t iso7816_nonce_size(key_type type) noexcept {
    switch (type) {
    case key_type::des:
    case key_type::tdes_2k:
      return 8;
    case key_type::tdes_3k:
    case key_type::aes_128:
      return 16;
    }
    return 0;
  }

  /// Derive the EV1 key from the first reader nonce and the second card nonce.
  /// Both borrowed nonces must match the effective cipher's width. Transfer the derived key in
  /// erasing storage.
  result<secret_buffer> derive_iso7816_session_key(
    key_type effective,
    byte_view reader_first,
    byte_view card_second
  ) {
    const auto size = iso7816_nonce_size(effective);
    if (!size || reader_first.size() != size || card_second.size() != size) {
      return result<secret_buffer>::failure({error_code::invalid_argument});
    }
    return result<secret_buffer>::success(
      effective == key_type::aes_128 ? derive_aes_session_key(reader_first, card_second)
                                     : derive_iso_session_key(effective, reader_first, card_second)
    );
  }
}
