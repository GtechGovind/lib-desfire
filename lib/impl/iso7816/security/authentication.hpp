/// @file
/// @brief Standard three-phase authentication on one admitted card operation.
#pragma once
#include "../../core/operation.hpp"

namespace desfire::detail {
  /// Run 84, 82 and 88 under the caller's single deadline. The private random source must
  /// provide two fresh independent randoms in one allocation before any APDU. The static key
  /// is borrowed only during this call. Only a verified Internal response installs credentials.
  result<void> authenticate_iso7816_session(
    card_state &state,
    std::uint8_t number,
    key_type type,
    byte_view key,
    const operation_context &operation,
    result<bytes> (*random_bytes)(std::size_t) = generate_random_bytes
  );
}
