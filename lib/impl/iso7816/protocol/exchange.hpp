/// @file
/// @brief Bounded standard APDU exchange and scope invalidation after uncertain delivery.
#pragma once

#include "../../core/operation.hpp"
#include "status.hpp"

namespace desfire::detail {
  /// Exchange a complete basic-channel short APDU under the caller's admitted deadline.
  /// Unauthenticated file reads and application FCI can use bounded GET RESPONSE under the
  /// original deadline. Each command APDU is sent once. Unknown outcomes invalidate credentials.
  result<iso7816_response> exchange_iso7816(
    card_state &state,
    byte_view command,
    const operation_context &operation
  );

  /// Discard credentials and require local reset after ambiguous exchange or integrity failure.
  /// Uncertain SELECT discards DF and EF scope. Uncertain file I/O discards EF scope.
  void invalidate_iso7816_exchange(
    card_state &state,
    std::uint8_t instruction
  ) noexcept;
}
