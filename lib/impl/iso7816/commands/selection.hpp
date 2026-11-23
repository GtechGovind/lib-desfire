/// @file
/// @brief Standard selection and updates to the shared native and ISO scope.
#pragma once

#include "../protocol/exchange.hpp"
#include <desfire/iso7816/selection.hpp>

namespace desfire::detail {
  /// Select by exact file identifier or raw name, then publish the successful scope transition.
  /// The optional identifier is present for identifier-based addressing. Among DF names, only
  /// the registered DESFire PICC name establishes a known native AID.
  result<iso7816_response> select_iso7816_scope(
    card_state &state,
    std::uint8_t p1,
    byte_view data,
    const std::optional<std::uint16_t> &identifier,
    iso7816_select_response response
  );
}
