/// @file
/// @brief DESFire standard read response integrity for an admitted file operation.
#pragma once
#include "../../core/card_state.hpp"
#include <desfire/iso7816/status.hpp>

namespace desfire::detail {
  /// Permit ordinary clear unauthenticated reads and EV1 CMAC reads.
  /// Legacy 0A sessions have different file-dependent MAC rules.
  bool supports_iso7816_file_read(const card_state &state) noexcept;

  /// For EV1, verify the leading eight bytes of the full retained CMAC over payload and
  /// successful DESFire response code 00. The ISO command itself does not advance the IV.
  /// Unprotected EOF cannot prove a protected outcome. Failures expose no payload and
  /// invalidate the shared session. Call only after checking supports_iso7816_file_read.
  result<iso7816_response> verify_iso7816_file_read(
    card_state &state,
    iso7816_response response
  );
}
