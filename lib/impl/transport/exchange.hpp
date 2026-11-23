#pragma once

#include "../core/operation.hpp"

namespace desfire::detail {

  /// Decoded native response: status precedes payload in the adapter's byte vector.
  struct native_response {
    /// Native completion/continuation/error byte, interpreted by the current protocol phase.
    std::uint8_t status{0};
    /// Owned bytes following the status; still unverified at this transport layer.
    bytes data;
  };

  /// A complete logical response, retaining physical records for GetDFNames.
  struct chained_response {
    /// Last accepted physical status; a completed logical response must end with success.
    std::uint8_t status{0};
    /// Concatenated protected payload, verified only by the security layer.
    bytes data;
    /// Physical payload boundaries in arrival order; native status bytes are excluded.
    std::vector<bytes> frames;
  };

  /// Reject an empty adapter response; preserve its leading status without interpreting it.
  result<native_response> parse_native_response(byte_view input);

  /// Submit one frame exactly once. Enforce limits/deadline and preserve proven non-delivery.
  /// Caller holds the operation lock and interprets native status for its protocol phase.
  result<native_response> exchange_frame(
    card_state &state,
    byte_view frame,
    const operation_context &operation
  );

  /// Upload an explicitly chainable command, then collect response continuations under one budget.
  /// Fixed commands must fit a single frame; allow_upload_chaining is reserved for native writes.
  /// Returns card_rejected for a definite native error; unexpected continuation is uncertain.
  result<chained_response> exchange_chained(
    card_state &state,
    byte_view command,
    const operation_context &operation,
    bool allow_upload_chaining = false
  );

  /// Split before transmission; subsequent frames reserve their first byte for native 0xAF.
  /// limit counts additional frames, excluding the initial command frame.
  result<std::vector<bytes>> split_command_frames(
    byte_view command,
    std::size_t width,
    std::size_t limit
  );

  /// Test the operation's monotonic absolute deadline without extending it.
  [[nodiscard]] bool check_deadline(const operation_context &operation) noexcept;

  /// Overflow-safe check that appending added bytes stays within limit.
  bool check_response_limit(
    std::size_t current,
    std::size_t added,
    std::size_t limit
  ) noexcept;

  /// Append an accepted physical response without losing its record boundary.
  result<void> append_response_frame(
    chained_response &response,
    native_response &&frame,
    std::size_t limit
  );

} // namespace desfire::detail
