/// @file
/// @brief Apply command admission, protected exchange and verified-response session transitions.

#include "operation.hpp"
#include "../security/messaging.hpp"
#include <algorithm>

namespace desfire::detail {

  /// Start one monotonic budget from the already-validated immutable options.
  /// Continuations and local verification share this deadline; no phase extends it.
  void begin_operation(
    const card_state &state,
    operation_context &operation
  ) {
    operation.expires_at = std::chrono::steady_clock::now() + state.options.operation_timeout;
  }

  /// Execute a validated command policy while the caller owns operation admission.
  /// Reject impossible bounds before preparation and release only verified response bytes.
  /// A protected command cannot establish rejection from a bare status. Transport uncertainty
  /// or failed verification invalidates credentials and blocks further commands until recovery.
  /// Admission also checks for credentials discarded during an unsent operation.
  result<bytes> execute_command(
    card_state &state,
    const command_request &request,
    const operation_context &operation
  ) {
    if (request.header.size() >= state.options.max_frame_size) {
      return result<bytes>::failure({error_code::invalid_argument});
    }
    if (request.expected_size && *request.expected_size > state.options.max_response_size) {
      return result<bytes>::failure({error_code::response_too_large});
    }
    if (request.requires_authentication && !require_authentication(state.session)) {
      return result<bytes>::failure({error_code::invalid_state});
    }
    if (request.clear_before) {
      clear_session(state.session);
    }
    auto prepared = prepare_command(state, request);
    if (!prepared) {
      return result<bytes>::failure(prepared.get_error());
    }
    auto response = exchange_chained(
      state, byte_view(prepared.value().wire), operation, request.allow_upload_chaining
    );
    if (!response) {
      auto error = response.get_error();
      // A bare status cannot establish rejection when the command requires response integrity.
      if (
        error.outcome == delivery_outcome::rejected && requires_response_integrity(state, request)
      ) {
        error.outcome = delivery_outcome::unknown;
      }
      clear_session(state.session);
      state.poisoned = error.outcome == delivery_outcome::unknown;
      return result<bytes>::failure(error);
    }
    auto verified = verify_response(state, request, response.value());
    if (!verified) {
      clear_session(state.session);
      state.poisoned = true;
      return verified;
    }
    state.response_frames = std::move(response.value().frames);
    // Remove a trailing MAC from physical frames without losing DF-name record boundaries.
    std::size_t total = response.value().data.size();
    for (auto iterator = state.response_frames.rbegin();
         total > verified.value().size() && iterator != state.response_frames.rend();
         ++iterator) {
      const auto count = std::min(iterator->size(), total - verified.value().size());
      iterator->resize(iterator->size() - count);
      total -= count;
    }
    if (request.clear_after) {
      clear_session(state.session);
    }
    return verified;
  }
} // namespace desfire::detail
