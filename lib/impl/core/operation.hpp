#pragma once

#include "card_state.hpp"
#include <new>

namespace desfire::detail {

  /// One absolute deadline covers command preparation, every continuation and verification.
  struct operation_context {
    /// Monotonic endpoint shared by every phase, with no per-frame timeout restart.
    deadline expires_at;
    /// SW1/SW2 of the current physical reply, cleared before invoking each APDU callback.
    mutable std::optional<std::uint16_t> iso_status{};
  };

  struct command_request;

  /// Own one nonblocking operation admission until scope exit, including exception unwinding.
  /// An atomic flag permits safe same-thread callback reentry, which returns busy immediately.
  class operation_guard {

    std::atomic_flag &active_;
    const bool acquired_;

  public:

    /// Attempt admission once; acquire ordering exposes prior completed session transitions.
    explicit operation_guard(std::atomic_flag &active) noexcept
        : active_(active),
          acquired_(!active.test_and_set(std::memory_order_acquire)) {}

    /// Release only an admission acquired here, publishing state on every normal/exceptional exit.
    ~operation_guard() {
      if (acquired_) {
        active_.clear(std::memory_order_release);
      }
    }

    /// Admission has exactly one releasing scope; copying ownership is forbidden.
    operation_guard(const operation_guard &) = delete;
    /// An acquired guard cannot transfer or duplicate its release obligation by assignment.
    operation_guard &operator=(const operation_guard &) = delete;

    /// Return whether this scope admitted work, without touching the protected session itself.
    [[nodiscard]] bool owns_lock() const noexcept { return acquired_; }
  };

  /// Construct a deadline after admission so queued/reentrant calls cannot extend an operation.
  void begin_operation(
    const card_state &state,
    operation_context &operation
  );

  /// Prepare, exchange and authenticate a command. No plaintext escapes before verification.
  /// Requires the operation lock. Unknown delivery or invalid integrity invalidates the session.
  result<bytes> execute_command(
    card_state &state,
    const command_request &request,
    const operation_context &operation
  );

  /// One admission boundary protects every frame and cryptographic state transition.
  template <
    class value_type,
    class function_type>
  result<value_type> run_operation(
    card_state &state,
    function_type function,
    bool allow_poisoned = false,
    bool iso7816 = false
  ) {
    operation_guard lock(state.operation_active);
    if (!lock.owns_lock()) {
      return result<value_type>::failure({error_code::busy});
    }
    if (iso7816 && !state.apdu_exchange) {
      return result<value_type>::failure({error_code::unsupported});
    }
    if (iso7816 ? !validate_iso7816_options(state) : !validate_card_options(state)) {
      return result<value_type>::failure({error_code::invalid_argument});
    }
    if (state.poisoned && !allow_poisoned) {
      return result<value_type>::failure({error_code::invalid_state});
    }
    state.transmitted = false;
    operation_context operation{};
    begin_operation(state, operation);
    const bool had_credentials = require_authentication(state.session);
    const auto exception_failure = [&](error_code code) {
      // ISO preparation before the first APDU never advances the installed session. Native
      // preparation can advance its IV or clear the old session before sending any frame.
      if (state.transmitted || (!iso7816 && had_credentials)) {
        clear_session(state.session);
        state.poisoned = true;
      }
      return result<value_type>::failure(
        {code,
         state.transmitted ? delivery_outcome::unknown : delivery_outcome::not_sent,
         {},
         {},
         operation.iso_status}
      );
    };
    try {
      auto response = function(operation);
      if (
        !response && !iso7816 && had_credentials &&
        response.get_error().outcome == delivery_outcome::not_sent &&
        !require_authentication(state.session)
      ) {
        // The physical card retains the old session when preparation discarded it locally.
        state.poisoned = true;
      }
      if (response && std::chrono::steady_clock::now() >= operation.expires_at) {
        // Verification and typed parsing also consume the admitted operation budget.
        // Success proves execution, so late host completion must not invent RF uncertainty
        // or discard an aligned session. Preserve existing failures below this boundary.
        operation_error late{
          error_code::timeout,
          state.transmitted ? delivery_outcome::succeeded : delivery_outcome::not_sent
        };
        if (iso7816) {
          late.iso_status = operation.iso_status;
        }
        return result<value_type>::failure(late);
      }
      return response;
    } catch (const std::bad_alloc &) {
      return exception_failure(error_code::allocation_failed);
    } catch (...) {
      return exception_failure(error_code::callback_failed);
    }
  }

  /// Admit standard ISO traffic with the same lock, timeout, poison and exception handling.
  template <
    class value_type,
    class function_type>
  result<value_type> run_iso7816_operation(
    card_state &state,
    function_type function,
    bool allow_poisoned = false
  ) {
    return run_operation<value_type>(state, std::move(function), allow_poisoned, true);
  }

  /// Preserve an operation error when the public command has no response payload.
  inline result<void> discard_value(result<bytes> value) {
    return value ? result<void>::success() : result<void>::failure(value.get_error());
  }

} // namespace desfire::detail
