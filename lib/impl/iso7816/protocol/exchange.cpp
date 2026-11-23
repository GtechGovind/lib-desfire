/// @file
/// @brief Execute bounded standard APDU traffic with the card's shared operation deadline.

#include "exchange.hpp"
#include "../../transport/exchange.hpp"
#include "apdu_codec.hpp"
#include <algorithm>
#include <array>

namespace desfire::detail {
  /// Erase credentials and block further I/O after an uncertain standard command.
  /// Uncertain SELECT invalidates all scope. A file command only invalidates the EF.
  void invalidate_iso7816_exchange(
    card_state &state,
    std::uint8_t instruction
  ) noexcept {
    clear_session(state.session);
    state.poisoned = true;
    if (instruction == 0xa4) {
      invalidate_selection(state.selection);
    } else if (
      instruction == 0xb0 || instruction == 0xb2 || instruction == 0xd6 || instruction == 0xe2
    ) {
      state.selection.iso_ef.reset();
      state.selection.iso_short_file_id.reset();
    }
  }

  namespace {
    /// Identify a status that establishes rejection without a success or state-change warning.
    bool has_rejection_status(const operation_error &error) noexcept {
      if (error.outcome != delivery_outcome::rejected || !error.iso_status) {
        return false;
      }
      const auto sw1 = *error.iso_status >> 8;
      return sw1 == 0x64 || (sw1 >= 0x66 && sw1 <= 0x6f);
    }

    /// Decode an octet representing short Le/available bytes; zero denotes 256 bytes.
    std::size_t short_length(std::uint8_t octet) noexcept {
      return octet ? static_cast<std::size_t>(octet) : 256;
    }

    /// Decode the optional Le from a validated short case 2 or 4 APDU.
    std::optional<std::size_t> expected_response_size(byte_view command) noexcept {
      if (command.size() == 5 || (command.size() > 5 && command.size() == 6u + command[4])) {
        return short_length(command[command.size() - 1]);
      }
      return {};
    }

    /// Submit a complete APDU once; preserve an unsent proof only before the first transmission.
    result<iso7816_response> submit_apdu(
      card_state &state,
      byte_view command,
      const operation_context &operation
    ) {
      if (!check_deadline(operation)) {
        return result<iso7816_response>::failure(
          {error_code::timeout,
           state.transmitted ? delivery_outcome::unknown : delivery_outcome::not_sent}
        );
      }
      operation.iso_status.reset();
      const bool already_transmitted = state.transmitted;
      state.transmitted = true;
      auto wire = state.apdu_exchange(command.data(), command.size(), operation.expires_at);
      if (!wire) {
        auto error = wire.get_error();
        if (!already_transmitted && error.outcome == delivery_outcome::not_sent) {
          state.transmitted = false;
        } else if (!has_rejection_status(error)) {
          error.outcome = delivery_outcome::unknown;
        } else if (!check_deadline(operation)) {
          // A callback-supplied SW has the same deadline policy as a returned response APDU.
          error.code = error_code::timeout;
          error.outcome = delivery_outcome::unknown;
        }
        return result<iso7816_response>::failure(error);
      }
      const byte_view raw(wire.value());
      operation.iso_status = read_iso7816_status_word(raw);
      if (!check_deadline(operation)) {
        return result<iso7816_response>::failure(
          {error_code::timeout, delivery_outcome::unknown, {}, {}, operation.iso_status}
        );
      }
      if (raw.size() > state.options.max_iso_response_size) {
        return result<iso7816_response>::failure(
          {error_code::response_too_large, delivery_outcome::unknown, {}, {}, operation.iso_status}
        );
      }
      return parse_iso7816_response(raw);
    }

    /// Permit GET RESPONSE for unauthenticated file reads and application FCI.
    bool permits_get_response(
      const card_state &state,
      byte_view command
    ) noexcept {
      return ((command[1] == 0xb0 || command[1] == 0xb2) &&
              !require_authentication(state.session)) ||
             (command[1] == 0xa4 && command[3] == 0);
    }
  }

  /// Send a validated short APDU under the caller's admission and absolute deadline.
  /// Bound each reply, the assembled data, and the GET RESPONSE count independently. Preserve
  /// the available ISO status when a continuation, transport failure or malformed reply makes
  /// delivery uncertain.
  result<iso7816_response> exchange_iso7816(
    card_state &state,
    byte_view command,
    const operation_context &operation
  ) {
    if (!state.apdu_exchange) {
      return result<iso7816_response>::failure({error_code::unsupported});
    }
    const auto validated = validate_short_apdu(command);
    if (!validated) {
      return result<iso7816_response>::failure(validated.get_error());
    }
    if (command.size() > state.options.max_apdu_size) {
      return result<iso7816_response>::failure({error_code::invalid_argument});
    }

    const auto instruction = command[1];
    const auto fail = [&](const operation_error &error) {
      if (error.outcome == delivery_outcome::unknown) {
        invalidate_iso7816_exchange(state, instruction);
      }
      return result<iso7816_response>::failure(error);
    };

    // The configured clear bound is independent of wire Le. EV1 reads need room for their CMAC.
    const auto response_overhead =
      (instruction == 0xb0 || instruction == 0xb2) && require_authentication(state.session) ? 8u
                                                                                            : 0u;
    const auto configured_limit = state.options.max_response_size + response_overhead;
    const auto total_limit =
      std::min(configured_limit, expected_response_size(command).value_or(configured_limit));
    const bool continuation_permitted = permits_get_response(state, command);
    try {
      auto response = submit_apdu(state, command, operation);
      auto fragment_limit = total_limit;
      iso7816_response output;
      std::size_t continuations = 0;
      while (response) {
        auto &part = response.value();
        const auto word = part.status_word;
        const bool more = (word >> 8) == 0x61;
        if (!more || !continuation_permitted) {
          const auto status = accept_iso7816_status(instruction, word);
          if (!status) {
            auto error = status.get_error();
            if (continuations != 0) {
              error.outcome = delivery_outcome::unknown;
            }
            return fail(error);
          }
        }
        if (
          part.data.size() > fragment_limit ||
          !check_response_limit(output.data.size(), part.data.size(), total_limit)
        ) {
          return fail(
            iso7816_error(error_code::response_too_large, delivery_outcome::unknown, word)
          );
        }
        if (output.data.empty()) {
          output.data = std::move(part.data);
        } else {
          output.data.insert(output.data.end(), part.data.begin(), part.data.end());
        }
        output.status_word = word;
        if (!more) {
          return result<iso7816_response>::success(std::move(output));
        }
        const auto advertised = static_cast<std::uint8_t>(word);
        fragment_limit = short_length(advertised);
        if (!check_response_limit(output.data.size(), fragment_limit, total_limit)) {
          return fail(
            iso7816_error(error_code::response_too_large, delivery_outcome::unknown, word)
          );
        }
        if (
          continuations == state.options.max_iso_continuations || state.options.max_apdu_size < 5
        ) {
          return fail(
            iso7816_error(error_code::continuation_limit, delivery_outcome::unknown, word)
          );
        }
        ++continuations;
        const std::array<std::uint8_t, 5> next{0, 0xc0, 0, 0, advertised};
        response = submit_apdu(state, byte_view(next.data(), next.size()), operation);
      }
      auto error = response.get_error();
      if (continuations != 0) {
        error.outcome = delivery_outcome::unknown;
      }
      return fail(error);
    } catch (...) {
      if (state.transmitted) {
        invalidate_iso7816_exchange(state, instruction);
      }
      throw;
    }
  }
}
