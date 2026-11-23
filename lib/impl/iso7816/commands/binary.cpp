/// @file
/// @brief Encode ISO binary addresses and execute bounded standard file commands.

#include "binary.hpp"
#include "../protocol/apdu_codec.hpp"
#include "../security/secure_messaging.hpp"
#include <desfire/buffer/buffer_helpers.hpp>

namespace desfire::detail {
  namespace {
    /// Encode either address form, preserving offset 255 in the narrowed SFID layout.
    result<std::uint8_t> binary_p1(const iso7816_binary_address &address) {
      if (address.short_file_id) {
        if (*address.short_file_id == 0 || *address.short_file_id > 30 || address.offset > 255) {
          return result<std::uint8_t>::failure({error_code::invalid_argument});
        }
        return result<std::uint8_t>::success(
          static_cast<std::uint8_t>(0x80 | *address.short_file_id)
        );
      }
      if (address.offset > 32767) {
        return result<std::uint8_t>::failure({error_code::invalid_argument});
      }
      return result<std::uint8_t>::success(static_cast<std::uint8_t>(address.offset >> 8));
    }
  }

  /// Read binary or record data under one admission. The wire Le includes any EV1 response CMAC.
  /// Verify protection and the requested clear length before returning owned data. Record the
  /// implicit EF selection on success and discard EF knowledge if the result is uncertain.
  result<iso7816_response> read_iso7816_file(
    card_state &state,
    std::uint8_t instruction,
    std::uint8_t p1,
    std::uint8_t p2,
    std::uint16_t length,
    const std::optional<std::uint8_t> &short_file_id
  ) {
    return run_iso7816_operation<iso7816_response>(state, [&](const auto &operation) {
      if (length == 0 || length > 256) {
        return result<iso7816_response>::failure({error_code::invalid_argument});
      }
      if (length > state.options.max_response_size) {
        return result<iso7816_response>::failure({error_code::response_too_large});
      }
      const bool authenticated = require_authentication(state.session);
      if (authenticated && !supports_iso7816_file_read(state)) {
        return result<iso7816_response>::failure({error_code::unsupported});
      }
      if (authenticated && state.options.max_iso_response_size < 11) {
        // At least one clear byte, the eight-byte CMAC and two status bytes must fit.
        return result<iso7816_response>::failure({error_code::response_too_large});
      }
      // Le counts all bytes received on the wire, including the EV1 response CMAC.
      const auto wire_length = static_cast<std::uint16_t>(length + (authenticated ? 8 : 0));
      auto command = encode_short_apdu(instruction, p1, p2, {}, wire_length);
      if (!command) {
        return result<iso7816_response>::failure(command.get_error());
      }
      auto reply = exchange_iso7816(state, byte_view(command.value()), operation);
      if (!reply) {
        auto error = reply.get_error();
        if (authenticated && error.outcome != delivery_outcome::not_sent) {
          error.outcome = delivery_outcome::unknown;
          invalidate_iso7816_exchange(state, instruction);
        }
        return result<iso7816_response>::failure(error);
      }
      if (authenticated) {
        try {
          reply = verify_iso7816_file_read(state, std::move(reply.value()));
        } catch (...) {
          invalidate_iso7816_exchange(state, instruction);
          throw;
        }
        if (!reply) {
          invalidate_iso7816_exchange(state, instruction);
          return reply;
        }
      }
      if (
        reply.value().data.size() > length ||
        (reply.value().data.empty() && reply.value().status_word == 0x9000)
      ) {
        invalidate_iso7816_exchange(state, instruction);
        return result<iso7816_response>::failure(iso7816_error(
          error_code::malformed_response, delivery_outcome::unknown, reply.value().status_word
        ));
      }
      select_short_ef(state.selection, short_file_id);
      return reply;
    });
  }

  /// Send a nonempty payload in one plain mutation APDU and erase the encoded copy on release.
  /// Successful status-only completion publishes the short file ID when supplied.
  result<void> write_iso7816_file(
    card_state &state,
    std::uint8_t instruction,
    std::uint8_t p1,
    std::uint8_t p2,
    byte_view data,
    const std::optional<std::uint8_t> &short_file_id
  ) {
    return run_iso7816_operation<void>(state, [&](const auto &operation) {
      if (data.empty()) {
        return result<void>::failure({error_code::invalid_argument});
      }
      auto command = encode_short_apdu(instruction, p1, p2, data);
      if (!command) {
        return result<void>::failure(command.get_error());
      }
      // Wipe even when the transport callback throws. The caller keeps ownership of its input.
      input_buffer wire(std::move(command.value()));
      auto reply = exchange_iso7816(state, wire.view(), operation);
      if (!reply) {
        if (reply.get_error().outcome == delivery_outcome::rejected) {
          clear_session(state.session);
        }
        return result<void>::failure(reply.get_error());
      }
      if (!reply.value().data.empty()) {
        invalidate_iso7816_exchange(state, instruction);
        return result<void>::failure(iso7816_error(
          error_code::malformed_response, delivery_outcome::unknown, reply.value().status_word
        ));
      }
      select_short_ef(state.selection, short_file_id);
      return result<void>::success();
    });
  }
}

namespace desfire {
  /// Encode a selected-EF offset or the short-ID addressing form before dispatching READ BINARY.
  result<iso7816_response> card::iso7816_read_binary(const iso7816_binary_read &request) {
    auto p1 = detail::binary_p1(request.address);
    if (!p1) {
      return result<iso7816_response>::failure(p1.get_error());
    }
    return detail::read_iso7816_file(
      mutable_state(),
      0xb0,
      p1.value(),
      static_cast<std::uint8_t>(request.address.offset),
      request.length,
      request.address.short_file_id
    );
  }

  /// Validate and encode the binary address, then borrow the normalized data for UPDATE BINARY.
  result<void> card::iso7816_update_binary_bytes(
    const iso7816_binary_address &address,
    detail::byte_view data
  ) {
    auto p1 = detail::binary_p1(address);
    if (!p1) {
      return result<void>::failure(p1.get_error());
    }
    return detail::write_iso7816_file(
      mutable_state(),
      0xd6,
      p1.value(),
      static_cast<std::uint8_t>(address.offset),
      data,
      address.short_file_id
    );
  }
}
