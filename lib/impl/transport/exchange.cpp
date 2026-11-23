/// @file
/// @brief Submit bounded native frames exactly once and reassemble command/response continuations.

#include "exchange.hpp"
#include <algorithm>

namespace desfire::detail {

  /// Test the current monotonic time against the shared absolute deadline without extending it.
  bool check_deadline(const operation_context &operation) noexcept {
    return std::chrono::steady_clock::now() < operation.expires_at;
  }

  /// Check aggregate growth with subtraction so current + added cannot overflow.
  /// limit includes the bounded protection overhead at this transport layer.
  bool check_response_limit(
    std::size_t current,
    std::size_t added,
    std::size_t limit
  ) noexcept {
    return current <= limit && added <= limit - current;
  }

  /// Copy a borrowed status-first response into an owned native payload.
  /// Empty input cannot establish execution and returns malformed_response/unknown; status meaning
  /// is interpreted by the upload, download or authentication phase that requested this frame.
  result<native_response> parse_native_response(byte_view input) {
    if (input.empty()) {
      return result<native_response>::failure(
        {error_code::malformed_response, delivery_outcome::unknown}
      );
    }
    return result<native_response>::success({input[0], bytes(input.begin() + 1, input.end())});
  }

  /// Submit one complete native request through the synchronous adapter with no retries.
  /// The caller owns admission and supplies a live frame plus the shared deadline. Local bounds
  /// or expiry fail before the callback. An explicit not_sent proof is preserved only when no
  /// earlier frame may have reached the card. A late, empty or oversized reply is uncertain until
  /// higher layers can verify its integrity. Callback/allocation exceptions reach run_operation.
  result<native_response> exchange_frame(
    card_state &state,
    byte_view frame,
    const operation_context &operation
  ) {
    if (frame.empty() || frame.size() > state.options.max_frame_size) {
      return result<native_response>::failure(
        {error_code::invalid_argument,
         state.transmitted ? delivery_outcome::unknown : delivery_outcome::not_sent}
      );
    }
    if (!check_deadline(operation)) {
      return result<native_response>::failure(
        {error_code::timeout,
         state.transmitted ? delivery_outcome::unknown : delivery_outcome::not_sent}
      );
    }
    const bool previously_transmitted = state.transmitted;
    state.transmitted = true;
    auto reply = state.exchange(frame.data(), frame.size(), operation.expires_at);
    if (!reply) {
      auto error = reply.get_error();
      // The adapter may prove this frame was not sent. Earlier frames still make the
      // complete operation uncertain, even when its final frame never left the reader.
      if (error.outcome == delivery_outcome::not_sent && !previously_transmitted) {
        state.transmitted = false;
      } else if (error.outcome == delivery_outcome::rejected && !check_deadline(operation)) {
        error.code = error_code::timeout;
        error.outcome = delivery_outcome::unknown;
      } else if (error.outcome != delivery_outcome::rejected) {
        error.outcome = delivery_outcome::unknown;
      }
      return result<native_response>::failure(error);
    }
    if (!check_deadline(operation)) {
      operation_error error{error_code::timeout, delivery_outcome::unknown};
      if (!reply.value().empty()) {
        error.card_status = reply.value().front();
      }
      return result<native_response>::failure(error);
    }
    if (reply.value().size() > state.options.max_response_size + 33) {
      return result<native_response>::failure(
        {error_code::response_too_large, delivery_outcome::unknown}
      );
    }
    return parse_native_response(byte_view(reply.value()));
  }

  /// Prebuild an upload transcript with at most limit additional frames, before sending any.
  /// width counts every physical byte: the initial frame contains the opcode and later frames
  /// reserve one byte for AF. The caller decides whether the opcode permits upload continuation
  /// and ensures that its entire clear header fits the initial frame.
  result<std::vector<bytes>> split_command_frames(
    byte_view command,
    std::size_t width,
    std::size_t limit
  ) {
    if (command.empty() || width < 2) {
      return result<std::vector<bytes>>::failure({error_code::invalid_argument});
    }
    std::vector<bytes> frames;
    std::size_t offset = 0;
    while (offset < command.size()) {
      if (frames.size() > limit) {
        return result<std::vector<bytes>>::failure({error_code::continuation_limit});
      }
      const bool additional = !frames.empty();
      const auto count = std::min(command.size() - offset, width - (additional ? 1 : 0));
      bytes frame;
      if (additional) {
        frame.push_back(0xaf);
      }
      frame.insert(frame.end(), command.begin() + offset, command.begin() + offset + count);
      frames.push_back(std::move(frame));
      offset += count;
    }
    return result<std::vector<bytes>>::success(std::move(frames));
  }

  /// Append an accepted payload to both the aggregate and its owned physical record list.
  /// Preserve boundaries for GetDFNames and reject aggregate overflow before either insertion.
  /// Allocation failure propagates because the card may already have consumed this exchange.
  result<void> append_response_frame(
    chained_response &response,
    native_response &&frame,
    std::size_t limit
  ) {
    if (!check_response_limit(response.data.size(), frame.data.size(), limit)) {
      return result<void>::failure({error_code::response_too_large, delivery_outcome::unknown});
    }
    response.status = frame.status;
    response.data.insert(response.data.end(), frame.data.begin(), frame.data.end());
    response.frames.push_back(std::move(frame.data));
    return result<void>::success();
  }

  /// Upload one logical command and download its complete native response under shared limits.
  /// Only explicitly permitted writes split across outgoing AF frames. Intermediate upload replies
  /// must request continuation without payload. Upload and download share one additional-frame
  /// budget; physical response boundaries survive aggregation for directory parsing. Native error
  /// statuses report definite rejection; unexpected framing or a lost response remains unknown.
  result<chained_response> exchange_chained(
    card_state &state,
    byte_view command,
    const operation_context &operation,
    bool allow_upload_chaining
  ) {
    if (!allow_upload_chaining && command.size() > state.options.max_frame_size) {
      return result<chained_response>::failure({error_code::invalid_argument});
    }
    auto frames = split_command_frames(
      command, state.options.max_frame_size, state.options.max_additional_frames
    );
    if (!frames) {
      return result<chained_response>::failure(frames.get_error());
    }
    chained_response output;
    std::size_t additional = 0;
    for (std::size_t index = 0; index < frames.value().size(); ++index) {
      auto reply = exchange_frame(state, byte_view(frames.value()[index]), operation);
      if (!reply) {
        return result<chained_response>::failure(reply.get_error());
      }
      if (reply.value().status != 0 && reply.value().status != 0xaf) {
        return result<chained_response>::failure(
          {error_code::card_rejected, delivery_outcome::rejected, reply.value().status}
        );
      }
      if (index + 1 < frames.value().size()) {
        if (reply.value().status != 0xaf || !reply.value().data.empty()) {
          return result<chained_response>::failure(
            {error_code::malformed_response, delivery_outcome::unknown}
          );
        }
        ++additional;
      } else {
        auto appended = append_response_frame(
          output, std::move(reply.value()), state.options.max_response_size + 32
        );
        if (!appended) {
          return result<chained_response>::failure(appended.get_error());
        }
      }
    }
    while (output.status == 0xaf) {
      if (additional++ >= state.options.max_additional_frames) {
        return result<chained_response>::failure(
          {error_code::continuation_limit, delivery_outcome::unknown}
        );
      }
      const bytes next{0xaf};
      auto reply = exchange_frame(state, byte_view(next), operation);
      if (!reply) {
        return result<chained_response>::failure(reply.get_error());
      }
      if (reply.value().status != 0 && reply.value().status != 0xaf) {
        return result<chained_response>::failure(
          {error_code::card_rejected, delivery_outcome::rejected, reply.value().status}
        );
      }
      auto appended = append_response_frame(
        output, std::move(reply.value()), state.options.max_response_size + 32
      );
      if (!appended) {
        return result<chained_response>::failure(appended.get_error());
      }
    }
    return result<chained_response>::success(std::move(output));
  }
} // namespace desfire::detail
