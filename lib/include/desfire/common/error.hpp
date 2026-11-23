/// @file
/// @brief Failure reasons and the separately tracked certainty of card delivery.

#ifndef desfire_desfire_common_error_hpp
#define desfire_desfire_common_error_hpp
#include <cstdint>
#include <optional>

namespace desfire {
  /// Whether a failed host operation reached a definite card-side outcome.
  /// An error can report succeeded after verified execution, for example when a read does not fit
  /// its destination or verified host processing finishes after the deadline.
  enum class delivery_outcome {
    /// No command frame was delivered; local validation failures use this value.
    not_sent,
    /// The card returned a definite rejection status.
    rejected,
    /// Card execution succeeded, but a later host-side step failed.
    succeeded,
    /// Delivery or execution cannot be established; do not infer rollback or retry safety.
    unknown
  };

  /// Host-side classification. Inspect operation_error for delivery, status and reader details.
  enum class error_code {
    /// An argument, encoded field or card option is outside its accepted domain.
    invalid_argument,
    /// The session is unusable or lacks authentication required for the operation.
    invalid_state,
    /// Another operation already owns this card instance, including a reentrant call.
    busy,
    /// The requested protocol or cryptographic operation is not implemented.
    unsupported,
    /// The reader callback reported a transport failure.
    transport_error,
    /// The shared operation deadline expired.
    timeout,
    /// The card returned a failure status. Inspect the delivery outcome for certainty.
    card_rejected,
    /// Authentication failed to establish a verified session.
    authentication_failed,
    /// The received message authentication code did not verify.
    mac_mismatch,
    /// A protected response's checksum did not verify.
    crc_mismatch,
    /// A decrypted response did not have the required padding.
    invalid_padding,
    /// The response length, status sequence or encoded fields are inconsistent.
    malformed_response,
    /// Input collection or response accumulation exceeded its configured byte bound.
    response_too_large,
    /// An existing destination range cannot hold the complete result.
    buffer_too_small,
    /// The exchange exhausted the allowed native AF or ISO GET RESPONSE budget.
    continuation_limit,
    /// The private cryptographic backend failed.
    crypto_error,
    /// Memory allocation failed while preparing or processing an operation.
    allocation_failed,
    /// A callback or generic range operation raised an unexpected exception.
    callback_failed
  };

  /// Copyable failure detail; absent status/code fields mean no such evidence was available.
  struct operation_error {
    /// Host-side reason for the failure; independent of delivery certainty.
    error_code code{error_code::invalid_argument};
    /// Best established card-side outcome at the point of failure.
    delivery_outcome outcome{delivery_outcome::not_sent};
    /// Native status byte when one was received and retained.
    std::optional<std::uint8_t> card_status{};
    /// Reader-defined diagnostic code, copied from a callback-reported failure.
    std::optional<int> transport_code{};
    /// Exact standard status word with SW1 in the high byte and SW2 in the low byte.
    std::optional<std::uint16_t> iso_status{};
  };
} // namespace desfire

#endif // desfire_desfire_common_error_hpp
