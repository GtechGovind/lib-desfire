/// @file
/// @brief Synchronous raw standard APDU callback contract.
#pragma once

#include "callback.hpp"

namespace desfire {
  /// Send one complete standard APDU and return owned response data followed by SW1/SW2.
  /// The request pointer is borrowed until this synchronous callback returns. Honor the absolute
  /// deadline, bind both card adapters to the same activation, and use the native callback's
  /// delivery contract. Each invocation transmits once. When reporting a definite rejection as
  /// an error, include its exact terminal SW1/SW2 in iso_status. Warnings and continuation
  /// statuses must be returned as raw response APDUs. Return data-bearing error responses
  /// intact so the core can detect malformed framing.
  using apdu_exchange_callback =
    std::function<result<bytes>(const std::uint8_t *, std::size_t, deadline)>;
}
