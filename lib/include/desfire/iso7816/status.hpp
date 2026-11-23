/// @file
/// @brief Owned and caller-buffer standard ISO responses with exact card status.
#pragma once

#include "../buffer/byte_view.hpp"

namespace desfire {
  /// Owned standard response payload and exact SW1/SW2, including supported read warnings.
  struct iso7816_response {
    /// Complete verified response payload, owned by the result.
    bytes data;
    /// SW1 in the high byte and SW2 in the low byte. A default object has no status evidence.
    std::uint16_t status_word{};
  };

  /// Number of elements written to caller storage and exact SW1/SW2 from a bounded read.
  struct iso7816_read_result {
    /// Number of destination bytes changed by this successful bounded read.
    std::size_t bytes_written{};
    /// SW1 in the high byte and SW2 in the low byte. A default object has no status evidence.
    std::uint16_t status_word{};
  };
}
