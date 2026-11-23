/// @file
/// @brief Address, numbering and traversal models for standard record operations.
#pragma once

#include <cstdint>
#include <optional>

namespace desfire {
  /// Address the selected EF or use a short file identifier 1..30 within the current DF.
  struct iso7816_record_address {
    /// Explicit short ID 1..30. When absent, the card uses its selected EF.
    std::optional<std::uint8_t> short_file_id;
  };

  /// Absolute record numbering or traversal from the requested record to the last record.
  /// The card defines record order, including newest-first indices for cyclic records.
  enum class iso7816_record_mode {
    /// Read the record at the requested one-based index.
    absolute = 4,
    /// Read a traversal starting at the requested index in the card's forward order.
    forward = 5
  };

  /// Read one or more records from a one-based index using short Le.
  struct iso7816_record_read {
    /// Currently selected EF or explicitly addressed short ID.
    iso7816_record_address address;
    /// One-based record number 1..254. The default zero requires assignment before use.
    std::uint8_t record_number{};
    /// Select one record by default. Forward traversal preserves the order returned by the card.
    iso7816_record_mode mode{iso7816_record_mode::absolute};
    /// Maximum clear byte count. Use 1..256, or 1..248 for an authenticated EV1 read.
    std::uint16_t length{};
  };
}
