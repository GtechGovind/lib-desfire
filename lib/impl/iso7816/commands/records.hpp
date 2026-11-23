/// @file
/// @brief Encoding of selected-EF and short-file record addresses.
#pragma once

#include <desfire/common/result.hpp>
#include <desfire/iso7816/records.hpp>

namespace desfire::detail {
  /// Encode the upper five P2 bits. Zero denotes the currently selected EF.
  result<std::uint8_t> record_address_p2(const iso7816_record_address &address);
}
