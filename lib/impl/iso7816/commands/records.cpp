/// @file
/// @brief Encode ISO record addressing and preserve the card's traversal and write semantics.

#include "records.hpp"
#include "binary.hpp"

namespace desfire::detail {
  /// Put the 1..30 short ID in the upper five P2 bits, or zero for the selected EF.
  result<std::uint8_t> record_address_p2(const iso7816_record_address &address) {
    if (address.short_file_id && (*address.short_file_id == 0 || *address.short_file_id > 30)) {
      return result<std::uint8_t>::failure({error_code::invalid_argument});
    }
    return result<std::uint8_t>::success(
      static_cast<std::uint8_t>(address.short_file_id.value_or(0) << 3)
    );
  }
}

namespace desfire {
  /// Encode P1 as the first record and the low P2 bits as the traversal mode.
  /// The shared file read enforces length and verifies response protection.
  result<iso7816_response> card::iso7816_read_records(const iso7816_record_read &request) {
    if (
      request.record_number == 0 || request.record_number == 0xff ||
      (request.mode != iso7816_record_mode::absolute &&
       request.mode != iso7816_record_mode::forward)
    ) {
      return result<iso7816_response>::failure({error_code::invalid_argument});
    }
    auto p2 = detail::record_address_p2(request.address);
    if (!p2) {
      return result<iso7816_response>::failure(p2.get_error());
    }
    return detail::read_iso7816_file(
      mutable_state(),
      0xb2,
      request.record_number,
      static_cast<std::uint8_t>(p2.value() | static_cast<std::uint8_t>(request.mode)),
      request.length,
      request.address.short_file_id
    );
  }

  /// Submit the borrowed record with P1 zero and the selected-EF or short-ID form of P2.
  result<void> card::iso7816_append_record_bytes(
    const iso7816_record_address &address,
    detail::byte_view data
  ) {
    auto p2 = detail::record_address_p2(address);
    if (!p2) {
      return result<void>::failure(p2.get_error());
    }
    return detail::write_iso7816_file(
      mutable_state(), 0xe2, 0, p2.value(), data, address.short_file_id
    );
  }
}
