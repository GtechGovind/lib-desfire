/// @file
/// @brief Container adaptation for card commands; protocol work remains in the compiled core.

#ifndef desfire_card_templates_hpp
#define desfire_card_templates_hpp

// The public template header must also compile when included directly by a consumer.
// ReSharper disable once CppUnusedIncludeDirective
#include "card.hpp" // IWYU pragma: keep

namespace desfire {

  /// Borrow or normalize a bounded name while the compiled SELECT operation uses it.
  template <class range>
  result<iso7816_response> card::iso7816_select_by_df_name(
    const range &name,
    iso7816_select_response response
  ) {
    return detail::with_input<iso7816_response>(name, 16, [&](detail::byte_view input) {
      return iso7816_select_by_df_name_bytes(input, response);
    });
  }

  /// Collect up to sixteen name bytes in one pass and erase the copy after selection.
  template <class iterator>
  result<iso7816_response> card::iso7816_select_by_df_name(
    iterator first,
    iterator last,
    iso7816_select_response response
  ) {
    return detail::with_input<iso7816_response>(first, last, 16, [&](detail::byte_view input) {
      return iso7816_select_by_df_name_bytes(input, response);
    });
  }

  /// Bound input by short Lc before admission. The compiled operation applies the APDU limit.
  template <class range>
  result<void> card::iso7816_update_binary(
    const iso7816_binary_address &address,
    const range &data
  ) {
    return detail::with_input(data, 255, [&](detail::byte_view input) {
      return iso7816_update_binary_bytes(address, input);
    });
  }

  /// Collect binary data once and erase the copy after dispatch returns.
  template <class iterator>
  result<void> card::iso7816_update_binary(
    const iso7816_binary_address &address,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, 255, [&](detail::byte_view input) {
      return iso7816_update_binary_bytes(address, input);
    });
  }

  /// Adapt record bytes to one short APDU without interpreting the card's record format.
  template <class range>
  result<void> card::iso7816_append_record(
    const iso7816_record_address &address,
    const range &data
  ) {
    return detail::with_input(data, 255, [&](detail::byte_view input) {
      return iso7816_append_record_bytes(address, input);
    });
  }

  /// Collect the record once within the short Lc bound and erase the copy on return.
  template <class iterator>
  result<void> card::iso7816_append_record(
    const iso7816_record_address &address,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, 255, [&](detail::byte_view input) {
      return iso7816_append_record_bytes(address, input);
    });
  }

  /// Bound key normalization at 24 bytes before the compiled handshake checks the exact width.
  template <class range>
  result<void> card::iso7816_authenticate(
    std::uint8_t number,
    key_type type,
    const range &key
  ) {
    return detail::with_input(key, 24, [&](detail::byte_view input) {
      return iso7816_authenticate_bytes(number, type, input);
    });
  }

  /// Own any collected static key bytes across all three phases and erase them on return.
  template <class iterator>
  result<void> card::iso7816_authenticate(
    std::uint8_t number,
    key_type type,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, 24, [&](detail::byte_view input) {
      return iso7816_authenticate_bytes(number, type, input);
    });
  }

  namespace detail {
    /// Preserve the status on success and when verified data cannot fit caller storage.
    /// Actual payload length can be less than Le, so capacity is checked after the read.
    template <class iterator>
    result<iso7816_read_result> copy_iso7816_read(
      result<iso7816_response> response,
      iterator first,
      iterator last
    ) {
      if (!response) {
        return result<iso7816_read_result>::failure(response.get_error());
      }
      const auto status = response.value().status_word;
      try {
        auto copied = copy_bytes(byte_view(response.value().data), first, last);
        if (!copied) {
          return result<iso7816_read_result>::failure(
            {copied.get_error().code, delivery_outcome::succeeded, {}, {}, status}
          );
        }
        return result<iso7816_read_result>::success({copied.value(), status});
      } catch (const std::bad_alloc &) {
        return result<iso7816_read_result>::failure(
          {error_code::allocation_failed, delivery_outcome::succeeded, {}, {}, status}
        );
      } catch (...) {
        return result<iso7816_read_result>::failure(
          {error_code::callback_failed, delivery_outcome::succeeded, {}, {}, status}
        );
      }
    }
  } // namespace detail

  /// Obtain the destination endpoints before issuing the binary read.
  template <class output_range>
  result<iso7816_read_result> card::iso7816_read_binary_into(
    const iso7816_binary_read &request,
    output_range &output
  ) {
    return iso7816_read_binary_into(request, std::begin(output), std::end(output));
  }

  /// Copy only verified binary bytes after checking the actual returned length.
  template <class output_iterator>
  result<iso7816_read_result> card::iso7816_read_binary_into(
    const iso7816_binary_read &request,
    output_iterator first,
    output_iterator last
  ) {
    return detail::copy_iso7816_read(iso7816_read_binary(request), first, last);
  }

  /// Obtain the destination endpoints before issuing the record read.
  template <class output_range>
  result<iso7816_read_result> card::iso7816_read_records_into(
    const iso7816_record_read &request,
    output_range &output
  ) {
    return iso7816_read_records_into(request, std::begin(output), std::end(output));
  }

  /// Copy verified records in card order and retain the terminal ISO status.
  template <class output_iterator>
  result<iso7816_read_result> card::iso7816_read_records_into(
    const iso7816_record_read &request,
    output_iterator first,
    output_iterator last
  ) {
    return detail::copy_iso7816_read(iso7816_read_records(request), first, last);
  }

  template <class range>
  result<void> card::authenticate(
    std::uint8_t number,
    key_type type,
    const range &key
  ) {
    return detail::with_input(key, 24, [&](detail::byte_view data) {
      return authenticate_bytes(authentication_type::legacy, number, type, data);
    });
  }

  template <class iterator>
  result<void> card::authenticate(
    std::uint8_t number,
    key_type type,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, 24, [&](detail::byte_view data) {
      return authenticate_bytes(authentication_type::legacy, number, type, data);
    });
  }

  template <class range>
  result<void> card::authenticate_iso(
    std::uint8_t number,
    key_type type,
    const range &key
  ) {
    return detail::with_input(key, 24, [&](detail::byte_view data) {
      return authenticate_bytes(authentication_type::iso, number, type, data);
    });
  }

  template <class iterator>
  result<void> card::authenticate_iso(
    std::uint8_t number,
    key_type type,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, 24, [&](detail::byte_view data) {
      return authenticate_bytes(authentication_type::iso, number, type, data);
    });
  }

  template <class range>
  result<void> card::authenticate_aes(
    std::uint8_t number,
    const range &key
  ) {
    return detail::with_input(key, 16, [&](detail::byte_view data) {
      return authenticate_bytes(authentication_type::aes, number, key_type::aes_128, data);
    });
  }

  template <class iterator>
  result<void> card::authenticate_aes(
    std::uint8_t number,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, 16, [&](detail::byte_view data) {
      return authenticate_bytes(authentication_type::aes, number, key_type::aes_128, data);
    });
  }

  template <class range>
  result<void> card::change_picc_master_key(
    key_type type,
    const range &key,
    std::uint8_t version
  ) {
    return detail::with_input(key, 24, [&](detail::byte_view data) {
      return change_picc_master_key_bytes(type, data, version);
    });
  }

  template <class iterator>
  result<void> card::change_picc_master_key(
    key_type type,
    iterator first,
    iterator last,
    std::uint8_t version
  ) {
    return detail::with_input(first, last, 24, [&](detail::byte_view data) {
      return change_picc_master_key_bytes(type, data, version);
    });
  }

  template <
    class old_range,
    class new_range>
  result<void> card::change_app_key(
    std::uint8_t number,
    const old_range &old_key,
    const new_range &new_key,
    std::uint8_t version
  ) {
    return detail::with_input(old_key, 24, [&](detail::byte_view old_data) {
      return detail::with_input(new_key, 24, [&](detail::byte_view new_data) {
        return change_app_key_bytes(number, old_data, new_data, version);
      });
    });
  }

  template <
    class old_iterator,
    class new_iterator>
  result<void> card::change_app_key(
    std::uint8_t number,
    old_iterator old_first,
    old_iterator old_last,
    new_iterator new_first,
    new_iterator new_last,
    std::uint8_t version
  ) {
    return detail::with_input(old_first, old_last, 24, [&](detail::byte_view old_data) {
      return detail::with_input(new_first, new_last, 24, [&](detail::byte_view new_data) {
        return change_app_key_bytes(number, old_data, new_data, version);
      });
    });
  }

  /// Borrow contiguous ranges or erase bounded input copies after synchronous admission.
  template <
    class old_range,
    class new_range>
  result<void> card::change_app_key(
    std::uint8_t number,
    key_type old_type,
    const old_range &old_key,
    key_type new_type,
    const new_range &new_key,
    std::uint8_t version
  ) {
    return detail::with_input(old_key, 24, [&](detail::byte_view old_data) {
      return detail::with_input(new_key, 24, [&](detail::byte_view new_data) {
        return change_app_key_bytes(number, old_type, old_data, new_type, new_data, version);
      });
    });
  }

  /// Keep both normalized buffers alive while encoding explicitly typed native key material.
  template <
    class old_iterator,
    class new_iterator>
  result<void> card::change_app_key(
    std::uint8_t number,
    key_type old_type,
    old_iterator old_first,
    old_iterator old_last,
    key_type new_type,
    new_iterator new_first,
    new_iterator new_last,
    std::uint8_t version
  ) {
    return detail::with_input(old_first, old_last, 24, [&](detail::byte_view old_data) {
      return detail::with_input(new_first, new_last, 24, [&](detail::byte_view new_data) {
        return change_app_key_bytes(number, old_type, old_data, new_type, new_data, version);
      });
    });
  }

  template <class range>
  result<void> card::create_application(
    const application_config &config,
    const range &name
  ) {
    return detail::with_input(name, 16, [&](detail::byte_view data) {
      return create_application_bytes(config, data);
    });
  }

  template <class iterator>
  result<void> card::create_application(
    const application_config &config,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, 16, [&](detail::byte_view data) {
      return create_application_bytes(config, data);
    });
  }

  template <class range>
  result<void> card::set_configuration(
    std::uint8_t option,
    const range &data
  ) {
    return detail::with_input(data, max_input_size(), [&](detail::byte_view input) {
      return set_configuration_bytes(option, input);
    });
  }

  template <class iterator>
  result<void> card::set_configuration(
    std::uint8_t option,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, max_input_size(), [&](detail::byte_view data) {
      return set_configuration_bytes(option, data);
    });
  }

  template <class range>
  result<void> card::write_data(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    const range &data
  ) {
    return detail::with_input(data, max_input_size(), [&](detail::byte_view input) {
      return write_data_bytes(file, mode, offset, input);
    });
  }

  template <class iterator>
  result<void> card::write_data(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, max_input_size(), [&](detail::byte_view data) {
      return write_data_bytes(file, mode, offset, data);
    });
  }

  template <class range>
  result<void> card::write_record(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    const range &data
  ) {
    return detail::with_input(data, max_input_size(), [&](detail::byte_view input) {
      return write_record_bytes(file, mode, offset, input);
    });
  }

  template <class iterator>
  result<void> card::write_record(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    iterator first,
    iterator last
  ) {
    return detail::with_input(first, last, max_input_size(), [&](detail::byte_view data) {
      return write_record_bytes(file, mode, offset, data);
    });
  }

  namespace detail {
    /// Preflight known output extent, run one verified read, then copy without capacity truncation.
    /// reader owns command admission; its failure passes through unchanged. A later capacity
    /// failure reports succeeded card delivery. Iterator exceptions propagate and may interrupt
    /// copying.
    template <
      class iterator,
      class reader>
    result<std::size_t> read_into(
      iterator first,
      iterator last,
      std::size_t needed,
      reader read
    ) {
      auto capacity = validate_output_capacity(first, last, needed);
      if (!capacity) {
        return capacity;
      }
      auto value = read();
      if (!value) {
        return result<std::size_t>::failure(value.get_error());
      }
      auto copied = copy_bytes(byte_view(value.value()), first, last);
      if (!copied) {
        auto error = copied.get_error();
        error.outcome = delivery_outcome::succeeded;
        return result<std::size_t>::failure(error);
      }
      return copied;
    }
  } // namespace detail

  template <class range>
  result<std::size_t> card::read_data_into(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    std::uint32_t length,
    range &output
  ) {
    return read_data_into(file, mode, offset, length, std::begin(output), std::end(output));
  }

  template <class iterator>
  result<std::size_t> card::read_data_into(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    std::uint32_t length,
    iterator first,
    iterator last
  ) {
    return detail::read_into(first, last, length, [&] {
      return read_data(file, mode, offset, length);
    });
  }

  template <class range>
  result<std::size_t> card::read_records_into(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t first_record,
    std::uint32_t count,
    std::uint32_t record_size,
    range &output
  ) {
    return read_records_into(
      file, mode, first_record, count, record_size, std::begin(output), std::end(output)
    );
  }

  template <class iterator>
  result<std::size_t> card::read_records_into(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t first_record,
    std::uint32_t count,
    std::uint32_t record_size,
    iterator first,
    iterator last
  ) {
    const auto size = static_cast<std::uint64_t>(count) * record_size;
    if (size > max_input_size()) {
      return result<std::size_t>::failure({error_code::response_too_large});
    }
    return detail::read_into(first, last, static_cast<std::size_t>(size), [&] {
      return read_records(file, mode, first_record, count, record_size);
    });
  }

  template <class range> result<std::size_t> card::get_card_uid_into(range &output) {
    return get_card_uid_into(std::begin(output), std::end(output));
  }

  template <class iterator>
  result<std::size_t> card::get_card_uid_into(
    iterator first,
    iterator last
  ) {
    return detail::read_into(first, last, 7, [&] {
      return get_card_uid();
    });
  }
} // namespace desfire

#endif // desfire_card_templates_hpp
