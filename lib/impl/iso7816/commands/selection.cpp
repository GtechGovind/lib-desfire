/// @file
/// @brief Select an ISO DF or EF and publish the corresponding native scope knowledge.

#include "selection.hpp"
#include "../protocol/apdu_codec.hpp"
#include <algorithm>
#include <array>

namespace desfire::detail {
  namespace {
    /// Registered DF name that selects the DESFire PICC.
    constexpr std::array<std::uint8_t, 7> picc_name{0xd2, 0x76, 0, 0, 0x85, 1, 0};

    /// FCI storage on DESFire may be raw. Validate the extent when the de facto 6F template is
    /// present, using only definite, minimal short or long lengths. Leave its contents opaque.
    bool valid_fci(byte_view data) noexcept {
      if (data.empty() || data[0] != 0x6f) {
        return true;
      }
      if (data.size() < 2) {
        return false;
      }
      std::size_t offset = 2;
      std::size_t length = data[1];
      if (length >= 0x80) {
        const auto count = length & 0x7f;
        if (count == 0 || count > 2 || count > data.size() - offset || data[offset] == 0) {
          return false;
        }
        length = 0;
        for (std::size_t end = offset + count; offset < end; ++offset) {
          length = (length << 8) | data[offset];
        }
        if (length < 128) {
          return false;
        }
      }
      return length == data.size() - offset;
    }
  }

  /// Dispatch SELECT with its P1 address form and a response form permitted for that target.
  /// Definite rejection preserves the current scope. A completed selection is published before
  /// validating the optional FCI payload, so malformed FCI reports succeeded delivery.
  result<iso7816_response> select_iso7816_scope(
    card_state &state,
    std::uint8_t p1,
    byte_view data,
    const std::optional<std::uint16_t> &identifier,
    iso7816_select_response response
  ) {
    return run_iso7816_operation<iso7816_response>(state, [&](const auto &operation) {
      if (p1 == 4 && (data.empty() || data.size() > 16)) {
        return result<iso7816_response>::failure({error_code::invalid_argument});
      }
      if (
        identifier && (*identifier == 0 || *identifier == 0xffff || *identifier == 0x3fff ||
                       (*identifier == 0x3f00 && p1 != 0))
      ) {
        return result<iso7816_response>::failure({error_code::invalid_argument});
      }
      const bool master =
        p1 == 0 ||
        (p1 == 4 && std::equal(data.begin(), data.end(), picc_name.begin(), picc_name.end()));
      const bool elementary = p1 == 2;
      const bool fci = response == iso7816_select_response::fci;
      if ((response != iso7816_select_response::none && !fci) || (fci && (master || elementary))) {
        return result<iso7816_response>::failure({error_code::unsupported});
      }

      // Keep the qualified case-4 layout for status-only SELECT. FCI uses the same Le=00.
      auto command = encode_short_apdu(0xa4, p1, fci ? 0 : 0x0c, data, 256);
      if (!command) {
        return result<iso7816_response>::failure(command.get_error());
      }
      auto reply = exchange_iso7816(state, byte_view(command.value()), operation);
      if (!reply) {
        // A definite rejection leaves the existing selection and credentials aligned.
        return reply;
      }

      if ((master || elementary) && reply.value().status_word == 0x6283) {
        invalidate_iso7816_exchange(state, 0xa4);
        return result<iso7816_response>::failure(iso7816_error(
          error_code::malformed_response, delivery_outcome::unknown, reply.value().status_word
        ));
      }

      if (elementary) {
        state.selection.iso_ef = identifier;
        state.selection.iso_short_file_id.reset();
      } else {
        clear_session(state.session);
        if (master) {
          select_native_scope(state.selection, 0);
        } else {
          select_iso_application_scope(state.selection, identifier);
        }
      }
      state.response_frames.clear();
      if (
        (!fci && !reply.value().data.empty()) ||
        (fci && (reply.value().data.size() > 256 || !valid_fci(byte_view(reply.value().data))))
      ) {
        // SW establishes a completed selection; malformed FCI cannot undo that transition.
        return result<iso7816_response>::failure(iso7816_error(
          error_code::malformed_response, delivery_outcome::succeeded, reply.value().status_word
        ));
      }
      return reply;
    });
  }
}

namespace desfire {
  /// Select the MF with P1 zero and the fixed big-endian identifier 3F00.
  result<iso7816_response> card::iso7816_select_master_file(iso7816_select_response response) {
    constexpr std::array<std::uint8_t, 2> master{0x3f, 0x00};
    return detail::select_iso7816_scope(
      mutable_state(), 0, {master.data(), master.size()}, 0x3f00, response
    );
  }

  /// Encode the caller's numeric identifier in big-endian order and choose child DF or EF P1.
  result<iso7816_response> card::iso7816_select_file(
    std::uint16_t identifier,
    iso7816_file_scope scope,
    iso7816_select_response response
  ) {
    if (
      scope != iso7816_file_scope::application_df && scope != iso7816_file_scope::elementary_file
    ) {
      return result<iso7816_response>::failure({error_code::invalid_argument});
    }
    const std::array<std::uint8_t, 2> fid{
      static_cast<std::uint8_t>(identifier >> 8), static_cast<std::uint8_t>(identifier)
    };
    return detail::select_iso7816_scope(
      mutable_state(),
      scope == iso7816_file_scope::application_df ? 1 : 2,
      {fid.data(), fid.size()},
      identifier,
      response
    );
  }

  /// Borrow the exact DF name during selection by name and let the core resolve the PICC alias.
  result<iso7816_response> card::iso7816_select_by_df_name_bytes(
    detail::byte_view name,
    iso7816_select_response response
  ) {
    return detail::select_iso7816_scope(mutable_state(), 4, name, {}, response);
  }
}
