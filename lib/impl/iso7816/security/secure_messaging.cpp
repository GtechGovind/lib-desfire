/// @file
/// @brief Standard B0/B2 response CMAC; this policy is separate from native command CMAC.
#include "secure_messaging.hpp"
#include "../../security/iso.hpp"
#include <algorithm>

namespace desfire::detail {
  /// Standard reads support unauthenticated data and the EV1 response CMAC profile.
  bool supports_iso7816_file_read(const card_state &state) noexcept {
    return state.session.profile == messaging_profile::none ||
           state.session.profile == messaging_profile::ev1;
  }

  /// For an EV1 read, verify the trailing eight wire bytes against the retained full CMAC.
  /// Return owned clear data and the status after verification. Proof or framing failure erases
  /// credentials, poisons the session and leaves delivery uncertain.
  result<iso7816_response> verify_iso7816_file_read(
    card_state &state,
    iso7816_response response
  ) {
    if (state.session.profile == messaging_profile::none) {
      return result<iso7816_response>::success(std::move(response));
    }
    const auto fail = [&](error_code code) {
      clear_session(state.session);
      state.poisoned = true;
      return result<iso7816_response>::failure(
        {code, delivery_outcome::unknown, {}, {}, response.status_word}
      );
    };
    constexpr std::size_t tag_size = 8;
    if (
      state.session.profile != messaging_profile::ev1 || response.status_word != 0x9000 ||
      response.data.size() < tag_size
    ) {
      return fail(error_code::malformed_response);
    }
    const auto size = response.data.size() - tag_size;
    const auto data = byte_view(response.data);
    // Response-only CMAC: the logical native SUCCESS byte follows application data.
    secret_buffer covered(bytes(size + 1, 0));
    std::copy_n(data.begin(), size, covered.data());
    auto mac = iso_cmac(state, covered.view());
    if (!mac) {
      return fail(error_code::crypto_error);
    }
    secret_buffer full(std::move(mac.value()));
    if (!constant_time_equal(full.view().subview(0, tag_size), data.subview(size, tag_size))) {
      return fail(error_code::mac_mismatch);
    }
    response.data.resize(size);
    return result<iso7816_response>::success(std::move(response));
  }
}
