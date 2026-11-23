/// @file
/// @brief Authentication-state installation and erasure for one independently owned card session.
/// Application selection and uncertain-delivery recovery belong to the card/operation layer.

#include "session.hpp"
#include "../crypto/openssl_crypto.hpp"

namespace desfire::detail {
  /// Erase the live key and full IV, then reset authentication metadata to its inert defaults.
  /// Storage may retain cleansed capacity. This local reset neither sends a command nor changes
  /// the separately tracked selected application or the physical card's authentication state.
  void clear_session(session_state &state) noexcept {
    state.key.clear();
    state.iv.clear();
    state.authentication = authentication_type::none;
    state.profile = messaging_profile::none;
    state.declared_key_type = key_type::des;
    state.cipher = key_type::des;
    state.authenticated_key = 0;
  }

  /// Invalidate credentials using the same complete key/IV erasure as any other session reset.
  /// The explicit name marks authentication-loss call sites without adding transport behavior.
  void clear_authentication(session_state &state) noexcept {
    clear_session(state);
  }

  /// Replace old credentials with an independently owned, already validated session key.
  /// The entire cipher-block IV starts at zero, including bytes that AES MAC transmission omits.
  /// @param state Host session to replace; previous live secrets are erased first.
  /// @param family Validated native or standard authentication protocol compatible with cipher.
  /// @param cipher Effective cipher determining the derived-key and full IV block widths.
  /// @param number Authenticated key number in the separately selected application scope.
  /// @param key Owned derived key with the validated cipher's width; consumed by this call.
  /// @param declared_key_type Original static key type before equal-halves DES normalization.
  /// If absent, record the effective cipher as the static key type.
  /// @throws std::bad_alloc IV allocation failed; old credentials remain cleared and key is erased
  /// during unwinding. Authentication is marked present only after allocation and key transfer.
  void install_authentication(
    session_state &state,
    authentication_type family,
    key_type cipher,
    std::uint8_t number,
    secret_buffer key,
    const std::optional<key_type> &declared_key_type
  ) {
    clear_session(state);
    messaging_profile profile;
    switch (family) {
    case authentication_type::legacy:
      profile = messaging_profile::legacy;
      break;
    case authentication_type::iso:
    case authentication_type::aes:
    case authentication_type::iso7816:
      profile = messaging_profile::ev1;
      break;
    default:
      return;
    }
    state.iv.resize(block_size(cipher));
    state.key = std::move(key);
    state.profile = profile;
    state.declared_key_type = declared_key_type.value_or(cipher);
    state.cipher = cipher;
    state.authenticated_key = number;
    state.authentication = family;
  }

  /// Test host credential presence without allocating, sending, or checking card access policy.
  /// Key width/family coherence is guaranteed by the validated installation precondition.
  bool require_authentication(const session_state &state) noexcept {
    return state.authentication != authentication_type::none && state.key.size() != 0;
  }
} // namespace desfire::detail
