/// @file
/// @brief Credentials and retained protection state shared by native and standard commands.
#pragma once

#include "../crypto/secret_buffer.hpp"
#include <desfire/model/enums.hpp>
#include <optional>

namespace desfire::detail {

  /// Wire protection profile selected after the native or standard handshake.
  enum class messaging_profile { none, legacy, ev1 };

  /// Authentication state belongs to a single selected application on one card connection.
  /// Key and IV use erasing storage; they are never shared between card instances.
  struct session_state {

    /// Installed native or standard authentication protocol, or none after reset.
    authentication_type authentication{authentication_type::none};
    /// Secure messaging profile for subsequent commands.
    messaging_profile profile{messaging_profile::none};
    /// Static key type before equal-halves normalization. Defaults to the effective cipher when
    /// the caller omits it.
    key_type declared_key_type{key_type::des};
    /// Cipher family of key and IV; inert DES default when authentication is absent.
    key_type cipher{key_type::des};
    /// Independently owned derived key, erased when cleared, replaced or destroyed.
    secret_buffer key;

    /// Full cipher-block IV, including the untransmitted half of an AES CMAC.
    secret_buffer iv;
    /// Key number in the separately selected application scope, valid only while authenticated.
    std::uint8_t authenticated_key{0};
  };

  /// Wipe live key/IV bytes and mark authentication absent; selection is owned separately.
  void clear_session(session_state &state) noexcept;

  /// Explicit authentication invalidation, with the same erasure as clear_session.
  void clear_authentication(session_state &state) noexcept;

  /// Install a validated session key and reset the full IV to zero.
  /// Callers must supply a supported cipher, matching key width and compatible family.
  /// @throws std::bad_alloc IV allocation failed after clearing the old credentials; the supplied
  /// owned key is erased during unwinding and the session remains unauthenticated.
  void install_authentication(
    session_state &state,
    authentication_type family,
    key_type cipher,
    std::uint8_t number,
    secret_buffer key,
    const std::optional<key_type> &declared_key_type = {}
  );

  /// Test presence of installed authentication; no transport or card permission check occurs.
  [[nodiscard]] bool require_authentication(const session_state &state) noexcept;

} // namespace desfire::detail
