#pragma once

#include "../core/operation.hpp"

namespace desfire::detail {
  /// Accept only defined family/type pairs with the exact static-key length; borrow key bytes.
  bool validate_authentication_key(
    authentication_type family,
    key_type type,
    byte_view key
  ) noexcept;

  /// Copy a nonce with its first byte moved to the end; empty input produces empty output.
  bytes rotate_left(byte_view input);

  /// Compare the one-byte nonce rotation with the card proof without data-dependent comparisons.
  bool verify_rotated_nonce(
    byte_view nonce,
    byte_view proof
  );

  /// Derive DES/2K3DES session bytes from two validated eight-byte nonces.
  /// The caller must supply a supported legacy type and both complete nonces.
  secret_buffer derive_legacy_session_key(
    key_type type,
    byte_view host_nonce,
    byte_view card_nonce
  );

  /// Derive DES/2K3DES/3K3DES session bytes; 3K3DES requires sixteen-byte nonces, others eight.
  /// Inputs are borrowed; the returned key owns and erases its bytes.
  secret_buffer derive_iso_session_key(
    key_type type,
    byte_view host_nonce,
    byte_view card_nonce
  );

  /// Derive AES session bytes from the first and last four bytes of each sixteen-byte nonce.
  secret_buffer derive_aes_session_key(
    byte_view host_nonce,
    byte_view card_nonce
  );

  /// Run mutual legacy authentication under one deadline; clear/install session state as it
  /// advances. The public facade clears any incomplete session and poisons uncertain delivery on
  /// failure.
  result<void> authenticate_legacy_session(
    card_state &state,
    std::uint8_t key_number,
    key_type type,
    byte_view key,
    const operation_context &operation
  );

  /// Run ISO mutual authentication, retaining CBC state between the three cryptographic stages.
  result<void> authenticate_iso_session(
    card_state &state,
    std::uint8_t key_number,
    key_type type,
    byte_view key,
    const operation_context &operation
  );

  /// Run AES mutual authentication; install the derived key with a fresh all-zero IV on success.
  result<void> authenticate_aes_session(
    card_state &state,
    std::uint8_t key_number,
    byte_view key,
    const operation_context &operation
  );
} // namespace desfire::detail
