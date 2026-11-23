/// @file
/// @brief DESFire standard authentication with separate transcript and native session IVs.
#include "authentication.hpp"
#include "../../session/selection.hpp"
#include "../protocol/exchange.hpp"
#include "session_derivation.hpp"
#include <algorithm>

namespace desfire::detail {
  namespace {
    /// Match the card's explicit P1 algorithm identifier, shared by External and Internal.
    std::uint8_t algorithm_selector(key_type type) noexcept {
      switch (type) {
      case key_type::des:
      case key_type::tdes_2k:
        return 0x02;
      case key_type::tdes_3k:
        return 0x04;
      case key_type::aes_128:
        return 0x09;
      }
      return 0;
    }

    /// Preserve the exact wire status for malformed successful replies or failed mutual proof.
    operation_error invalidate(
      card_state &state,
      error_code code,
      std::uint16_t status_word
    ) {
      clear_session(state.session);
      state.poisoned = true;
      return {code, delivery_outcome::unknown, {}, {}, status_word};
    }

    /// Open a new exchange on card; a delivered GetChallenge supersedes previous authentication.
    result<bytes> challenge(
      card_state &state,
      std::size_t size,
      const operation_context &operation
    ) {
      if (!size) {
        return result<bytes>::failure({error_code::invalid_argument});
      }
      if (
        size > state.options.max_response_size || size + 2 > state.options.max_iso_response_size
      ) {
        return result<bytes>::failure({error_code::response_too_large});
      }
      const std::uint8_t apdu[] = {0, 0x84, 0, 0, static_cast<std::uint8_t>(size)};
      auto response = exchange_iso7816(state, {apdu, sizeof(apdu)}, operation);
      if (!response) {
        if (response.get_error().outcome != delivery_outcome::not_sent) {
          clear_session(state.session);
        }
        return result<bytes>::failure(response.get_error());
      }
      clear_session(state.session);
      if (response.value().data.size() != size) {
        return result<bytes>::failure(
          invalidate(state, error_code::malformed_response, response.value().status_word)
        );
      }
      return result<bytes>::success(std::move(response.value().data));
    }

    /// A proven unsent later phase leaves an earlier handshake active on card. Preserve its
    /// diagnostic but report the entire operation as uncertain. A received denial terminates it.
    result<void> phase_failure(
      card_state &state,
      operation_error error
    ) {
      clear_session(state.session);
      if (error.outcome != delivery_outcome::rejected) {
        error.outcome = delivery_outcome::unknown;
        state.poisoned = true;
      }
      return result<void>::failure(error);
    }
  }

  /// Run the three standard authentication APDUs under the admitted deadline.
  /// Use the declared type for validation and the APDU algorithm selector. Equal 2K halves use
  /// effective DES for cryptography. Verify the Internal proof before installing the derived key.
  result<void> authenticate_iso7816_session(
    card_state &state,
    std::uint8_t number,
    key_type type,
    byte_view key,
    const operation_context &operation,
    result<bytes> (*random_bytes)(std::size_t)
  ) {
    const auto size = iso7816_nonce_size(type);
    if (
      !size || key.size() != key_size(type) || number > 13 || !random_bytes ||
      (is_picc_selected(state.selection) && number != 0)
    ) {
      return result<void>::failure({error_code::invalid_argument});
    }
    if (state.selection.scope == selected_scope::unknown) {
      return result<void>::failure({error_code::invalid_state});
    }
    if (5 + size * 2 > state.options.max_apdu_size) {
      return result<void>::failure({error_code::invalid_argument});
    }
    if (
      size * 2 > state.options.max_response_size ||
      2 + size * 2 > state.options.max_iso_response_size
    ) {
      return result<void>::failure({error_code::response_too_large});
    }
    if (!state.crypto) {
      auto context = create_crypto_context();
      if (!context) {
        return result<void>::failure(context.get_error());
      }
      state.crypto = std::move(context.value());
    }
    auto randoms = random_bytes(size * 2);
    if (!randoms) {
      return result<void>::failure(randoms.get_error());
    }
    secret_buffer host(std::move(randoms.value()));
    if (host.size() != size * 2) {
      return result<void>::failure({error_code::crypto_error});
    }

    const auto effective =
      type == key_type::tdes_2k && constant_time_equal(key.subview(0, 8), key.subview(8, 8))
        ? key_type::des
        : type;
    key = key.subview(0, key_size(effective));
    const auto width = block_size(effective);
    const auto first = host.view().subview(0, size);
    const auto second = host.view().subview(size, size);
    const auto selector = algorithm_selector(type);
    const auto reference =
      static_cast<std::uint8_t>(number | (is_picc_selected(state.selection) ? 0 : 0x80));
    const auto token_size = static_cast<std::uint8_t>(2 * size);
    secret_buffer clear(bytes(2 * size));
    auto initial = challenge(state, size, operation);
    if (!initial) {
      return result<void>::failure(initial.get_error());
    }
    operation.iso_status.reset(); // External Authenticate starts a new phase.
    secret_buffer card_first(std::move(initial.value()));
    std::copy(first.begin(), first.end(), clear.data());
    std::copy_n(card_first.data(), size, clear.data() + size);
    auto token = encrypt_cbc(*state.crypto, effective, key, byte_view(bytes(width)), clear.view());
    if (!token) {
      return phase_failure(state, token.get_error());
    }
    bytes external{0, 0x82, selector, reference, token_size};
    external.insert(external.end(), token.value().begin(), token.value().end());
    auto accepted = exchange_iso7816(state, byte_view(external), operation);
    if (!accepted) {
      return phase_failure(state, accepted.get_error());
    }
    if (!accepted.value().data.empty()) {
      return result<void>::failure(
        invalidate(state, error_code::malformed_response, accepted.value().status_word)
      );
    }

    operation.iso_status.reset(); // Internal Authenticate starts a new phase.
    // The challenge sent with Internal is in clear on wire. Keep the APDU's copy erasable.
    secret_buffer internal(bytes(6 + size));
    const std::uint8_t header[] = {0, 0x88, selector, reference, static_cast<std::uint8_t>(size)};
    std::copy_n(header, 5, internal.data());
    std::copy_n(second.data(), size, internal.data() + 5);
    internal.data()[5 + size] = token_size;
    auto proof = exchange_iso7816(state, internal.view(), operation);
    if (!proof) {
      return phase_failure(state, proof.get_error());
    }
    auto &response = proof.value();
    if (response.data.size() != token_size) {
      return result<void>::failure(
        invalidate(state, error_code::malformed_response, response.status_word)
      );
    }
    auto decoded = decrypt_cbc(
      *state.crypto,
      effective,
      key,
      byte_view(token.value()).subview(token_size - width, width),
      byte_view(response.data)
    );
    if (!decoded) {
      return result<void>::failure(
        invalidate(state, decoded.get_error().code, response.status_word)
      );
    }
    secret_buffer clear_proof(std::move(decoded.value()));
    if (!constant_time_equal(second, clear_proof.view().subview(size, size))) {
      return result<void>::failure(
        invalidate(state, error_code::authentication_failed, response.status_word)
      );
    }
    auto session_key =
      derive_iso7816_session_key(effective, first, clear_proof.view().subview(0, size));
    if (!session_key) {
      return result<void>::failure(
        invalidate(state, session_key.get_error().code, response.status_word)
      );
    }
    install_authentication(
      state.session,
      authentication_type::iso7816,
      effective,
      number,
      std::move(session_key.value()),
      type
    );
    return result<void>::success();
  }
}

namespace desfire {
  /// Acquire a standalone challenge. Delivery supersedes prior authentication, and a later
  /// handshake requests a fresh card nonce.
  result<bytes> card::iso7816_get_challenge(key_type type) {
    auto &state = mutable_state();
    return detail::run_iso7816_operation<bytes>(state, [&](const auto &operation) {
      return detail::challenge(state, detail::iso7816_nonce_size(type), operation);
    });
  }

  /// Hold one admission for all phases. The range adapter erases any collected key bytes.
  result<void> card::iso7816_authenticate_bytes(
    std::uint8_t number,
    key_type type,
    detail::byte_view key
  ) {
    auto &state = mutable_state();
    return detail::run_iso7816_operation<void>(state, [&](const auto &operation) {
      return detail::authenticate_iso7816_session(state, number, type, key, operation);
    });
  }
}
