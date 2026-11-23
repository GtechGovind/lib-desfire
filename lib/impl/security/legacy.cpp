/// @file
/// @brief Native DES/2K3DES message protection with per-call zero chaining state.
/// The legacy send path uses primitive decryption; its MAC deliberately uses encryption instead.

#include "legacy.hpp"

#include <algorithm>

namespace desfire::detail {
  namespace {
    /// Process borrowed complete legacy DES/2K3DES blocks with a fresh zero chain for each call.
    /// Require a consistent session/context. Sending XORs before primitive decryption; receiving
    /// XORs afterward with preceding input ciphertext. Session IV is untouched, owned output is
    /// returned, and partial secret intermediates are erased on argument/provider failure.
    result<bytes> legacy_crypt(
      const card_state &state,
      byte_view input,
      bool sending
    ) {
      if (input.size() % 8) {
        return result<bytes>::failure({error_code::invalid_argument});
      }
      if (input.empty()) {
        return result<bytes>::success({});
      }

      secret_buffer output(bytes(input.size()));
      secret_buffer chain(bytes(8));
      for (std::size_t offset = 0; offset < input.size(); offset += 8) {
        secret_buffer block(input.subview(offset, 8));
        if (sending) {
          for (std::size_t index = 0; index < 8; ++index) {
            block.data()[index] =
              static_cast<std::uint8_t>(block.data()[index] ^ chain.data()[index]);
          }
        }
        // Legacy messaging uses primitive DECRYPT in both directions; ordinary CBC differs.
        auto decrypted = decrypt_block(
          *state.crypto, state.session.cipher, state.session.key.view(), block.view()
        );
        if (!decrypted) {
          return decrypted;
        }

        secret_buffer clear(std::move(decrypted.value()));
        for (std::size_t index = 0; index < 8; ++index) {
          output.data()[offset + index] =
            static_cast<std::uint8_t>(clear.data()[index] ^ (sending ? 0 : chain.data()[index]));
        }
        std::copy_n(sending ? output.data() + offset : input.data() + offset, 8, chain.data());
      }
      return result<bytes>::success(bytes(output.data(), output.data() + output.size()));
    }
  } // namespace

  /// Encode borrowed outgoing legacy blocks with XOR-then-decrypt chaining from zero.
  /// Require a valid legacy session/context and return owned protected bytes or a primitive error;
  /// no persistent IV changes occur, including across authentication stages.
  result<bytes> legacy_encipher(
    const card_state &state,
    byte_view input
  ) {
    return legacy_crypt(state, input, true);
  }

  /// Decode borrowed legacy blocks with decrypt-then-XOR chaining from zero.
  /// Require a valid legacy session/context; return owned unchecked plaintext or a primitive
  /// error, leaving session IV unchanged. The caller verifies/erases successful plaintext.
  result<bytes> legacy_decipher(
    const card_state &state,
    byte_view input
  ) {
    return legacy_crypt(state, input, false);
  }

  /// Return an owned four-byte legacy MAC over zero-padded borrowed logical input.
  /// Require a valid DES/2K3DES session/context and representable padded size; CBC encryption
  /// begins at zero without retaining an IV. Empty input matches the native zero-iteration tag,
  /// provider errors propagate, and padded input/intermediate full blocks are erased.
  result<bytes> legacy_mac(
    const card_state &state,
    byte_view input
  ) {
    secret_buffer padded(input);
    padded.resize(calculate_padded_size(input.size(), 8));
    bytes zero_iv(8);
    if (padded.size() == 0) {
      return result<bytes>::success(bytes(4));
    }
    auto output = encrypt_cbc(
      *state.crypto,
      state.session.cipher,
      state.session.key.view(),
      byte_view(zero_iv),
      padded.view()
    );
    if (!output) {
      return output;
    }
    secret_buffer encrypted(std::move(output.value()));
    // NativeMac (0x158dc) uses ENCRYPT chaining and copies bytes 0..3 of the final block.
    return result<bytes>::success(
      bytes(encrypted.data() + encrypted.size() - 8, encrypted.data() + encrypted.size() - 4)
    );
  }

  /// Encode a builder-validated legacy policy into owned wire bytes before transport AF splitting.
  /// Shared encoding applies its selected skipped CRC/MAC prefix and reversed send cipher;
  /// consistent session/context is required for protection and preparation errors propagate.
  result<bytes> prepare_legacy_command(
    card_state &state,
    const command_request &request
  ) {
    return prepare_profile_command(state, request);
  }

  /// Verify a complete borrowed legacy reply under its command-selected CRC/MAC and length rules.
  /// Return owned clear bytes only after success. Shared verification leaves the legacy session
  /// IV unused and reports delivery-unknown integrity errors for operation-level cleanup.
  result<bytes> verify_legacy_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  ) {
    return verify_profile_response(state, request, response);
  }
} // namespace desfire::detail
