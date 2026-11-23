#pragma once

#include "../core/card_state.hpp"
#include "../transport/exchange.hpp"

namespace desfire::detail {
  /// Command policy fixes the authenticated byte boundaries, independently of physical frames.
  struct command_request {
    /// Native command byte; AF framing is added only after cryptographic preparation.
    std::uint8_t opcode{0};
    /// Clear command parameters following the opcode; included in modern CRC/CMAC coverage.
    bytes header;
    /// Only native WriteData/WriteRecord accept AF upload continuation frames.
    /// Their entire opcode/header must fit the initial frame before payload submission.
    bool allow_upload_chaining{false};
    /// Owned clear payload, erased when the request is released.
    secret_buffer data;
    /// Protection applied to outgoing payload; modern plain commands still advance the CMAC IV.
    communication_mode request_mode{communication_mode::plain};
    /// Expected response protection; modern sessions authenticate even plain response payloads.
    communication_mode response_mode{communication_mode::mac};
    /// Exact verified clear byte count, or nullopt for variable-length responses.
    std::optional<std::size_t> expected_size{0};
    /// Nonzero record width requires the verified clear length to be an integral number of records.
    std::size_t record_size{0};
    /// Leading command bytes omitted from legacy CRC/MAC coverage; never applies to ISO/AES.
    std::size_t legacy_crc_skip{0};
    /// Additional encrypted checksum bytes, such as the unmasked replacement-key CRC in ChangeKey.
    /// Own and erase these key-derived bytes together with the request's clear payload.
    secret_buffer extra_crc;
    /// Reject execution without an authenticated session, even when request_mode is plain.
    bool requires_authentication{false};
    /// Discard the preceding session before preparation, as required by selection/reset operations.
    bool clear_before{false};
    /// Discard the session after the operation, including failure after transmission.
    bool clear_after{false};
    /// Accept a length-checked response without a tag, as required when the card changes its key.
    bool unprotected_response{false};
    /// Require a four-byte legacy MAC on the response; normal legacy plain replies have no tag.
    bool legacy_mac_response{false};
    /// Add 0x80 before zero padding only when the encrypted clear payload is not block-aligned.
    bool padding_marker{false};
  };

  /// Logical protected command; transport splitting must preserve the covered byte sequence.
  struct prepared_command {
    /// Opcode, clear header and protected payload, before any AF continuation prefixes.
    bytes wire;
  };

  /// Prepare the complete command and advance modern IV state; execution owns failure cleanup.
  result<prepared_command> prepare_command(
    card_state &state,
    const command_request &request
  );

  /// Whether the active session and command require a verified response CRC, MAC or CMAC.
  bool requires_response_integrity(
    const card_state &state,
    const command_request &request
  ) noexcept;

  /// Authenticate/decrypt a reassembled response and enforce exact/record/maximum clear lengths.
  /// Verification can advance the IV before detecting tampering; execution clears failed sessions.
  result<bytes> verify_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  );

  /// Round size up to a width multiple; require nonzero width and representable rounded output.
  std::size_t calculate_padded_size(
    std::size_t size,
    std::size_t width
  );

  /// Extend data with zeros to the next width boundary; requirements match calculate_padded_size.
  void append_zero_padding(
    bytes &data,
    std::size_t width
  );

  /// Check every padding byte without early exit on the first nonzero byte.
  bool verify_zero_padding(byte_view padding) noexcept;

  /// Check clear size against the operation's exact length, record width and configured maximum.
  bool validate_response_length(
    const command_request &request,
    std::size_t size,
    std::size_t maximum
  ) noexcept;

  /// Legacy-family entry to the shared policy encoder; require consistent authenticated state.
  result<bytes> prepare_legacy_command(
    card_state &state,
    const command_request &request
  );

  /// ISO-family entry to the shared policy encoder; require consistent authenticated state.
  result<bytes> prepare_iso_command(
    card_state &state,
    const command_request &request
  );

  /// AES-family entry to the shared policy encoder; require consistent authenticated state.
  result<bytes> prepare_aes_command(
    card_state &state,
    const command_request &request
  );

  /// Legacy-family entry to shared response verification, with policy-selected MAC/CRC coverage.
  result<bytes> verify_legacy_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  );

  /// ISO-family entry to shared response verification, retaining the full eight-byte IV.
  result<bytes> verify_iso_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  );

  /// AES-family entry to shared response verification, retaining sixteen IV bytes for eight-byte
  /// tags.
  result<bytes> verify_aes_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  );

  /// Apply profile-specific CRC/MAC/encryption rules to one complete logical command.
  result<bytes> prepare_profile_command(
    card_state &state,
    const command_request &request
  );

  /// Verify one complete response after transport reassembly; failures have unknown delivery
  /// outcome.
  result<bytes> verify_profile_response(
    card_state &state,
    const command_request &request,
    const chained_response &response
  );
} // namespace desfire::detail
