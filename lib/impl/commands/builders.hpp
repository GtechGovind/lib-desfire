/// @file
/// Internal typed-command builders and the serialized build/verify/parse boundary.
/// Builders validate and copy borrowed inputs without performing I/O or modifying sessions;
/// the resulting command_request fixes operation-specific protection and response constraints.

#pragma once

#include "../security/messaging.hpp"

namespace desfire::detail {

  /// An owned command policy or a pre-transmission error; no partially built request escapes.
  using command_result = result<command_request>;

  /// Validation failure before command preparation or transport submission.
  inline command_result invalid_command() {
    return command_result::failure({error_code::invalid_argument});
  }

  /// Default management policy: a plain request, modern response MAC when authenticated,
  /// and an exact expected payload length. nullopt permits a variable-length response.
  /// @param opcode Native command byte, without transport AF framing.
  /// @param header Owned clear parameters, moved into the returned request.
  /// @param expected Exact clear response byte count; zero means status only.
  /// @return Owned policy. This helper neither advances authentication nor sends bytes.
  inline command_request management_command(
    std::uint8_t opcode,
    bytes header = {},
    const std::optional<std::size_t> &expected = 0
  ) {
    command_request request;
    request.opcode = opcode;
    request.header = std::move(header);
    request.expected_size = expected;
    return request;
  }

  /// Admit one operation, build it under the lock, verify it, then parse its typed payload.
  /// A structurally invalid verified payload also invalidates the session; it cannot be retried.
  /// @tparam value_type Owned public response type, including void for status-only commands.
  /// @tparam builder_type Synchronous nullary callable returning command_result.
  /// @tparam parser_type Callable accepting borrowed verified bytes and returning
  /// result<value_type>.
  /// @param state Card state whose admission lock spans validation, transport and parsing.
  /// @param builder Copied callable; captured borrowed inputs must survive this synchronous call.
  /// @param parser Copied callable; must copy any response bytes needed beyond its invocation.
  /// @return Builder/transport/protection/parse result with the original delivery evidence.
  template <
    class value_type,
    class builder_type,
    class parser_type>
  result<value_type> run_command(
    card_state &state,
    builder_type builder,
    parser_type parser
  ) {
    return run_operation<value_type>(state, [&](const auto &operation) {
      auto command = builder();
      if (!command) {
        return result<value_type>::failure(command.get_error());
      }
      auto response = execute_command(state, command.value(), operation);
      if (!response) {
        return result<value_type>::failure(response.get_error());
      }
      auto parsed = parser(byte_view(response.value()));
      if (!parsed) {
        clear_session(state.session);
        state.poisoned = true;
      }
      return parsed;
    });
  }

  /// Execute a command whose builder expects a status-only success response.
  /// @tparam builder_type Nullary callable returning a policy with expected_size equal to zero.
  /// @param state Card state admitted for the entire synchronous operation.
  /// @param builder Copied builder; response verification enforces the absence of clear data.
  /// @return Success only after verification; operation errors retain their delivery outcome.
  template <class builder_type>
  result<void> run_void_command(
    card_state &state,
    builder_type builder
  ) {
    return run_command<void>(state, builder, [](byte_view) {
      return result<void>::success();
    });
  }

  /// Encrypt one key-settings byte under the current authenticated session.
  command_result build_change_key_settings(std::uint8_t settings);

  /// Read the exact two-byte key-settings response.
  command_result build_get_key_settings();

  /// Read a key version for native key numbers 0..13.
  command_result build_get_key_version(std::uint8_t number);

  /// Encode a PICC master-key replacement, including the new family's selector.
  /// Caller verifies PICC scope; the successful status-only response ends authentication.
  command_result build_change_picc_master_key(
    const session_state &session,
    key_type type,
    byte_view key,
    std::uint8_t version
  );

  /// Encode current-key replacement or XOR other-key replacement with its extra key CRC.
  /// Inputs must match the authenticated family's key size. Replacement bytes and the extra
  /// unmasked-key checksum are held in erasing storage; current-key success clears authentication.
  command_result build_change_app_key(
    const session_state &session,
    std::uint8_t number,
    byte_view old_key,
    byte_view new_key,
    std::uint8_t version
  );

  /// Encode explicitly typed key bytes under the effective session cipher. DES/2K3DES share
  /// one wire family and are normalized to sixteen bytes before XOR and checksum calculation.
  command_result build_change_app_key(
    const session_state &session,
    std::uint8_t number,
    key_type old_type,
    byte_view old_key,
    key_type new_type,
    byte_view new_key,
    std::uint8_t version
  );

  /// Create a native application with consistent optional ISO identifier and raw DF name.
  command_result build_create_application(
    const application_config &config,
    byte_view name
  );

  /// Delete a nonzero 24-bit AID.
  command_result build_delete_application(std::uint32_t id);

  /// Enumerate concatenated three-byte native AIDs.
  command_result build_get_application_ids();

  /// Select an AID (zero means PICC), discarding prior authentication before submission.
  command_result build_select_application(std::uint32_t id);

  /// Request physical DF-name records; their boundaries survive response aggregation.
  command_result build_get_df_names();

  /// Format under authenticated PICC scope and end authentication after success.
  command_result build_format_picc();

  /// Read the three-part 28-byte native version response.
  command_result build_get_version();

  /// Read the three-byte little-endian free-memory count.
  command_result build_free_memory();

  /// Apply the supported SetConfiguration option layouts.
  command_result build_set_configuration(
    std::uint8_t option,
    byte_view data
  );

  /// Read a seven-byte UID through an encrypted authenticated response.
  command_result build_get_card_uid();

  /// Enumerate one-byte native file numbers.
  command_result build_get_fids();

  /// Enumerate two-byte ISO file identifiers.
  command_result build_get_iso_fids();

  /// Read the selected file's type-specific settings layout.
  command_result build_get_file_settings(std::uint8_t file);

  /// Change mode/access under the caller's requested plain or encrypted command policy.
  command_result build_change_file_settings(
    std::uint8_t file,
    const file_settings_change &settings
  );

  /// Create a standard or backup data file; backup selects opcode 0xCB instead of 0xCD.
  command_result build_create_data_file(
    std::uint8_t file,
    const data_file_config &config,
    bool backup
  );

  /// Create a signed value file with validated limits and initial value.
  command_result build_create_value_file(
    std::uint8_t file,
    const value_file_config &config
  );

  /// Create a linear or cyclic record file with a nonzero width and capacity.
  command_result build_create_record_file(
    std::uint8_t file,
    const record_file_config &config,
    bool cyclic
  );

  /// Delete a native file number 0..31.
  command_result build_delete_file(std::uint8_t file);

  /// Read length bytes at a byte offset; plain/MAC permits zero for the remaining data.
  /// Encrypted mode requires a nonzero exact clear length to locate CRC and padding.
  command_result build_read_data(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    std::uint32_t length
  );

  /// Write a bounded payload, preserving its clear seven-byte file/offset/length header.
  command_result build_write_data(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    byte_view data
  );

  /// Read one signed 32-bit value with the file's communication policy.
  command_result build_get_value(
    std::uint8_t file,
    communication_mode mode
  );

  /// Encode credit/debit/limited-credit; callers supply one of those native opcodes.
  command_result build_value_mutation(
    std::uint8_t opcode,
    std::uint8_t file,
    communication_mode mode,
    std::int32_t amount
  );

  /// Write bytes at an offset within a record using the native data-write framing layout.
  command_result build_write_record(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    byte_view data
  );

  /// Read complete records; plain/MAC permits zero count for all remaining records.
  /// Encrypted mode requires a nonzero exact record count.
  /// record_size enables a preflight byte limit and verified-response alignment check.
  command_result build_read_records(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t first_record,
    std::uint32_t count,
    std::uint32_t record_size
  );

  /// Stage clearing a record file; transaction completion is always explicit.
  command_result build_clear_record_file(std::uint8_t file);

  /// Commit staged changes once; delivery uncertainty must never trigger an automatic retry.
  command_result build_commit_transaction();

  /// Abort staged changes once, subject to the same delivery rules as other mutations.
  command_result build_abort_transaction();

} // namespace desfire::detail
