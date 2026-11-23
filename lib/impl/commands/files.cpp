/// @file
/// Native file-directory, settings and creation command policies.
/// Creation settings are clear command parameters even when the new file mode is
/// encrypted; ChangeFileSettings independently chooses outgoing command protection.

#include "../protocol/codec.hpp"
#include "builders.hpp"

namespace desfire::detail {

  /// Build native one-byte file enumeration with a variable verified response length.
  /// @return Management policy; parse_file_ids later enforces the native 0..31 identifier range.
  command_result build_get_fids() {
    return command_result::success(management_command(0x6f, {}, {}));
  }

  /// Build ISO file-ID enumeration, retaining numeric two-byte response fields.
  /// @return Variable-length management policy; incomplete ISO IDs are rejected by the parser.
  command_result build_get_iso_fids() {
    return command_result::success(management_command(0x61, {}, {}));
  }

  /// Build a type-dependent GetFileSettings query.
  /// @param file Native file number, 0..31.
  /// @return Variable-length policy, or invalid_argument; the parser enforces the exact type
  /// layout.
  command_result build_get_file_settings(std::uint8_t file) {
    if (file > 31) {
      return invalid_command();
    }
    return command_result::success(management_command(0xf5, {file}, {}));
  }

  /// Build a policy update whose clear file selector precedes three settings bytes.
  /// @param file Native file number, 0..31.
  /// @param settings New mode/access selectors and an independent encryption choice.
  /// @return Status-only policy, or invalid_argument. Legacy CRC-A covers the three encrypted
  /// policy bytes; modern CRC32 covers the complete command including the clear header.
  command_result build_change_file_settings(
    std::uint8_t file,
    const file_settings_change &settings
  ) {
    if (file > 31 || !valid_mode(settings.mode) || !valid_access(settings.access)) {
      return invalid_command();
    }
    auto request = management_command(0x5f, {file});
    bytes payload{static_cast<std::uint8_t>(settings.mode)};
    append_access_rights(payload, settings.access);
    request.data = secret_buffer(std::move(payload));
    request.request_mode =
      settings.encrypted_command ? communication_mode::encrypted : communication_mode::plain;
    request.legacy_crc_skip = 2;
    return command_result::success(std::move(request));
  }

  /// Build standard or backup creation, validating mode/access and a nonzero byte size.
  /// @param file Native file number, 0..31.
  /// @param config File policy, 24-bit byte size and optional numeric ISO ID.
  /// @param backup Select backup opcode 0xCB when true, standard opcode 0xCD otherwise.
  /// @return Status-only management policy with creation fields copied into its clear header,
  /// or invalid_argument before any transport activity.
  command_result build_create_data_file(
    std::uint8_t file,
    const data_file_config &config,
    bool backup
  ) {
    if (file > 31 || !validate_data_file_config(config)) {
      return invalid_command();
    }
    auto request = management_command(backup ? 0xcb : 0xcd, {file});
    if (config.iso_id) {
      append_u16_le(request.header, *config.iso_id);
    }
    request.header.push_back(static_cast<std::uint8_t>(config.mode));
    append_access_rights(request.header, config.access);
    append_u24_le(request.header, config.size);
    return command_result::success(std::move(request));
  }

  /// Build value-file creation using explicit little-endian two's-complement fields.
  /// @param file Native file number, 0..31.
  /// @param config Ordered signed limits, in-range initial value, access and limited-credit policy.
  /// @return Clear creation policy or invalid_argument; signed values retain their exact low 32
  /// bits.
  command_result build_create_value_file(
    std::uint8_t file,
    const value_file_config &config
  ) {
    if (file > 31 || !validate_value_file_config(config)) {
      return invalid_command();
    }
    auto request = management_command(0xcc, {file, static_cast<std::uint8_t>(config.mode)});
    append_access_rights(request.header, config.access);
    append_u32_le(request.header, static_cast<std::uint32_t>(config.lower_limit));
    append_u32_le(request.header, static_cast<std::uint32_t>(config.upper_limit));
    append_u32_le(request.header, static_cast<std::uint32_t>(config.initial_value));
    request.header.push_back(config.limited_credit_enabled ? 1 : 0);
    return command_result::success(std::move(request));
  }

  /// Build linear or cyclic creation with validated nonzero 24-bit geometry.
  /// @param file Native file number, 0..31.
  /// @param config Record width in bytes, record capacity, access and optional numeric ISO ID.
  /// @param cyclic Select cyclic opcode 0xC0 when true, linear opcode 0xC1 otherwise.
  /// @return Status-only management policy or invalid_argument; geometry remains unmultiplied on
  /// wire.
  command_result build_create_record_file(
    std::uint8_t file,
    const record_file_config &config,
    bool cyclic
  ) {
    if (file > 31 || !validate_record_file_config(config)) {
      return invalid_command();
    }
    auto request = management_command(cyclic ? 0xc0 : 0xc1, {file});
    if (config.iso_id) {
      append_u16_le(request.header, *config.iso_id);
    }
    request.header.push_back(static_cast<std::uint8_t>(config.mode));
    append_access_rights(request.header, config.access);
    append_u24_le(request.header, config.record_size);
    append_u24_le(request.header, config.max_records);
    return command_result::success(std::move(request));
  }

  /// Build deletion of one native file in the selected application.
  /// @param file Native file number, 0..31.
  /// @return Status-only policy, or invalid_argument before transmission.
  command_result build_delete_file(std::uint8_t file) {
    if (file > 31) {
      return invalid_command();
    }
    return command_result::success(management_command(0xdf, {file}));
  }
} // namespace desfire::detail

namespace desfire {

  /// Return owned native file numbers after response verification and range checking.
  /// @return File IDs in response order; an ID above 31 is malformed and invalidates the session.
  result<std::vector<std::uint8_t>> card::get_fids() {
    return detail::run_command<bytes>(
      mutable_state(), detail::build_get_fids, detail::parse_file_ids
    );
  }

  /// Return owned numeric ISO file identifiers after whole-response verification.
  /// @return Decoded little-endian IDs; an odd response length fails and invalidates the session.
  result<std::vector<std::uint16_t>> card::get_iso_fids() {
    return detail::run_command<std::vector<std::uint16_t>>(
      mutable_state(), detail::build_get_iso_fids, detail::parse_iso_file_ids
    );
  }

  /// Query and decode one complete, type-specific settings payload.
  /// @param file Native file number, 0..31.
  /// @return Owned data/value/record settings; malformed type, mode or length invalidates the
  /// session.
  result<file_settings> card::get_file_settings(std::uint8_t file) {
    return detail::run_command<file_settings>(
      mutable_state(),
      [&] {
        return detail::build_get_file_settings(file);
      },
      detail::parse_file_settings
    );
  }

  /// Change file policy and verify one status-only response.
  /// @param file Native file number, 0..31.
  /// @param settings New file policy and the independent outgoing-command protection choice.
  /// @return Operation result; invalid settings are rejected before transmission.
  result<void> card::change_file_settings(
    std::uint8_t file,
    const file_settings_change &settings
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_change_file_settings(file, settings);
    });
  }

  /// Create one standard data file with optional ISO-ID bytes.
  /// @param file Native file number, 0..31.
  /// @param config New file policy and nonzero size in bytes.
  /// @return Verified status-only result; invalid configuration is rejected before I/O.
  result<void> card::create_std_data_file(
    std::uint8_t file,
    const data_file_config &config
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_create_data_file(file, config, false);
    });
  }

  /// Create one transactional backup data file with optional ISO-ID bytes.
  /// @param file Native file number, 0..31.
  /// @param config New file policy and nonzero size in bytes.
  /// @return Verified status-only result; transaction completion remains an explicit caller action.
  result<void> card::create_backup_data_file(
    std::uint8_t file,
    const data_file_config &config
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_create_data_file(file, config, true);
    });
  }

  /// Create a signed value file after validating its inclusive limits and initial value.
  /// @param file Native file number, 0..31.
  /// @param config Values use caller-defined units; access and communication settings are copied.
  /// @return Verified status-only result or a local/transport/protection error.
  result<void> card::create_value_file(
    std::uint8_t file,
    const value_file_config &config
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_create_value_file(file, config);
    });
  }

  /// Create a linear record file with nonzero width and capacity.
  /// @param file Native file number, 0..31.
  /// @param config Width in bytes, capacity in records and native file policy.
  /// @return Verified status-only result; invalid geometry is rejected before I/O.
  result<void> card::create_linear_record_file(
    std::uint8_t file,
    const record_file_config &config
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_create_record_file(file, config, false);
    });
  }

  /// Create a cyclic record file using the same geometry serializer as linear creation.
  /// @param file Native file number, 0..31.
  /// @param config Width in bytes, capacity in records and native file policy.
  /// @return Verified status-only result; invalid geometry is rejected before I/O.
  result<void> card::create_cyclic_record_file(
    std::uint8_t file,
    const record_file_config &config
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_create_record_file(file, config, true);
    });
  }

  /// Delete a native file once under the serialized operation boundary.
  /// @param file Native file number, 0..31.
  /// @return Verified status-only result; unknown delivery is surfaced without automatic replay.
  result<void> card::delete_file(std::uint8_t file) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_delete_file(file);
    });
  }
} // namespace desfire
