/// @file
/// Application directory builders and serialized card entry points.
/// All AIDs are numeric 24-bit values encoded least-significant byte first; DF names
/// are copied as uninterpreted bytes. Builders do not mutate the live card session.

#include "../protocol/codec.hpp"
#include "builders.hpp"

namespace desfire::detail {

  /// Build CreateApplication after validating its key-family and optional ISO fields.
  /// @param config Nonzero 24-bit AID, raw key settings and an optional numeric ISO ID.
  /// @param name Borrowed raw DF-name bytes, at most 16; copied into the owned header.
  /// @return Status-only management policy, or invalid_argument before any I/O.
  command_result build_create_application(
    const application_config &config,
    byte_view name
  ) {
    if (!validate_application_config(config, name)) {
      return invalid_command();
    }
    auto request = management_command(0xca);
    append_application_id(request.header, config.id);
    request.header.push_back(config.keys.settings_1);
    request.header.push_back(config.keys.settings_2);
    if (config.iso_id) {
      append_u16_le(request.header, *config.iso_id);
    }
    if (!name.empty()) {
      request.header.insert(request.header.end(), name.begin(), name.end());
    }
    return command_result::success(std::move(request));
  }

  /// Build deletion of a nonzero 24-bit application identifier.
  /// @param id Numeric AID; zero is PICC scope and cannot be deleted.
  /// @return Status-only management policy, or invalid_argument for an out-of-range AID.
  command_result build_delete_application(std::uint32_t id) {
    if (!id || id > 0xffffff) {
      return invalid_command();
    }
    auto request = management_command(0xda);
    append_application_id(request.header, id);
    return command_result::success(std::move(request));
  }

  /// Build GetApplicationIDs with a variable-length verified payload.
  /// @return Plain outgoing command; a modern session verifies its aggregated response MAC.
  command_result build_get_application_ids() {
    return command_result::success(management_command(0x6a, {}, {}));
  }

  /// Build selection of an application or PICC scope, clearing authentication before I/O.
  /// @param id Numeric 24-bit AID; zero selects the PICC.
  /// @return Status-only policy with clear_before, or invalid_argument without session changes.
  command_result build_select_application(std::uint32_t id) {
    if (id > 0xffffff) {
      return invalid_command();
    }
    auto request = management_command(0x5a);
    append_application_id(request.header, id);
    request.clear_before = true;
    return command_result::success(std::move(request));
  }

  /// Build GetDFNames while permitting multiple physical directory records.
  /// @return Variable-length management policy; parsing later uses verified frame boundaries.
  command_result build_get_df_names() {
    return command_result::success(management_command(0x6d, {}, {}));
  }
} // namespace desfire::detail

namespace desfire {

  /// Create an application without DF-name bytes through the common serialized path.
  /// @param config Copied native creation fields; ISO-ID presence must match the settings flag.
  /// @return Verified status-only success, or validation, transport or response-protection error.
  result<void> card::create_application(const application_config &config) {
    return create_application_bytes(config, {});
  }

  /// Create an application with a borrowed raw DF name, copied while the operation is held.
  /// @param config Native AID, key settings and optional ISO identifier.
  /// @param name Raw name bytes, at most 16, valid for this synchronous call.
  /// @return Verified status-only success; local validation fails before transmission.
  result<void> card::create_application_bytes(
    const application_config &config,
    detail::byte_view name
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_create_application(config, name);
    });
  }

  /// Send one application deletion and verify its status response.
  /// @param id Nonzero numeric 24-bit AID.
  /// @return Operation result; uncertain delivery is reported without replaying the deletion.
  result<void> card::delete_application(std::uint32_t id) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_delete_application(id);
    });
  }

  /// Enumerate owned numeric AIDs after whole-response integrity verification.
  /// @return Complete three-byte IDs; a partial final ID is malformed_response with unknown
  /// delivery and invalidates the session through run_command.
  result<std::vector<std::uint32_t>> card::get_application_ids() {
    return detail::run_command<std::vector<std::uint32_t>>(
      mutable_state(), detail::build_get_application_ids, detail::parse_application_ids
    );
  }

  /// Select an AID and publish the new selected scope only after verified success.
  /// @param id Numeric 24-bit AID; zero selects PICC scope.
  /// @return Operation result. A valid selection discards old authentication before submission,
  /// including when the card later rejects the selection.
  result<void> card::select_application(std::uint32_t id) {
    return detail::run_operation<void>(mutable_state(), [&](const auto &operation) {
      auto request = detail::build_select_application(id);
      if (!request) {
        return result<void>::failure(request.get_error());
      }
      auto &state = mutable_state();
      try {
        auto value = detail::execute_command(state, request.value(), operation);
        if (value) {
          detail::select_native_scope(state.selection, id);
        } else if (value.get_error().outcome == delivery_outcome::unknown) {
          detail::invalidate_selection(state.selection);
        }
        return detail::discard_value(std::move(value));
      } catch (...) {
        if (state.transmitted) {
          detail::invalidate_selection(state.selection);
        }
        throw;
      }
    });
  }

  /// Decode each nonempty verified GetDFNames frame as one owned directory entry.
  /// @return Entries in physical-frame order; an invalid AID/ISO/name layout fails atomically and
  /// invalidates the session. Empty final frames, including a MAC-only frame, add no entry.
  result<std::vector<df_name_entry>> card::get_df_names() {
    return detail::run_command<std::vector<df_name_entry>>(
      mutable_state(), detail::build_get_df_names, [&](detail::byte_view) {
        std::vector<df_name_entry> output;
        for (const auto &frame : mutable_state().response_frames) {
          if (frame.empty()) {
            continue;
          }
          auto parsed = detail::parse_df_name_frame(detail::byte_view(frame));
          if (!parsed) {
            return result<std::vector<df_name_entry>>::failure(parsed.get_error());
          }
          output.push_back(std::move(parsed.value()));
        }
        return result<std::vector<df_name_entry>>::success(std::move(output));
      }
    );
  }
} // namespace desfire
