/// @file
/// @brief Shared DF and EF scope for native and standard card commands.
#pragma once

#include <cstdint>
#include <optional>

namespace desfire::detail {
  /// Host knowledge of the selected DF. A successful ISO DF select carries no native AID.
  enum class selected_scope {
    /// Known native AID, including PICC zero after master-file selection.
    native,
    /// Standard application DF with no known mapping to a native AID.
    iso_application,
    /// No established DF after an uncertain selection.
    unknown
  };

  /// Track the two protocol views of the same physical selection under operation admission.
  struct selection_state {
    /// Scope established by the last successful selecting command.
    selected_scope scope{selected_scope::native};
    /// Native AID when known, including zero for PICC. ISO DF selects can leave it absent.
    std::optional<std::uint32_t> native_application{0};
    /// ISO DF identifier when explicitly provided by the selecting command.
    std::optional<std::uint16_t> iso_df;
    /// Current EF's full identifier when last selected with SELECT FILE.
    std::optional<std::uint16_t> iso_ef;
    /// Current EF's short identifier after implicit selection by an ISO data command.
    std::optional<std::uint8_t> iso_short_file_id;
  };

  /// Record explicit native selection, including the known PICC AID zero.
  void select_native_scope(
    selection_state &selection,
    std::uint32_t aid
  ) noexcept;

  /// Record a verified application selection with unavailable native mapping.
  void select_iso_application_scope(
    selection_state &selection,
    const std::optional<std::uint16_t> &identifier
  ) noexcept;

  /// Record an elementary file selection via explicit short-file addressing, when present.
  void select_short_ef(
    selection_state &selection,
    const std::optional<std::uint8_t> &short_file_id
  ) noexcept;

  /// Discard selection knowledge after an ambiguously delivered selection command.
  void invalidate_selection(selection_state &selection) noexcept;

  /// True only when native AID zero is established for this physical selection.
  bool is_picc_selected(const selection_state &selection) noexcept;

}
