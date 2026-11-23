/// @file
/// @brief Maintain a single verified DF/EF selection across native and standard commands.

#include "selection.hpp"

namespace desfire::detail {
  /// Record a known native AID and discard file identifiers from the previous scope.
  void select_native_scope(
    selection_state &selection,
    std::uint32_t aid
  ) noexcept {
    selection = {selected_scope::native, aid, {}, {}, {}};
  }

  /// Record a selected ISO DF with its identifier when available and no native AID mapping.
  void select_iso_application_scope(
    selection_state &selection,
    const std::optional<std::uint16_t> &identifier
  ) noexcept {
    selection = {selected_scope::iso_application, {}, identifier, {}, {}};
  }

  /// Mark scope unknown and discard identifiers after uncertain selection.
  void invalidate_selection(selection_state &selection) noexcept {
    selection = {selected_scope::unknown, {}, {}, {}, {}};
  }

  /// Match known native AID zero. An absent mapping carries no evidence of PICC scope.
  bool is_picc_selected(const selection_state &selection) noexcept {
    return selection.native_application == 0;
  }

  /// Record implicit selection by short ID and clear the previous full EF identifier.
  /// A command that uses the selected file leaves its recorded address in place.
  void select_short_ef(
    selection_state &selection,
    const std::optional<std::uint8_t> &short_file_id
  ) noexcept {
    if (short_file_id) {
      selection.iso_ef.reset();
      selection.iso_short_file_id = short_file_id;
    }
  }
}
