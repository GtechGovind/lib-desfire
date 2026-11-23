/// @file
/// @brief Standard selection scope and response form.
#pragma once

namespace desfire {
  /// Select a child application DF or an EF directly under the currently selected DF.
  enum class iso7816_file_scope {
    /// Select a child dedicated file by identifier and establish application scope.
    application_df,
    /// Select an elementary file within the current dedicated file.
    elementary_file
  };

  /// Request status only, or the card's raw application file control information.
  enum class iso7816_select_response {
    /// Return only SW1/SW2.
    none,
    /// Request the application-specific file control information as raw bytes.
    fci
  };
}
