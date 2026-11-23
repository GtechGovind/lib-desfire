/// @file
/// @brief Explicit file policies and owned GetFileSettings payload alternatives.

#ifndef desfire_desfire_model_file_hpp
#define desfire_desfire_model_file_hpp
#include "enums.hpp"
#include <optional>
#include <variant>

namespace desfire {
  /// Four access selectors: key numbers 0..13, 0xE for free access, or 0xF for never.
  /// Each must fit one native nibble; the selected application's policy determines usable keys.
  struct access_rights {
    /// Key permitting read operations.
    std::uint8_t read{0};
    /// Key permitting write operations.
    std::uint8_t write{0};
    /// Key permitting both reads and writes.
    std::uint8_t read_write{0};
    /// Key permitting policy changes.
    std::uint8_t change{0};
  };

  /// Copied creation policy shared by standard and backup data files; contains no borrowed data.
  struct data_file_config {
    /// Communication protection required by the file.
    communication_mode mode{communication_mode::plain};
    /// Explicit access selectors, encoded as two native bytes.
    access_rights access{};
    /// Nonzero file size in bytes, fitting a native 24-bit field.
    std::uint32_t size{0};
    /// Optional numeric ISO file identifier; omitted from native creation when absent.
    std::optional<std::uint16_t> iso_id{};
  };

  /// Copied signed value-file creation policy; amounts use caller-defined units without conversion.
  struct value_file_config {
    /// File communication protection.
    communication_mode mode{communication_mode::plain};
    /// File access selectors.
    access_rights access{};
    /// Inclusive lower value bound.
    std::int32_t lower_limit{0};
    /// Inclusive upper value bound, no smaller than lower_limit.
    std::int32_t upper_limit{0};
    /// Initial value, validated to lie within both limits.
    std::int32_t initial_value{0};
    /// Whether the card permits LimitedCredit operations for this file.
    bool limited_credit_enabled{false};
  };

  /// Copied creation policy shared by linear and cyclic record files; geometry uses byte units.
  struct record_file_config {
    /// File communication protection.
    communication_mode mode{communication_mode::plain};
    /// File access selectors.
    access_rights access{};
    /// Nonzero record width in bytes, fitting a native 24-bit field.
    std::uint32_t record_size{0};
    /// Nonzero record capacity, fitting a native 24-bit field.
    std::uint32_t max_records{0};
    /// Optional numeric ISO file identifier.
    std::optional<std::uint16_t> iso_id{};
  };

  /// File policy update; command protection and the new file mode are independent choices.
  struct file_settings_change {
    /// New communication mode assigned to the file.
    communication_mode mode{communication_mode::plain};
    /// New access selectors assigned to the file.
    access_rights access{};
    /// Encrypt this ChangeFileSettings request under the current session.
    bool encrypted_command{true};
  };

  /// Data-file details returned by GetFileSettings; ISO metadata is not returned by that command.
  struct data_file_info {
    /// Current allocated data-file width in bytes.
    std::uint32_t size{0};
  };

  /// Card-reported value-file limits and limited-credit state.
  struct value_file_info {
    /// Inclusive lower value bound.
    std::int32_t lower_limit{0};
    /// Inclusive upper value bound.
    std::int32_t upper_limit{0};
    /// Card-reported limited-credit value, not the current GetValue balance.
    std::int32_t limited_credit_value{0};
    /// Card-reported limited-credit capability.
    bool limited_credit_enabled{false};
  };

  /// Card-reported record geometry and occupancy.
  struct record_file_info {
    /// Record width in bytes.
    std::uint32_t record_size{0};
    /// Configured record capacity.
    std::uint32_t max_records{0};
    /// Current number of stored records.
    std::uint32_t current_records{0};
  };

  /// Owned parsed settings whose information alternative corresponds to type.
  struct file_settings {
    /// Native file type reported by the card.
    file_type type{file_type::standard_data};
    /// Communication protection reported by the card.
    communication_mode mode{communication_mode::plain};
    /// Decoded read/write/change access selectors.
    access_rights access{};
    /// Data details for either data type, value details for value, record details for either record
    /// type.
    std::variant<data_file_info, value_file_info, record_file_info> information{};
  };
} // namespace desfire

#endif // desfire_desfire_model_file_hpp
