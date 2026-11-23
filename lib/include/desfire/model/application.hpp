/// @file
/// @brief Numeric application creation policy and owned native directory entries.

#ifndef desfire_desfire_model_application_hpp
#define desfire_desfire_model_application_hpp
#include "../buffer/byte_view.hpp"
#include <optional>

namespace desfire {
  /// The two native settings bytes, preserving key-family and ISO-directory flags.
  struct key_settings {
    /// Master-key and directory access policy.
    std::uint8_t settings_1{0};
    /// Low nibble: key count (0..14); 0x20: ISO IDs; 0xC0: cipher family (0xC0 is invalid).
    std::uint8_t settings_2{0};
  };

  /// Copied application creation policy; fields are serialized individually, without host padding.
  /// DF-name bytes are supplied as a separate generic range and are not retained by the card
  /// object.
  struct application_config {
    /// Nonzero numeric 24-bit identifier; encoded little-endian on the native wire.
    std::uint32_t id{0};
    /// Exact native settings, independent of host struct representation.
    key_settings keys{};
    /// Must be present exactly when keys.settings_2 has bit 0x20 set; names also require this
    /// field.
    std::optional<std::uint16_t> iso_id{};
  };

  /// One owned physical GetDFNames directory record, exposed after whole-response checks succeed.
  struct df_name_entry {
    /// Numeric native application identifier.
    std::uint32_t application_id{0};
    /// Numeric ISO file identifier.
    std::uint16_t iso_id{0};
    /// Owned raw name bytes (0..16); no character conversion or terminator is added.
    bytes name{};
  };
} // namespace desfire

#endif // desfire_desfire_model_application_hpp
