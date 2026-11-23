/// @file
/// @brief Owned fields decoded from the native GetVersion response.

#ifndef desfire_desfire_model_version_hpp
#define desfire_desfire_model_version_hpp
#include <array>
#include <cstdint>

namespace desfire {
  /// Exact fields of the legacy 28-byte GetVersion response, with raw vendor encodings retained.
  struct version_info {
    /// Seven hardware-description bytes in native response order.
    std::array<std::uint8_t, 7> hardware{};
    /// Seven software-description bytes in native response order.
    std::array<std::uint8_t, 7> software{};
    /// Seven UID bytes in card order.
    std::array<std::uint8_t, 7> uid{};
    /// Five-byte manufacturing batch identifier.
    std::array<std::uint8_t, 5> batch{};
    /// Raw card-encoded manufacturing week; no calendar conversion is applied.
    std::uint8_t production_week{0};
    /// Raw card-encoded manufacturing year; no century is inferred.
    std::uint8_t production_year{0};
  };
} // namespace desfire

#endif // desfire_desfire_model_version_hpp
