/// @file
/// @brief Explicit cipher families, authentication protocols and native file policy values.

#ifndef desfire_desfire_model_enums_hpp
#define desfire_desfire_model_enums_hpp
#include <cstdint>

namespace desfire {
  /// Raw key family; key bytes are supplied separately and are never hex-decoded.
  enum class key_type {
    des,     ///< Eight-byte single-DES key.
    tdes_2k, ///< Sixteen-byte two-key triple-DES key.
    tdes_3k, ///< Twenty-four-byte three-key triple-DES key.
    aes_128  ///< Sixteen-byte AES-128 key.
  };

  /// Authentication protocol, distinct from the cipher family used by its key.
  enum class authentication_type {
    none,   ///< No authenticated session.
    legacy, ///< Native 0x0A DES/two-key TDES authentication.
    iso,    ///< Native 0x1A DES/TDES authentication, not ISO 7816 external authentication.
    aes,    ///< Native 0xAA AES authentication.
    iso7816 ///< Standard 84/82/88 mutual authentication using DESFire EV1 session protection.
  };

  /// Native file communication policy; pass the actual file policy to read/write operations.
  enum class communication_mode : std::uint8_t {
    plain = 0,    ///< Clear payload, with session-dependent command/response handling.
    mac = 1,      ///< Clear payload authenticated according to the active session.
    encrypted = 3 ///< Encrypted payload with the session's integrity checks.
  };

  /// Native GetFileSettings discriminator; administrative and transaction behavior differ by type.
  enum class file_type : std::uint8_t {
    standard_data = 0, ///< Data writes take effect without CommitTransaction.
    backup_data = 1,   ///< Data writes are transactional.
    value = 2,         ///< Signed balance with card-enforced limits.
    linear_record = 3, ///< Records stop accumulating at the configured capacity.
    cyclic_record = 4  ///< New records replace the oldest records at capacity.
  };
} // namespace desfire

#endif // desfire_desfire_model_enums_hpp
