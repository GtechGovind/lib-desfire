#pragma once

#include <desfire/buffer/byte_view.hpp>
#include <desfire/common/result.hpp>
#include <desfire/model/enums.hpp>

#include <memory>

namespace desfire::detail {
  /// Per-card provider ownership; OpenSSL 3 providers remain loaded while operations use them.
  struct crypto_context;

  /// Create a private provider context supporting AES and legacy DES; report crypto_error on
  /// failure.
  result<std::shared_ptr<crypto_context>> create_crypto_context();

  /// Return size cryptographically random bytes; reject sizes beyond OpenSSL's int-sized API.
  result<bytes> generate_random_bytes(std::size_t size);

  /// Cipher block width in bytes: 16 for AES, 8 for the supported DES variants.
  /// Callers must first validate type with key_size(type) != 0.
  std::size_t block_size(key_type type) noexcept;

  /// Required key bytes; zero identifies an unsupported enum value.
  std::size_t key_size(key_type type) noexcept;

  /// Encrypt exactly one block with no padding; inputs are borrowed and output is caller-owned.
  /// Invalid types or lengths yield invalid_argument; provider failures yield crypto_error.
  result<bytes> encrypt_block(
    crypto_context &context,
    key_type type,
    byte_view key,
    byte_view input
  );

  /// Decrypt exactly one block; validation and output ownership match encrypt_block.
  result<bytes> decrypt_block(
    crypto_context &context,
    key_type type,
    byte_view key,
    byte_view input
  );

  /// Encrypt whole blocks without padding; require one block of IV and leave the borrowed IV
  /// intact. Callers own protocol IV updates and erasure of any key-derived output they retain.
  result<bytes> encrypt_cbc(
    crypto_context &context,
    key_type type,
    byte_view key,
    byte_view iv,
    byte_view input
  );

  /// Decrypt whole blocks without padding; validation and IV ownership match encrypt_cbc.
  result<bytes> decrypt_cbc(
    crypto_context &context,
    key_type type,
    byte_view key,
    byte_view iv,
    byte_view input
  );

  /// Return a full-block CMAC, using an all-zero IV unless a full-block initial_iv is supplied.
  /// The nonzero-IV form implements DESFire's retained chaining state; it does not mutate inputs.
  result<bytes> calculate_cmac(
    crypto_context &context,
    key_type type,
    byte_view key,
    byte_view input,
    byte_view initial_iv = {}
  );

  /// Compare equal-length bytes in constant time; differing lengths fail before byte comparison.
  bool constant_time_equal(
    byte_view left,
    byte_view right
  ) noexcept;
} // namespace desfire::detail
