#pragma once

#include <desfire/buffer/byte_view.hpp>

#include <utility>

namespace desfire::detail {
  /// Overwrite size bytes through OpenSSL's non-elidable cleanse; data may be null only for size 0.
  void secure_zero(
    void *data,
    std::size_t size
  ) noexcept;

  /// Move-only storage that erases its live contents before release or replacement.
  class secret_buffer {
    /// Owned live bytes; shrinking erases the discarded range before its lifetime ends.
    bytes data_;

  public:

    /// Construct empty storage with no borrowed input.
    secret_buffer() = default;

    /// Take vector ownership without copying its live secret bytes.
    explicit secret_buffer(bytes value) noexcept : data_(std::move(value)) {}

    /// Copy a borrowed range into independently owned, erasable storage.
    explicit secret_buffer(byte_view value);

    /// Erase every live byte before releasing storage.
    ~secret_buffer();

    secret_buffer(const secret_buffer &) = delete;
    secret_buffer &operator=(const secret_buffer &) = delete;

    /// Transfer storage, leaving other empty.
    secret_buffer(secret_buffer &&other) noexcept;

    /// Erase this buffer, then transfer storage; self-move preserves the contents.
    secret_buffer &operator=(secret_buffer &&other) noexcept;

    /// Borrow mutable live bytes until the buffer is resized, cleared, moved or destroyed.
    [[nodiscard]] std::uint8_t *data() noexcept { return data_.data(); }

    /// Borrow read-only live bytes with the same lifetime as the mutable overload.
    [[nodiscard]] const std::uint8_t *data() const noexcept { return data_.data(); }

    /// Number of live secret bytes, excluding spare capacity.
    [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }

    /// Borrow the live range; the view never extends the buffer's lifetime.
    [[nodiscard]] byte_view view() const noexcept { return {data(), size()}; }

    /// Preserve the common prefix; erase discarded bytes or zero-initialize newly added bytes.
    void resize(std::size_t size);

    /// Erase all live bytes and become empty while retaining allocation capacity.
    void clear() noexcept;
  };
} // namespace desfire::detail
