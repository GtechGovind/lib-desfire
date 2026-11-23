/// @file
/// @brief Compiled ownership and non-elidable erasure for normalized generic byte inputs.
/// Borrowed views never transfer ownership; only the vector's live owned extent is cleansed.

#include "input_buffer.hpp"
#include "../crypto/secret_buffer.hpp"

namespace desfire::detail {

  /// Cleanse the caller-specified writable extent without allocating or throwing.
  /// @param data Live writable storage, or null when size is zero.
  /// @param size Number of bytes to erase; no capacity beyond this extent is inspected.
  void erase_bytes(
    void *data,
    std::size_t size
  ) noexcept {
    secure_zero(data, size);
  }

  /// Adopt an already normalized vector without copying and point the view at its live elements.
  /// Vector move construction cannot allocate with bytes' standard allocator. The vector's own
  /// data/size invariant makes the checked view construction nonthrowing here.
  input_buffer::input_buffer(bytes owned) noexcept
      : owned_(std::move(owned)),
        view_(owned_) {}

  /// Erase the owned live range before its allocation is released; borrowed input is untouched.
  input_buffer::~input_buffer() {
    clear();
  }

  /// Cleanse owned live elements, retain the allocation, and invalidate this wrapper's view.
  /// Repeated clearing is harmless. Spare capacity supplied by an arbitrary adopted vector is
  /// outside the live range and is not inspected; normalization itself never shrinks its vector.
  void input_buffer::clear() noexcept {
    erase_bytes(owned_.data(), owned_.size());
    owned_.clear();
    view_ = {};
  }

} // namespace desfire::detail
