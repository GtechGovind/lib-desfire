/// @file
/// @brief Move-only secret storage with explicit erasure on shrink, replacement and destruction.
/// Growth uses a fresh allocation so vector reallocation cannot free an uncleansed live secret.

#include "secret_buffer.hpp"

#include <algorithm>
#include <openssl/crypto.h>

namespace desfire::detail {
  /// Overwrite a caller-owned live range with OpenSSL's non-elidable cleanse.
  /// A nonzero extent requires writable storage; zero length accepts null and does no work.
  /// Ownership and allocation remain with the caller and no failure is reported.
  void secure_zero(
    void *data,
    std::size_t size
  ) noexcept {
    if (size) {
      OPENSSL_cleanse(data, size);
    }
  }

  /// Copy a borrowed range into independently owned secret storage.
  /// The caller keeps source bytes alive during construction and remains responsible for them;
  /// allocation failure propagates without changing the source. Empty views need no pointer access.
  secret_buffer::secret_buffer(byte_view value) {
    if (!value.empty()) {
      data_.assign(value.begin(), value.end());
    }
  }

  /// Erase all remaining live bytes before the vector releases their allocation.
  /// Bytes discarded by this buffer's earlier clear/shrink operations were already erased;
  /// adopting a vector never claims ownership of unrelated bytes in its unused capacity.
  secret_buffer::~secret_buffer() {
    clear();
  }

  /// Transfer the allocation without copying secret bytes, leaving the source logically empty.
  /// Swapping into initially empty storage preserves one erasure owner and cannot allocate/fail.
  secret_buffer::secret_buffer(secret_buffer &&other) noexcept {
    data_.swap(other.data_);
  }

  /// Replace this buffer by taking the source allocation after erasing the old live secret.
  /// The source becomes empty; its received allocation's previously live bytes were erased.
  /// Self-move is a no-op.
  /// No copying or allocation occurs, so ownership transfer is nonthrowing.
  secret_buffer &secret_buffer::operator=(secret_buffer &&other) noexcept {
    if (this != &other) {
      clear();
      data_.swap(other.data_);
    }
    return *this;
  }

  /// Erase every live byte before reducing the logical length to zero.
  /// Retain the now-cleansed capacity for later reuse; borrowed views cease to describe live data.
  void secret_buffer::clear() noexcept {
    secure_zero(data_.data(), data_.size());
    data_.clear();
  }

  /// Preserve the common prefix while erasing discarded bytes or zero-initializing a new tail.
  /// Growth allocates before touching the old secret, giving allocation failure a strong guarantee;
  /// after successful growth, all old live bytes are cleansed before their allocation is released.
  void secret_buffer::resize(std::size_t size) {
    if (size <= data_.size()) {
      if (size < data_.size()) {
        secure_zero(data_.data() + size, data_.size() - size);
      }
      data_.resize(size);
      return;
    }
    // Allocate first so failure leaves the old secret intact; erase the old live range
    // before swapping it into the replacement vector that is about to release it.
    bytes replacement(size);
    std::copy(data_.begin(), data_.end(), replacement.begin());
    clear();
    data_.swap(replacement);
  }
} // namespace desfire::detail
