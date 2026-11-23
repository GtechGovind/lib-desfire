/// @file
/// @brief Owned byte storage alias and a non-owning checked byte slice.

#ifndef desfire_desfire_buffer_byte_view_hpp
#define desfire_desfire_buffer_byte_view_hpp
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace desfire {
  /// Owning dynamic byte sequence returned by reads and transport callbacks.
  /// Ordinary bytes storage is not erased on destruction; the core erases its secret temporaries.
  using bytes = std::vector<std::uint8_t>;

  namespace detail {
    /// Read-only byte span; the caller keeps the backing allocation alive and unchanged.
    /// Empty views may have null data. Bounds are checked only by subview(), not operator[].
    class byte_view {
      const std::uint8_t *data_{nullptr};
      std::size_t size_{0};

    public:

      /// Construct an empty view that borrows no allocation.
      byte_view() = default;

      /// Borrow size bytes starting at data without copying.
      /// @pre A nonempty range describes live storage for at least size bytes.
      /// @throws std::invalid_argument data is null while size is nonzero.
      byte_view(
        const std::uint8_t *data,
        std::size_t size
      )
          : data_(data),
            size_(size) {
        if (!data && size) {
          throw std::invalid_argument("null byte view");
        }
      }

      /// Borrow a vector's elements; resizing or destroying the vector invalidates the view.
      explicit byte_view(const bytes &data)
          : byte_view(
              data.data(),
              data.size()
            ) {}

      /// Return the borrowed address, possibly null for an empty view.
      [[nodiscard]] const std::uint8_t *data() const noexcept { return data_; }

      /// Return the view's extent in bytes.
      [[nodiscard]] std::size_t size() const noexcept { return size_; }

      /// Return whether this view contains no bytes.
      [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

      /// Return a read-only iterator to the first byte.
      [[nodiscard]] const std::uint8_t *begin() const noexcept { return data_; }

      /// Return the matching end without performing arithmetic on a null pointer.
      [[nodiscard]] const std::uint8_t *end() const noexcept {
        return size_ ? data_ + size_ : data_;
      }

      /// Read one byte; index must be less than size().
      std::uint8_t operator[](std::size_t index) const { return data_[index]; }

      /// Borrow count bytes at offset; the returned slice shares this view's lifetime requirement.
      /// @throws std::out_of_range The requested slice extends beyond this view.
      [[nodiscard]] byte_view subview(
        std::size_t offset,
        std::size_t count
      ) const {
        if (offset > size_ || count > size_ - offset) {
          throw std::out_of_range("byte subview");
        }
        return {offset ? data_ + offset : data_, count};
      }
    };
  } // namespace detail
} // namespace desfire

#endif // desfire_desfire_buffer_byte_view_hpp
