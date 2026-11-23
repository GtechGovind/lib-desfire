/// @file
/// @brief Borrow contiguous inputs, erase collected inputs, and copy verified bounded outputs.

#ifndef desfire_desfire_buffer_buffer_helpers_hpp
#define desfire_desfire_buffer_buffer_helpers_hpp
#include "../common/result.hpp"
#include "buffer_traits.hpp"
#include "byte_view.hpp"
#include <new>

namespace desfire::detail {

  /// Overwrite size writable bytes using the private backend's non-elidable erasure routine.
  /// A null data pointer is permitted only for an empty extent.
  void erase_bytes(
    void *data,
    std::size_t size
  ) noexcept;

  /// Keep normalized input alive for one synchronous call and erase any owned bytes on exit.
  /// Borrowed storage remains caller-owned and is never erased by this wrapper.
  class input_buffer {

    bytes owned_;
    byte_view view_;

  public:

    /// Borrow an existing view whose allocation remains valid until clear() or destruction.
    explicit input_buffer(const byte_view borrowed) noexcept : view_(borrowed) {}

    /// Take ownership of normalized input; the moved vector is erased before release.
    explicit input_buffer(bytes owned) noexcept;

    /// Erase owned input; borrowed storage is left untouched.
    ~input_buffer();

    /// Copying would duplicate ownership and invalidate the relationship between storage and view.
    input_buffer(const input_buffer &) = delete;

    /// Owned input and its borrowed view cannot be reassigned independently.
    input_buffer &operator=(const input_buffer &) = delete;

    /// Borrow normalized bytes until this wrapper is cleared or destroyed.
    [[nodiscard]] byte_view view() const noexcept { return view_; }

    /// Erase live owned elements and reset the view while retaining allocation capacity.
    /// Bytes outside the vector's live extent are not inspected or erased.
    void clear() noexcept;
  };

  /// Preserve all eight bits of char, signed/unsigned char or std::byte input.
  template <class value_type> std::uint8_t to_byte(value_type value) {
    static_assert(is_byte_like<value_type>::value, "one-byte elements required");
    if constexpr (std::is_same_v<std::remove_cv_t<value_type>, std::byte>) {
      return std::to_integer<std::uint8_t>(value);
    } else {
      return static_cast<std::uint8_t>(value);
    }
  }

  /// Borrow a contiguous byte range without copying or text conversion.
  /// The caller keeps its allocation valid and unchanged through use of the returned view.
  template <class range> byte_view make_byte_view(const range &value) {
    static_assert(is_contiguous_byte_range<range>::value, "contiguous byte range required");
    return {
      reinterpret_cast<const std::uint8_t *>(std::data(value)),
      static_cast<std::size_t>(std::size(value))
    };
  }

  /// Consume a valid byte input range once, up to limit bytes, into owned storage.
  /// On overflow or iterator/allocation exceptions, erase collected bytes before returning an
  /// error. Successful callers must erase the returned bytes when they contain sensitive input.
  template <class iterator>
  result<bytes> collect_bytes(
    iterator first,
    iterator last,
    std::size_t limit
  ) {
    static_assert(is_byte_input_iterator<iterator>::value, "byte input iterator required");
    using value_type = typename std::iterator_traits<iterator>::value_type;
    bytes output;
    try {
      output.reserve(limit);
      for (; first != last; ++first) {
        if (output.size() == limit) {
          erase_bytes(output.data(), output.size());
          return result<bytes>::failure({error_code::response_too_large});
        }
        output.push_back(to_byte(static_cast<value_type>(*first)));
      }
      return result<bytes>::success(std::move(output));
    } catch (const std::bad_alloc &) {
      erase_bytes(output.data(), output.size());
      return result<bytes>::failure({error_code::allocation_failed});
    } catch (...) {
      erase_bytes(output.data(), output.size());
      return result<bytes>::failure({error_code::callback_failed});
    }
  }

  /// Normalize a single-pass input pair, call function synchronously, then erase the owned copy.
  /// function receives a borrowed view that must not escape the call; collection errors prevent it.
  template <
    class result_type = void,
    class iterator,
    class function_type>
  result<result_type> with_input(
    iterator first,
    iterator last,
    std::size_t limit,
    function_type function
  ) {
    auto collected = collect_bytes(first, last, limit);
    if (!collected) {
      return result<result_type>::failure(collected.get_error());
    }
    input_buffer input(std::move(collected.value()));
    return function(input.view());
  }

  /// Borrow contiguous input or collect other byte ranges; reject oversized input before function.
  /// The caller owns the original range. Only a collected temporary is erased after function
  /// returns.
  template <
    class result_type = void,
    class range,
    class function_type>
  result<result_type> with_input(
    const range &value,
    std::size_t limit,
    function_type function
  ) {
    static_assert(is_byte_range<range>::value, "byte range required");
    using storage_type =
      std::conditional_t<is_contiguous_byte_range<range>::value, byte_view, bytes>;
    // Only preflight runs under this handler. The command reports its own delivery outcome.
    const auto normalize = [&]() -> result<storage_type> {
      try {
        if constexpr (is_contiguous_byte_range<range>::value) {
          auto view = make_byte_view(value);
          if (view.size() > limit) {
            return result<storage_type>::failure({error_code::response_too_large});
          }
          return result<storage_type>::success(view);
        } else {
          return collect_bytes(std::begin(value), std::end(value), limit);
        }
      } catch (const std::bad_alloc &) {
        return result<storage_type>::failure({error_code::allocation_failed});
      } catch (...) {
        return result<storage_type>::failure({error_code::callback_failed});
      }
    };
    auto normalized = normalize();
    if (!normalized) {
      return result<result_type>::failure(normalized.get_error());
    }
    input_buffer input(std::move(normalized.value()));
    return function(input.view());
  }

  /// Inspect at most needed writable forward elements without changing the range.
  /// Return buffer_too_small before output is modified; iterator exceptions propagate to the
  /// caller.
  template <class iterator>
  result<std::size_t> validate_output_capacity(
    iterator first,
    iterator last,
    std::size_t needed
  ) {
    static_assert(
      is_writable_byte_iterator<iterator>::value, "bounded writable forward byte iterator required"
    );
    std::size_t count = 0;
    for (; first != last && count < needed; ++first) {
      ++count;
    }
    if (count < needed) {
      return result<std::size_t>::failure({error_code::buffer_too_small});
    }
    return result<std::size_t>::success(count);
  }

  /// Copy source into an existing bounded byte range after checking complete capacity.
  /// Returns bytes written; insufficient capacity leaves output untouched. Iterator exceptions
  /// propagate and may leave a partially written destination.
  template <class iterator>
  result<std::size_t> copy_bytes(
    byte_view source,
    iterator first,
    iterator last
  ) {
    auto capacity = validate_output_capacity(first, last, source.size());
    if (!capacity) {
      return capacity;
    }
    using value_type = typename std::iterator_traits<iterator>::value_type;
    for (auto byte : source) {
      *first = static_cast<value_type>(byte);
      ++first;
    }
    return result<std::size_t>::success(source.size());
  }
} // namespace desfire::detail

#endif // desfire_desfire_buffer_buffer_helpers_hpp
