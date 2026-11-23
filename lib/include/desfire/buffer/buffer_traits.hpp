/// @file
/// @brief C++17 detection traits for borrowed byte ranges and bounded writable outputs.

#ifndef desfire_desfire_buffer_buffer_traits_hpp
#define desfire_desfire_buffer_buffer_traits_hpp
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <utility>

namespace desfire::detail {
  /// Recognize byte storage without accepting bool or wider integer elements.
  template <class value_type>
  struct is_byte_like : std::bool_constant<
                          std::is_same_v<std::remove_cv_t<value_type>, char> ||
                          std::is_same_v<std::remove_cv_t<value_type>, signed char> ||
                          std::is_same_v<std::remove_cv_t<value_type>, unsigned char> ||
                          std::is_same_v<std::remove_cv_t<value_type>, std::byte>> {};

  /// Recognize readable input-or-stronger iterators whose value type is byte-like.
  /// Single-pass iterators are accepted; output-only iterators are not.
  template <class iterator, class = void> struct is_byte_input_iterator : std::false_type {};

  template <class iterator>
  struct is_byte_input_iterator<
    iterator,
    std::void_t<
      typename std::iterator_traits<iterator>::value_type,
      typename std::iterator_traits<iterator>::iterator_category,
      decltype(*std::declval<iterator &>()),
      decltype(++std::declval<iterator &>()),
      decltype(std::declval<const iterator &>() != std::declval<const iterator &>())>>
      : std::bool_constant<
          is_byte_like<typename std::iterator_traits<iterator>::value_type>::value &&
          std::is_base_of_v<
            std::input_iterator_tag,
            typename std::iterator_traits<iterator>::iterator_category> &&
          std::is_convertible_v<
            decltype(*std::declval<iterator &>()),
            typename std::iterator_traits<iterator>::value_type>> {};

  /// Recognize const-iterable byte ranges, including standard containers and C arrays.
  template <class range, class = void> struct is_byte_range : std::false_type {};

  template <class range>
  struct is_byte_range<
    range,
    std::void_t<
      decltype(std::begin(std::declval<const range &>())),
      decltype(std::end(std::declval<const range &>()))>>
      : is_byte_input_iterator<decltype(std::begin(std::declval<const range &>()))> {};

  /// Recognize data()/size() ranges that can be borrowed as nonvolatile byte storage.
  /// The pointer and reported size must describe one valid contiguous allocation.
  template <class range, class = void> struct is_contiguous_byte_range : std::false_type {};

  template <class range>
  struct is_contiguous_byte_range<
    range,
    std::void_t<
      decltype(std::data(std::declval<const range &>())),
      decltype(std::size(std::declval<const range &>()))>>
      : std::bool_constant<
          std::is_pointer_v<decltype(std::data(std::declval<const range &>()))> &&
          is_byte_like<
            std::remove_pointer_t<decltype(std::data(std::declval<const range &>()))>>::value &&
          !std::is_volatile_v<
            std::remove_pointer_t<decltype(std::data(std::declval<const range &>()))>> &&
          std::is_convertible_v<decltype(std::size(std::declval<const range &>())), std::size_t>> {
  };

  /// Recognize multipass byte iterators with assignable nonconst lvalue references.
  /// A bounded pair is required so capacity can be checked before any output is modified.
  template <class iterator, class = void> struct is_writable_byte_iterator : std::false_type {};

  template <class iterator>
  struct is_writable_byte_iterator<
    iterator,
    std::void_t<
      typename std::iterator_traits<iterator>::value_type,
      typename std::iterator_traits<iterator>::iterator_category,
      decltype(*std::declval<iterator &>())>>
      : std::bool_constant<
          is_byte_input_iterator<iterator>::value &&
          std::is_base_of_v<
            std::forward_iterator_tag,
            typename std::iterator_traits<iterator>::iterator_category> &&
          std::is_lvalue_reference_v<decltype(*std::declval<iterator &>())> &&
          !std::is_const_v<std::remove_reference_t<decltype(*std::declval<iterator &>())>> &&
          std::is_assignable_v<
            decltype(*std::declval<iterator &>()),
            typename std::iterator_traits<iterator>::value_type>> {};
} // namespace desfire::detail

#endif // desfire_desfire_buffer_buffer_traits_hpp
