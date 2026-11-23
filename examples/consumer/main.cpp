// An installed-package smoke check. No reader, credentials or card I/O.
#include <desfire.hpp>
#include <iostream>

int main() {
  int exchanges = 0;
  desfire::card card{[&exchanges](const std::uint8_t *, std::size_t, desfire::deadline) {
    ++exchanges;
    return desfire::result<desfire::bytes>::failure(
      {desfire::error_code::transport_error, desfire::delivery_outcome::not_sent});
  }};
  if (exchanges != 0) {
    return 1; // Construction must not touch the transport.
  }
  const auto invalid = card.select_application(0x01000000U);
  if (invalid || exchanges != 0 ||
      invalid.get_error().code != desfire::error_code::invalid_argument ||
      invalid.get_error().outcome != desfire::delivery_outcome::not_sent) {
    return 2; // An AID beyond 24 bits must fail before transport I/O.
  }
  const auto version = card.get_version();
  if (version || exchanges != 1 ||
      version.get_error().code != desfire::error_code::transport_error ||
      version.get_error().outcome != desfire::delivery_outcome::not_sent) {
    return 3; // The caller's failure must survive without an automatic retry.
  }
  std::cout << "Installed package and offline transport checks passed.\n";
}
