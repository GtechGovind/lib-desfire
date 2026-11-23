/// @file
/// @brief Short APDU conversion, independent of PC/SC handles and card state.

#include "apdu_codec.hpp"

namespace desfire_console {

  /// Use ISO case 2 for opcode-only commands and case 4 when native data are present.
  desfire::result<desfire::bytes> wrap_command(
    const std::uint8_t *request,
    std::size_t size
  ) {
    if (!request || size == 0 || size > 256) {
      return desfire::result<desfire::bytes>::failure({desfire::error_code::invalid_argument});
    }
    desfire::bytes command{0x90, request[0], 0, 0};
    if (size > 1) {
      command.push_back(static_cast<std::uint8_t>(size - 1));
      command.insert(command.end(), request + 1, request + size);
    }
    command.push_back(0); // Maximum short response length (Le=256).
    return desfire::result<desfire::bytes>::success(std::move(command));
  }

  /// Do not reinterpret ISO errors (including 9000) as native DESFire successes.
  desfire::result<desfire::bytes> unwrap_response(const desfire::bytes &response) {
    if (response.size() < 2) {
      return desfire::result<desfire::bytes>::failure(
        {desfire::error_code::malformed_response, desfire::delivery_outcome::unknown}
      );
    }
    if (response[response.size() - 2] != 0x91) {
      return desfire::result<desfire::bytes>::failure(
        {desfire::error_code::malformed_response,
         desfire::delivery_outcome::unknown,
         {},
         {},
         static_cast<std::uint16_t>((response[response.size() - 2] << 8) | response.back())}
      );
    }
    desfire::bytes native{response.back()};
    native.insert(native.end(), response.begin(), response.end() - 2);
    return desfire::result<desfire::bytes>::success(std::move(native));
  }

} // namespace desfire_console
