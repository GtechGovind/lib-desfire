/// @file
/// @brief Convert between the core's native frames and short ISO 7816 wrapped APDUs.

#ifndef desfire_console_apdu_codec_hpp
#define desfire_console_apdu_codec_hpp

#include <desfire/buffer/byte_view.hpp>
#include <desfire/common/result.hpp>

namespace desfire_console {

  /// Wrap one opcode and at most 255 data bytes; an empty request is invalid.
  desfire::result<desfire::bytes> wrap_command(
    const std::uint8_t *request,
    std::size_t size
  );

  /// Require SW1=0x91 and move SW2 before the payload, preserving native rejection statuses.
  /// A malformed reply has unknown delivery because a command was already transmitted.
  desfire::result<desfire::bytes> unwrap_response(const desfire::bytes &response);

} // namespace desfire_console

#endif
