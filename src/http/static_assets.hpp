#pragma once

#include <filesystem>
#include <httplib.h>
#include <map>
#include <string>

namespace desfire_console {
  // Immutable startup snapshot: request URLs never become filesystem paths.
  class static_assets final {

  public:

    explicit static_assets(const std::filesystem::path &directory);
    bool serve(
      const std::string &route,
      httplib::Response &response
    ) const;

  private:

    struct asset {
      std::string body;
      std::string content_type;
    };

    std::map<std::string, asset> routes_;
  };
}
