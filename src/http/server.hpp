#pragma once

#include "../application/command_service.hpp"
#include "request_guard.hpp"
#include "static_assets.hpp"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <httplib.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>

namespace desfire_console {
  class http_server final {

  public:

    http_server(
      std::uint16_t port,
      const std::filesystem::path &assets,
      nlohmann::json catalog
    );
    ~http_server();
    http_server(const http_server &) = delete;
    http_server &operator=(const http_server &) = delete;
    bool run();
    bool running() const;
    void stop() noexcept;
    const std::string &origin() const noexcept;

  private:

    void get(
      const httplib::Request &request,
      httplib::Response &response
    );
    void command(
      const httplib::Request &request,
      httplib::Response &response,
      const httplib::ContentReader &reader
    );
    std::unique_lock<std::mutex> command_slot();

    // All access to the persistent service, including snapshots, holds this slot.
    // try_lock is the only acquisition mode: operations are never queued here.
    std::mutex command_mutex_;
    command_service service_;
    request_guard guard_;
    static_assets assets_;
    nlohmann::json commands_;
    httplib::Server server_;
    std::atomic<bool> stop_requested_{false};
  };
}
