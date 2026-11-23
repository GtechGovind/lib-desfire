#include "server.hpp"

#include <cstddef>
#include <exception>
#include <openssl/crypto.h>
#include <stdexcept>
#include <string>
#include <utility>

namespace desfire_console {
  namespace {
    struct request_body {
      std::string value;

      ~request_body() {
        if (!value.empty()) {
          OPENSSL_cleanse(value.data(), value.size());
        }
      }
    };

    struct request_payload {
      nlohmann::json value;

      ~request_payload() { erase_request_strings(value); }
    };

    int command_status(const nlohmann::json &envelope) {
      if (
        envelope.value("ok", false) || !envelope.contains("error") || !envelope["error"].is_object()
      ) {
        return 200;
      }
      const auto code = envelope["error"].value("code", std::string{});
      if (code == "stale_session") {
        return 409;
      }
      return code == "invalid_arguments" || code == "confirmation_required" ? 400 : 200;
    }

    void internal_error(httplib::Response &response) {
      error_response(
        response,
        request_error(500, "internal_error", "The console could not process this request.")
      );
    }

    const char *response_delivery(const nlohmann::json &envelope) {
      const auto ok = envelope.find("ok");
      if (ok != envelope.end() && ok->is_boolean() && ok->get<bool>()) {
        return "succeeded";
      }
      const auto error = envelope.find("error");
      if (error != envelope.end() && error->is_object()) {
        const auto delivery = error->find("delivery");
        if (delivery != error->end() && delivery->is_string()) {
          const auto &value = delivery->get_ref<const std::string &>();
          if (value == "succeeded") {
            return "succeeded";
          }
          if (value == "rejected") {
            return "rejected";
          }
        }
      }
      return "unknown";
    }

    void command_response_failure(
      httplib::Response &response,
      const char *delivery,
      nlohmann::json *envelope = nullptr
    ) {
      constexpr const char *message =
        "The command response could not be delivered. Check the card before another command.";
      try {
        nlohmann::json failure{
          {"ok", false},
          {"result", nullptr},
          {"error",
           {{"code", "response_unavailable"}, {"message", message}, {"delivery", delivery}}}
        };
        if (envelope != nullptr && envelope->contains("state")) {
          failure["state"] = std::move((*envelope)["state"]);
        }
        json_response(response, 500, failure);
        return;
      } catch (...) {
        // A serialization/allocation error after execution must not erase the
        // delivery boundary. This bounded literal needs no result/state copy.
      }
      const char *fallback =
        R"({"ok":false,"result":null,"error":{"code":"response_unavailable","message":"The command response could not be delivered. Check the card before another command.","delivery":"unknown"}})";
      if (std::string_view(delivery) == "succeeded") {
        fallback =
          R"({"ok":false,"result":null,"error":{"code":"response_unavailable","message":"The command succeeded but its response could not be delivered. Check the card before another command.","delivery":"succeeded"}})";
      } else if (std::string_view(delivery) == "rejected") {
        fallback =
          R"({"ok":false,"result":null,"error":{"code":"response_unavailable","message":"The command was rejected but its response could not be delivered.","delivery":"rejected"}})";
      }
      response.status = 500;
      response.headers.erase("Content-Type");
      response.set_content(fallback, "application/json; charset=utf-8");
      security_headers(response);
    }
  }

  http_server::http_server(
    std::uint16_t port,
    const std::filesystem::path &assets,
    nlohmann::json catalog
  )
      : service_(catalog),
        guard_(port),
        assets_(assets),
        commands_(catalog.at("commands")) {
    // Four network workers and four pending connections bound HTTP resource use.
    // Card operations themselves always use the separate nonwaiting service slot.
    server_.new_task_queue = [] {
      return new httplib::ThreadPool(4, 4, 4);
    };
    server_.set_address_family(AF_INET);
    server_.set_payload_max_length(maximum_request_body);
    server_.set_read_timeout(10);
    server_.set_write_timeout(10);
    server_.set_keep_alive_max_count(1);
    server_.set_keep_alive_timeout(1);
    server_.set_idle_interval(0, 100000);
    server_.set_socket_options([](socket_t socket) {
#ifdef _WIN32
      // Windows SO_REUSEADDR would allow a second listener to steal connections.
      const int exclusive = 1;
      if (
        setsockopt(
          socket,
          SOL_SOCKET,
          SO_EXCLUSIVEADDRUSE,
          reinterpret_cast<const char *>(&exclusive),
          sizeof(exclusive)
        ) != 0
      ) {
        throw std::runtime_error("The loopback socket could not be secured.");
      }
#else
      (void)socket;
#endif
    });
    httplib::Response defaults;
    security_headers(defaults);
    server_.set_default_headers(defaults.headers);
    server_.set_pre_routing_handler([this](
                                      const httplib::Request &request, httplib::Response &response
                                    ) {
      try {
        guard_.validate_source(request);
        if (request.has_header("Expect")) {
          throw request_error(417, "invalid_headers", "Expect request headers are not supported.");
        }
        if (request.method == "POST") {
          guard_.authorize(request, true);
          if (request.path != "/api/command") {
            throw request_error(404, "not_found", "Route not found.");
          }
          guard_.command_body_size(request);
        }
        return httplib::Server::HandlerResponse::Unhandled;
      } catch (const request_error &error) {
        error_response(response, error);
        return httplib::Server::HandlerResponse::Handled;
      }
    });
    server_.set_expect_100_continue_handler([](
                                              const httplib::Request &, httplib::Response &response
                                            ) {
      error_response(
        response, request_error(417, "invalid_headers", "Expect request headers are not supported.")
      );
      return 417;
    });
    server_.set_post_routing_handler([](const httplib::Request &, httplib::Response &response) {
      security_headers(response);
    });
    server_.set_exception_handler(
      [](
        const httplib::Request &request, httplib::Response &response, std::exception_ptr exception
      ) {
        try {
          std::rethrow_exception(exception);
        } catch (const request_error &error) {
          error_response(response, error);
        } catch (...) {
          // Never expose exception text, command arguments or request details.
          if (request.method == "POST" && request.path == "/api/command") {
            command_response_failure(response, "unknown");
          } else {
            internal_error(response);
          }
        }
      }
    );
    server_.set_error_handler([](const httplib::Request &, httplib::Response &response) {
      if (response.body.empty()) {
        if (response.status == 413) {
          error_response(
            response, request_error(413, "body_too_large", "The request body exceeds 64 KiB.")
          );
        } else if (response.status == 404) {
          error_response(response, request_error(404, "not_found", "Route not found."));
        } else {
          const int status = response.status >= 400 ? response.status : 400;
          error_response(response, request_error(status, "http_error", "Invalid HTTP request."));
        }
      }
      security_headers(response);
    });
    server_.Get(R"(/.*)", [this](const httplib::Request &request, httplib::Response &response) {
      get(request, response);
    });
    server_.Post(
      "/api/command",
      [this](
        const httplib::Request &request,
        httplib::Response &response,
        const httplib::ContentReader &reader
      ) {
        command(request, response, reader);
      }
    );
    // Deliberately install no access/error logger: URLs, JSON and key data must
    // never be written to the process's output streams by the HTTP adapter.
    if (!server_.bind_to_port("127.0.0.1", static_cast<int>(port))) {
      throw std::runtime_error("The loopback port could not be opened.");
    }
  }

  http_server::~http_server() {
    stop();
  }

  bool http_server::run() {
    return server_.listen_after_bind();
  }

  bool http_server::running() const {
    return server_.is_running();
  }

  void http_server::stop() noexcept {
    if (!stop_requested_.exchange(true)) {
      server_.stop();
    }
  }

  const std::string &http_server::origin() const noexcept {
    return guard_.origin();
  }

  std::unique_lock<std::mutex> http_server::command_slot() {
    std::unique_lock<std::mutex> slot(command_mutex_, std::try_to_lock);
    if (!slot.owns_lock()) {
      throw request_error(409, "busy", "Another command is running. No command was queued.");
    }
    return slot;
  }

  void http_server::get(
    const httplib::Request &request,
    httplib::Response &response
  ) {
    if (request.path == "/api/bootstrap") {
      const auto slot = command_slot();
      json_response(
        response,
        200,
        {{"token", guard_.token()},
         {"commands", commands_},
         {"state", service_.state()},
         {"credentials", service_.credentials()}}
      );
    } else if (request.path == "/api/commands") {
      guard_.authorize(request, false);
      json_response(response, 200, {{"commands", commands_}});
    } else if (request.path == "/api/state") {
      guard_.authorize(request, false);
      const auto slot = command_slot();
      json_response(
        response,
        200,
        {{"ok", true}, {"result", nlohmann::json::object()}, {"state", service_.state()}}
      );
    } else if (!assets_.serve(request.path, response)) {
      throw request_error(404, "not_found", "Route not found.");
    }
  }

  void http_server::command(
    const httplib::Request &request,
    httplib::Response &response,
    const httplib::ContentReader &reader
  ) {
    const auto expected = guard_.command_body_size(request);
    request_body body;
    body.value.reserve(expected);
    const bool complete = reader([&body, expected](const char *data, std::size_t size) {
      if (size > expected - body.value.size()) {
        return false;
      }
      body.value.append(data, size);
      return true;
    });
    if (!complete || body.value.size() != expected) {
      throw request_error(400, "invalid_body", "The request body was incomplete.");
    }
    request_payload payload{parse_request_json(body.value)};
    const auto slot = command_slot();
    auto envelope = service_.execute(payload.value);
    try {
      json_response(response, command_status(envelope), envelope);
    } catch (...) {
      command_response_failure(response, response_delivery(envelope), &envelope);
    }
  }
}
