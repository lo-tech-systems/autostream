// =============================================================================
// autostream_monitor.cpp
//
// Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
//
// Top-level translation unit: ControlServer, AudioMonitor, and main().
// See autostream_monitor.h for the full design description.
//
// Build:
//   g++ -std=c++17 -O2 -o autostream_monitor \
//       autostream_monitor.cpp \
//       autostream_monitor_dsp.cpp \
//       autostream_monitor_io.cpp \
//       autostream_monitor_utils.cpp \
//       -lasound -lsamplerate -lpthread
// =============================================================================

#include "autostream_monitor.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <optional>
#include <sstream>
#include <iomanip>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>


// =============================================================================
// Global shutdown flag
//
// Set by the signal handler; the AudioMonitor::run() loop checks it.
//
// Declared volatile sig_atomic_t rather than std::atomic<bool> because POSIX
// only guarantees that volatile sig_atomic_t accesses are async-signal-safe.
// std::atomic<bool>::store() is not listed as async-signal-safe, so using it
// from a signal handler is technically undefined behaviour even though it
// compiles to a single instruction on common architectures.
// =============================================================================

static volatile sig_atomic_t g_shutdown_requested = 0;

static void signal_handler(int /*signum*/)
{
    g_shutdown_requested = 1;
}


// =============================================================================
// Minimal JSON helpers
//
// These are intentionally simple string-search functions rather than a full
// parser.  The commands we receive are small and well-defined, so a full
// JSON library would be overkill.  These functions search for "key":value
// patterns and are not designed for deeply nested or unusual JSON.
// =============================================================================

// Return the string value for a given key, or "" if not found.
// Handles "key":"value" patterns.  Correctly skips over \" escape sequences
// inside the value so that device names or paths containing a double-quote
// do not truncate the result.
static std::string json_get_string(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\"";
    auto key_pos = json.find(search);
    if (key_pos == std::string::npos)
        return "";

    auto colon_pos = json.find(':', key_pos + search.size());
    if (colon_pos == std::string::npos)
        return "";

    auto quote_start = json.find('"', colon_pos + 1);
    if (quote_start == std::string::npos)
        return "";

    // Scan forward from quote_start+1, treating \" as a literal character
    // and stopping at an unescaped closing quote.
    std::string value;
    size_t i = quote_start + 1;
    while (i < json.size())
    {
        char c = json[i];
        if (c == '\\' && i + 1 < json.size())
        {
            // Consume the escape sequence and include the escaped character.
            char next = json[i + 1];
            if      (next == '"')  { value += '"';  }
            else if (next == '\\') { value += '\\'; }
            else if (next == 'n')  { value += '\n'; }
            else if (next == 't')  { value += '\t'; }
            else                   { value += next; }  // pass others through
            i += 2;
        }
        else if (c == '"')
        {
            // Unescaped closing quote — end of string.
            break;
        }
        else
        {
            value += c;
            ++i;
        }
    }

    return value;
}

// Return the integer value for a given key, or default_val if not found.
// Handles "key":integer patterns.
static int json_get_int(const std::string& json, const std::string& key, int default_val = 0)
{
    std::string search = "\"" + key + "\"";
    auto key_pos = json.find(search);
    if (key_pos == std::string::npos)
        return default_val;

    auto colon_pos = json.find(':', key_pos + search.size());
    if (colon_pos == std::string::npos)
        return default_val;

    // Skip whitespace after colon
    size_t val_pos = colon_pos + 1;
    while (val_pos < json.size() && (json[val_pos] == ' ' || json[val_pos] == '\t'))
        val_pos++;

    try
    {
        return std::stoi(json.substr(val_pos));
    }
    catch (...)
    {
        return default_val;
    }
}

// Return the float value for a given key, or default_val if not found.
static float json_get_float(const std::string& json, const std::string& key, float default_val = 0.0f)
{
    std::string search = "\"" + key + "\"";
    auto key_pos = json.find(search);
    if (key_pos == std::string::npos)
        return default_val;

    auto colon_pos = json.find(':', key_pos + search.size());
    if (colon_pos == std::string::npos)
        return default_val;

    size_t val_pos = colon_pos + 1;
    while (val_pos < json.size() && (json[val_pos] == ' ' || json[val_pos] == '\t'))
        val_pos++;

    try
    {
        return std::stof(json.substr(val_pos));
    }
    catch (...)
    {
        return default_val;
    }
}

// Return the boolean value for a given key, or default_val if not found.
// Matches "key":true or "key":false.
static bool json_get_bool(const std::string& json, const std::string& key, bool default_val = false)
{
    std::string search = "\"" + key + "\"";
    auto key_pos = json.find(search);
    if (key_pos == std::string::npos)
        return default_val;

    auto colon_pos = json.find(':', key_pos + search.size());
    if (colon_pos == std::string::npos)
        return default_val;

    size_t val_pos = colon_pos + 1;
    while (val_pos < json.size() && (json[val_pos] == ' ' || json[val_pos] == '\t'))
        val_pos++;

    if (json.substr(val_pos, 4) == "true")
        return true;
    if (json.substr(val_pos, 5) == "false")
        return false;

    return default_val;
}

// Extract the content of a JSON array for a given key.
// Returns everything between the [ and ] brackets, or "" if not found.
static std::string json_get_array_content(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\"";
    auto key_pos = json.find(search);
    if (key_pos == std::string::npos)
        return "";

    auto bracket_pos = json.find('[', key_pos + search.size());
    if (bracket_pos == std::string::npos)
        return "";

    int depth = 0;
    for (size_t i = bracket_pos; i < json.size(); ++i)
    {
        if (json[i] == '[') depth++;
        if (json[i] == ']') depth--;
        if (depth == 0)
            return json.substr(bracket_pos + 1, i - bracket_pos - 1);
    }
    return "";
}

// Split a JSON array content string into individual "{...}" object strings.
static std::vector<std::string> json_split_objects(const std::string& array_content)
{
    std::vector<std::string> objects;
    int    depth = 0;
    size_t start = std::string::npos;

    for (size_t i = 0; i < array_content.size(); ++i)
    {
        if (array_content[i] == '{')
        {
            if (depth == 0)
                start = i;
            depth++;
        }
        else if (array_content[i] == '}')
        {
            depth--;
            if (depth == 0 && start != std::string::npos)
            {
                objects.push_back(array_content.substr(start, i - start + 1));
                start = std::string::npos;
            }
        }
    }
    return objects;
}

// Convert an EqBand type string to the enum value.
// Returns std::nullopt for unrecognised strings so callers can reject them
// rather than silently treating them as Peak.
static std::optional<EqBand::Type> parse_eq_band_type(const std::string& type_str)
{
    if (type_str == "peak")       return EqBand::Type::Peak;
    if (type_str == "low_shelf")  return EqBand::Type::LowShelf;
    if (type_str == "high_shelf") return EqBand::Type::HighShelf;
    if (type_str == "low_pass")   return EqBand::Type::LowPass;
    if (type_str == "high_pass")  return EqBand::Type::HighPass;
    return std::nullopt;
}

// Parse the "bands" array from a set_eq command.
// Returns std::nullopt if any band contains an unrecognised type string.
static std::optional<std::vector<EqBand>> parse_eq_bands(const std::string& json)
{
    std::vector<EqBand> bands;

    std::string array_content = json_get_array_content(json, "bands");
    if (array_content.empty())
        return bands;

    std::vector<std::string> band_objects = json_split_objects(array_content);

    for (const auto& obj : band_objects)
    {
        auto type = parse_eq_band_type(json_get_string(obj, "type"));
        if (!type)
            return std::nullopt;

        EqBand band;
        band.type    = *type;
        band.freq_hz = json_get_float(obj, "freq_hz", 1000.0f);
        band.gain_db = json_get_float(obj, "gain_db", 0.0f);
        band.q       = json_get_float(obj, "q", 0.707f);
        bands.push_back(band);
    }

    return bands;
}

// Escape a string for safe inclusion in a JSON value (RFC 8259 §7).
// All characters in U+0000..U+001F must be escaped; backslash and double-quote
// must also be escaped.  Named escapes are used where the spec defines them;
// remaining control characters use the \uXXXX form.
// This matters in practice because ALSA device descriptions come from kernel
// driver strings that may contain unexpected whitespace or control characters.
static std::string json_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        default:
            if (c < 0x20)
            {
                // Remaining control characters: use \uXXXX form.
                char buf[7];
                snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                out += buf;
            }
            else
            {
                out += static_cast<char>(c);
            }
            break;
        }
    }
    return out;
}

// Extract a string key from the top-level JSON object only.
// The search is restricted to the content before the first '[' character, so
// that keys inside nested arrays (e.g. the "type" fields inside "bands" objects
// in a set_eq command) cannot shadow top-level fields regardless of key order.
static std::string json_get_top_level_string(const std::string& json,
                                              const std::string& key)
{
    size_t limit = json.find('[');
    if (limit == std::string::npos)
        return json_get_string(json, key);
    return json_get_string(json.substr(0, limit), key);
}


// =============================================================================
// ControlServer
// =============================================================================

ControlServer::ControlServer(AudioMonitor& monitor)
    : _monitor(monitor)
{
}

ControlServer::~ControlServer()
{
    stop();
}

bool ControlServer::start(const std::string& socket_path)
{
    // Validate that the path fits in sockaddr_un.sun_path before we truncate it.
    // On Linux, sun_path is 108 bytes including the null terminator.
    struct sockaddr_un addr_check;
    if (socket_path.size() >= sizeof(addr_check.sun_path))
    {
        LOG_WARN("[control] Socket path too long (max %zu chars): '%s'",
                 sizeof(addr_check.sun_path) - 1, socket_path.c_str());
        return false;
    }

    _socket_path = socket_path;

    // Remove a stale socket file from a previous run, but only if the path
    // is actually a socket.  Blindly unlinking any file at the configured
    // path would silently delete unrelated files on misconfiguration.
    {
        struct stat st;
        if (stat(socket_path.c_str(), &st) == 0)
        {
            if (S_ISSOCK(st.st_mode))
                unlink(socket_path.c_str());
            else
                LOG_WARN("[control] Path '%s' exists but is not a socket; not removing",
                         socket_path.c_str());
        }
    }

    _server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_server_fd < 0)
    {
        LOG_WARN("[control] socket() failed: %s", strerror(errno));
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(_server_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        LOG_WARN("[control] bind() on '%s' failed: %s",
                 socket_path.c_str(), strerror(errno));
        ::close(_server_fd);
        _server_fd = -1;
        return false;
    }

    if (listen(_server_fd, /*backlog=*/4) < 0)
    {
        LOG_WARN("[control] listen() failed: %s", strerror(errno));
        ::close(_server_fd);
        _server_fd = -1;
        return false;
    }

    _running.store(true);
    _accept_thread = std::thread(&ControlServer::accept_loop, this);

    LOG_INFO("[control] Listening on '%s'", socket_path.c_str());
    return true;
}

void ControlServer::stop()
{
    if (!_running.exchange(false))
        return;

    // Step 1 — Unblock accept().
    // Closing the server socket causes any pending accept() call to return -1.
    if (_server_fd >= 0)
    {
        ::close(_server_fd);
        _server_fd = -1;
    }

    // Step 2 — Unblock all connected clients. shutdown(SHUT_RDWR) causes
    // recv() / send() to return immediately without transferring fd ownership.
    // Each worker thread still owns its fd lifetime and closes it after
    // handle_client() returns, so there is no double-close hazard here.
    {
        std::lock_guard<std::mutex> lock(_clients_mutex);
        for (int fd : _client_fds)
            shutdown(fd, SHUT_RDWR);
    }

    if (_accept_thread.joinable())
        _accept_thread.join();

    for (std::thread& t : _client_threads)
    {
        if (t.joinable())
            t.join();
    }
    _client_threads.clear();

    unlink(_socket_path.c_str());
}

void ControlServer::accept_loop()
{
    while (_running.load())
    {
        int client_fd = accept(_server_fd, nullptr, nullptr);

        if (client_fd < 0)
        {
            if (_running.load())
                LOG_WARN("[control] accept() failed: %s", strerror(errno));
            break;
        }

        // Impose receive and send timeouts so a misbehaving client (one that
        // stops reading responses) cannot wedge the server indefinitely.
        // recv() / send() will return -1 with errno EAGAIN/EWOULDBLOCK after
        // CLIENT_TIMEOUT_SECONDS seconds of blocking.
        struct timeval tv;
        tv.tv_sec  = CLIENT_TIMEOUT_SECONDS;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        {
            std::lock_guard<std::mutex> lock(_clients_mutex);
            _client_fds.insert(client_fd);
        }

        // _client_threads is only accessed from this thread (accept_loop) and
        // from stop() after _accept_thread.join(), so no mutex is needed here.
        _client_threads.emplace_back([this, client_fd]()
        {
            LOG_DEBUG("[control] Client connected (fd=%d)", client_fd);
            handle_client(client_fd);
            LOG_DEBUG("[control] Client disconnected (fd=%d)", client_fd);

            {
                std::lock_guard<std::mutex> lock(_clients_mutex);
                _client_fds.erase(client_fd);
            }
            ::close(client_fd);
        });
    }
}

void ControlServer::handle_client(int client_fd)
{
    // Read newline-delimited commands from the client.
    std::string line_buf;

    // Binary payload for get_id_snapshot responses.  Allocated here once and
    // reused across commands to avoid repeated heap allocations.
    std::vector<int16_t> snapshot_data;

    // Per-command deadline: the wall-clock time by which the current
    // newline-terminated command must be fully received.  This defeats
    // byte-trickling attacks where a client sends one byte every
    // (CLIENT_TIMEOUT_SECONDS - 1) seconds to keep recv() returning
    // before SO_RCVTIMEO fires, monopolising the connection indefinitely.
    // Reset to "no deadline" (0.0) when no command is in progress.
    double command_deadline = 0.0;

    // Read-ahead buffer: recv() fills this in chunks rather than one byte at a
    // time, eliminating per-character system-call overhead.  Characters are
    // consumed one at a time from the buffer so all command-processing logic
    // below remains unchanged.
    static constexpr size_t RECV_BUF_SIZE = 4096;
    char   recv_buf[RECV_BUF_SIZE];
    size_t recv_buf_len = 0;   // bytes currently available in recv_buf
    size_t recv_buf_pos = 0;   // index of the next byte to consume

    while (_running.load())
    {
        // Enforce the per-command deadline before blocking on recv().
        // SO_RCVTIMEO ensures recv() returns within CLIENT_TIMEOUT_SECONDS
        // even if the client goes silent, so the deadline check runs at
        // least that often.
        if (command_deadline > 0.0 && get_monotonic_time() > command_deadline)
        {
            LOG_WARN("[control] Command deadline exceeded; disconnecting");
            break;
        }

        // Refill the read-ahead buffer when empty.
        if (recv_buf_pos == recv_buf_len)
        {
            ssize_t n = recv(client_fd, recv_buf, RECV_BUF_SIZE, 0);
            if (n == 0)
            {
                // Clean EOF — client closed the connection.
                break;
            }
            if (n < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    LOG_WARN("[control] Client timed out after %d s of inactivity",
                             CLIENT_TIMEOUT_SECONDS);
                // Timeout, shutdown() interrupt, or read error — stop serving.
                break;
            }
            recv_buf_len = static_cast<size_t>(n);
            recv_buf_pos = 0;
        }

        // Consume one character from the buffer — identical logic to before.
        char ch = recv_buf[recv_buf_pos++];

        if (ch == '\n')
        {
            command_deadline = 0.0;  // command received; cancel the deadline

            // We have a complete command line.
            if (!line_buf.empty())
            {
                snapshot_data.clear();
                std::string response = dispatch_command(line_buf, &snapshot_data);
                // Ensure the response ends with a newline.
                if (response.empty() || response.back() != '\n')
                    response += '\n';

                // Loop until all bytes are sent.  A single send() call may
                // write fewer bytes than requested if the socket buffer is full.
                const char* resp_ptr  = response.c_str();
                size_t      resp_left = response.size();
                while (resp_left > 0)
                {
                    // MSG_NOSIGNAL prevents SIGPIPE if the client disconnects
                    // mid-send (SIGPIPE is also ignored globally, but this is
                    // cleaner for socket writes).
                    ssize_t sent = send(client_fd, resp_ptr, resp_left, MSG_NOSIGNAL);
                    if (sent <= 0)
                        break;
                    resp_ptr  += sent;
                    resp_left -= static_cast<size_t>(sent);
                }

                // If the send loop did not deliver all bytes (SO_SNDTIMEO fired
                // or the client closed), the client is unresponsive.  Disconnect
                // rather than continuing to read further commands.
                if (resp_left > 0)
                {
                    LOG_WARN("[control] Send incomplete; disconnecting unresponsive client");
                    break;
                }

                // For get_id_snapshot, send the raw binary payload immediately
                // after the JSON ack line.  The client must read exactly
                // frames*2 bytes (as declared in the "frames" field of the ack).
                if (!snapshot_data.empty())
                {
                    const char* bin_ptr  = reinterpret_cast<const char*>(snapshot_data.data());
                    size_t      bin_left = snapshot_data.size() * sizeof(int16_t);
                    while (bin_left > 0)
                    {
                        ssize_t sent = send(client_fd, bin_ptr, bin_left, MSG_NOSIGNAL);
                        if (sent <= 0)
                            break;
                        bin_ptr  += sent;
                        bin_left -= static_cast<size_t>(sent);
                    }

                    if (bin_left > 0)
                    {
                        LOG_WARN("[control] Binary send incomplete; disconnecting unresponsive client");
                        break;
                    }
                }
            }
            line_buf.clear();
        }
        else
        {
            // First byte of a new command: start the deadline clock.
            if (line_buf.empty())
                command_deadline = get_monotonic_time() + CLIENT_TIMEOUT_SECONDS;

            line_buf += ch;

            // Guard against unexpectedly large command strings.
            if (line_buf.size() > 65536)
            {
                LOG_WARN("[control] Command too long; dropping");
                line_buf.clear();
                command_deadline = 0.0;
            }
        }
    }
}

std::string ControlServer::dispatch_command(const std::string& json_command,
                                             std::vector<int16_t>* snapshot_out)
{
    std::string type = json_get_top_level_string(json_command, "type");
    LOG_SPAM("[control] Dispatching command type='%s'",
             type.empty() ? "<unknown>" : type.c_str());

    if (type == "get_status")
    {
        return _monitor.api_get_status();
    }
    else if (type == "get_id_snapshot")
    {
        int idx         = json_get_int(json_command, "input", 0);
        int max_seconds = json_get_int(json_command, "max_seconds", 20);
        return _monitor.api_get_id_snapshot(idx, max_seconds, snapshot_out);
    }
    else if (type == "list_devices")
    {
        return _monitor.api_list_devices();
    }
    else if (type == "configure_input")
    {
        int idx = json_get_int(json_command, "input", 0);
        InputConfig cfg;
        cfg.alsa_device             = json_get_string(json_command, "device");
        cfg.silence_threshold_dbfs  = json_get_float(json_command, "silence_threshold_dbfs", -66.0f);
        cfg.silence_seconds         = json_get_int(json_command, "silence_seconds", 30);
        return _monitor.api_configure_input(idx, cfg);
    }
    else if (type == "set_fifo")
    {
        std::string path = json_get_string(json_command, "path");
        return _monitor.api_set_fifo(path);
    }
    else if (type == "start_input")
    {
        int idx = json_get_int(json_command, "input", 0);
        return _monitor.api_start_input(idx);
    }
    else if (type == "stop_input")
    {
        int idx = json_get_int(json_command, "input", 0);
        return _monitor.api_stop_input(idx);
    }
    else if (type == "set_allow_capture")
    {
        int  idx   = json_get_int(json_command, "input", 0);
        bool allow = json_get_bool(json_command, "allow", false);
        return _monitor.api_set_allow_capture(idx, allow);
    }
    else if (type == "set_eq")
    {
        int  idx   = json_get_int(json_command, "input", 0);
        auto bands = parse_eq_bands(json_command);
        if (!bands)
        {
            LOG_WARN("[control] set_eq rejected: unknown EQ band type");
            return "{\"type\":\"ack\",\"command\":\"set_eq\","
                   "\"ok\":false,\"error\":\"unknown EQ band type\"}";
        }
        return _monitor.api_set_eq(idx, *bands);
    }
    else if (type == "set_output_eq")
    {
        auto bands = parse_eq_bands(json_command);
        if (!bands)
        {
            LOG_WARN("[control] set_output_eq rejected: unknown EQ band type");
            return "{\"type\":\"ack\",\"command\":\"set_output_eq\","
                   "\"ok\":false,\"error\":\"unknown EQ band type\"}";
        }
        return _monitor.api_set_output_eq(*bands);
    }
    else if (type == "set_gain")
    {
        int   idx     = json_get_int(json_command, "input", 0);
        float gain_db = json_get_float(json_command, "gain_db", 0.0f);
        return _monitor.api_set_gain(idx, gain_db);
    }
    else if (type == "set_output_gain")
    {
        float gain_db = json_get_float(json_command, "gain_db", 0.0f);
        return _monitor.api_set_output_gain(gain_db);
    }
    else if (type == "set_output_auto_trim")
    {
        bool enabled = json_get_bool(json_command, "enabled", false);
        return _monitor.api_set_output_auto_trim(enabled);
    }
    else if (type == "set_log_level")
    {
        std::string level_text = json_get_string(json_command, "level");
        return _monitor.api_set_log_level(level_text);
    }
    else if (type == "start_output_dump")
    {
        std::string path = json_get_string(json_command, "path");
        bool overwrite   = json_get_bool(json_command, "overwrite", false);
        return _monitor.api_start_output_dump(path, overwrite);
    }
    else if (type == "stop_output_dump")
    {
        return _monitor.api_stop_output_dump();
    }
    else
    {
        std::string escaped = json_escape(type.empty() ? json_command : type);
        LOG_WARN("[control] Unknown command received: %s",
                 type.empty() ? "<unparseable>" : type.c_str());
        return "{\"type\":\"ack\",\"command\":\"unknown\","
               "\"ok\":false,\"error\":\"unknown command: " + escaped + "\"}";
    }
}


// =============================================================================
// AudioMonitor
// =============================================================================

AudioMonitor::AudioMonitor(const std::string& socket_path)
    : _socket_path(socket_path)
    , _control_server(*this)
{
    // Create the two InputChannel objects.  They are not started here;
    // that happens only when api_start_input() is called.
    for (int i = 0; i < NUM_INPUTS; ++i)
    {
        _inputs[i] = std::make_unique<InputChannel>(
            i + 1,             // 1-based index
            _fifo_writer,
            _fifo_mutex,
            _output_processor,
            _dump_writer
        );
    }
}

AudioMonitor::~AudioMonitor()
{
    stop();
}

void AudioMonitor::run()
{
    _running.store(true);

    if (!_control_server.start(_socket_path))
    {
        LOG_WARN("[monitor] Failed to start control server; exiting");
        return;
    }

    LOG_INFO("[monitor] Ready on socket '%s'", _socket_path.c_str());

    // Main loop: poll for shutdown and auto-restart crashed inputs.
    while (_running.load() && !g_shutdown_requested)
    {
        // Sleep up to 100 ms, but wake immediately if stop() is called.
        {
            std::unique_lock<std::mutex> lk(_run_cv_mutex);
            _run_cv.wait_for(lk, std::chrono::milliseconds(100),
                [this]() { return !_running.load() || g_shutdown_requested != 0; });
        }

        // Auto-recover any input whose capture thread self-stopped after an
        // unrecoverable ALSA error (is_started=true, is_running=false).
        // A 5-second back-off is applied after each failed restart attempt to
        // avoid a tight retry loop while a USB device is absent.
        //
        // Note: api_start_input() and api_stop_input() also mutate channel
        // state from the control-server thread.  The atomic _started flag in
        // InputChannel::stop()/_started.exchange(false)) prevents double-stop,
        // and the is_started() guard in api_start_input() prevents double-start.
        // The residual TOCTOU window between the watchdog's stop() and start()
        // calls is acceptable for this trusted single-client deployment.
        double now = get_monotonic_time();
        for (int i = 0; i < NUM_INPUTS; ++i)
        {
            if (!_inputs[i])
                continue;
            if (!_inputs[i]->is_started() || _inputs[i]->is_running())
                continue;
            if (now < _restart_after[i])
                continue;

            LOG_WARN("[monitor] Input %d stopped unexpectedly; attempting auto-restart",
                     i + 1);
            _inputs[i]->stop();   // join threads and release ALSA/SRC resources

            std::string err;
            if (_inputs[i]->start(&err))
            {
                LOG_INFO("[monitor] Input %d restarted successfully", i + 1);
            }
            else
            {
                LOG_WARN("[monitor] Input %d restart failed: %s; will retry in %.0f s",
                         i + 1, err.c_str(), RESTART_BACKOFF_SECONDS);
                _restart_after[i] = get_monotonic_time() + RESTART_BACKOFF_SECONDS;
            }
        }
    }

    stop();
}

void AudioMonitor::stop()
{
    if (!_running.exchange(false))
        return;

    // Wake run() immediately so it does not wait out the 100 ms poll interval.
    _run_cv.notify_all();

    LOG_INFO("[monitor] Shutting down");

    // Stop all input channels.
    for (int i = 0; i < NUM_INPUTS; ++i)
    {
        if (_inputs[i])
            _inputs[i]->stop();
    }

    // Stop any active engineering output dump.  Inputs are already stopped so
    // no new frames will be submitted; the writer thread drains quickly.
    _dump_writer.stop();

    // Stop the control server (closes the socket).
    _control_server.stop();

    // Close the FIFO under _fifo_mutex so it is serialised with any in-flight
    // write() calls from the (now-stopped) InputChannel threads.
    {
        std::lock_guard<std::mutex> lock(_fifo_mutex);
        _fifo_writer.close();
    }

    LOG_INFO("[monitor] Shutdown complete");
}

InputChannel* AudioMonitor::get_input(int input_index)
{
    if (input_index < 1 || input_index > NUM_INPUTS)
        return nullptr;
    return _inputs[input_index - 1].get();
}


// ── api_get_status ────────────────────────────────────────────────────────────
//
// Returns a JSON status snapshot for all inputs and top-level daemon metadata.
// Called in response to a {"type":"get_status"} command.  Python polls this
// at whatever rate the UI requires.
//
std::string AudioMonitor::api_get_status()
{
    LOG_SPAM("[monitor] get_status requested");

    // Poll and reset the output clip accumulator.  Must be called before
    // building the response so the dBFS conversion happens once here rather
    // than on the hot path.
    float clip_dbfs = _output_processor.poll_clip_overshoot_dbfs();

    // Snapshot the current output gain state.
    OutputGainState gs = _output_processor.get_gain_state();

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    oss << "{\"type\":\"status\",\"monitor_build\":\""
        << json_escape(AUTOSTREAM_MONITOR_BUILD)
        << "\",\"log_level\":\""
        << protocol_log_level_name(logger_get_level())
        << "\",\"output_clip_dbfs\":"           << clip_dbfs
        << ",\"output_gain_db\":"               << gs.manual_gain_db
        << ",\"output_auto_trim_enabled\":"     << (gs.auto_trim_enabled ? "true" : "false")
        << ",\"output_auto_trim_db\":"          << gs.auto_trim_db
        << ",\"effective_output_gain_db\":"     << gs.effective_gain_db;

    {
        OutputDumpWriter::Status ds = _dump_writer.get_status();
        oss << ",\"output_dump\":{"
            << "\"active\":"         << (ds.active ? "true" : "false") << ","
            << "\"path\":\""         << json_escape(ds.path)            << "\","
            << "\"frames_written\":" << ds.frames_written               << ","
            << "\"dropped_frames\":" << ds.dropped_frames               << "}";
    }

    oss << ",\"inputs\":[";

    for (int i = 0; i < NUM_INPUTS; ++i)
    {
        if (i > 0)
            oss << ",";

        InputChannelStatus s = _inputs[i]->get_status();

        std::vector<VuBin> vu = _inputs[i]->get_vu_history();
        uint32_t latest_seq = vu.empty() ? 0u : vu.back().seq;

        oss << "{"
            << "\"index\":"               << s.index                << ","
            << "\"level_dbfs\":"          << s.level_dbfs            << ","
            << "\"poll_peak_dbfs\":"      << s.poll_peak_dbfs        << ","
            << "\"silent\":"              << (s.is_silent    ? "true" : "false") << ","
            << "\"capturing\":"           << (s.is_capturing ? "true" : "false") << ","
            << "\"detected_hz\":"         << s.detected_hz           << ","
            << "\"raw_peak_dbfs\":"       << s.raw_peak_dbfs         << ","
            << "\"effective_peak_dbfs\":" << s.effective_peak_dbfs   << ","
            << "\"started\":"             << (s.is_started   ? "true" : "false") << ","
            << "\"running\":"             << (s.is_running   ? "true" : "false") << ","
            << "\"vu_history\":{\"bin_ms\":100,\"latest_seq\":" << latest_seq << ",\"bins\":[";

        for (size_t j = 0; j < vu.size(); ++j)
        {
            if (j > 0) oss << ",";
            oss << "{\"seq\":"  << vu[j].seq
                << ",\"l\":"    << vu[j].left_dbfs
                << ",\"r\":"    << vu[j].right_dbfs << "}";
        }

        oss << "]}}";
    }

    oss << "]}";
    return oss.str();
}


// ── Validation helpers ────────────────────────────────────────────────────────

// Return an error string describing why cfg is invalid, or "" if it is valid.
static std::string validate_input_config(const InputConfig& cfg)
{
    // Device name must begin with "hw:" and be at least 5 characters
    // (e.g. "hw:1,0" or "hw:CARD=CODEC,DEV=0"). Full hw:* validation is
    // left to ALSA, which will return a clear error when open() is called.
    if (cfg.alsa_device.empty())
        return "device is empty";

    if (cfg.alsa_device.size() < 5
        || cfg.alsa_device.substr(0, 3) != "hw:")
    {
        return "device must be in ALSA hw:* format (e.g. hw:1,0)";
    }

    if (cfg.silence_threshold_dbfs > 0.0f || cfg.silence_threshold_dbfs < -120.0f)
        return "silence_threshold_dbfs must be in the range [-120.0, 0.0]";

    if (cfg.silence_seconds < 1 || cfg.silence_seconds > 3600)
        return "silence_seconds must be in the range [1, 3600]";

    return "";
}

// Return an error string describing why path is invalid as a FIFO path, or "".
static std::string validate_fifo_path(const std::string& path)
{
    if (path.empty())
        return "path is empty";

    if (path[0] != '/')
        return "path must be absolute (start with /)";

    // Reject traversal sequences.
    if (path.find("..") != std::string::npos)
        return "path must not contain ..";

    // Eagerly verify the path exists and is a named pipe.  This surfaces
    // misconfiguration at set_fifo time rather than silently on first write.
    struct stat st;
    if (stat(path.c_str(), &st) != 0)
    {
        // Use strerror to distinguish ENOENT, EACCES, etc.
        return std::string("cannot stat path: ") + strerror(errno);
    }

    if (!S_ISFIFO(st.st_mode))
        return "path exists but is not a named pipe (FIFO)";

    if (access(path.c_str(), W_OK) != 0)
        return std::string("path is not writable: ") + strerror(errno);

    return "";
}

// Return an error string if path is invalid as a WAV dump output path, or "".
// overwrite: if false, rejects the call when a file already exists at path.
static std::string validate_dump_path(const std::string& path, bool overwrite)
{
    if (path.empty())
        return "path is empty";

    if (path[0] != '/')
        return "path must be absolute (start with /)";

    if (path.find("..") != std::string::npos)
        return "path must not contain ..";

    struct stat st;
    if (stat(path.c_str(), &st) == 0)
    {
        // Path already exists — must be a regular file.
        if (!S_ISREG(st.st_mode))
            return "path exists but is not a regular file";
        if (!overwrite)
            return "file already exists; use \"overwrite\":true to replace";
    }

    // Verify the parent directory is writable so the open() in start() will
    // not fail with EACCES.  rfind('/') always finds at least the leading '/'.
    std::string parent = path.substr(0, path.rfind('/'));
    if (parent.empty())
        parent = "/";
    if (access(parent.c_str(), W_OK) != 0)
        return std::string("parent directory is not writable: ") + strerror(errno);

    return "";
}

// Return an error string if gain_db is out of range, or "".
// This validates the per-input pre-amplifier gain, which spans [-24, +24] dB.
// EQ band gain has its own tighter range check in validate_eq_bands().
static std::string validate_gain_db(float gain_db)
{
    if (gain_db < -24.0f || gain_db > 24.0f)
        return "gain_db must be in the range [-24.0, +24.0]";
    return "";
}

// Return an error string if gain_db is out of range for the output gain, or "".
// The output gain range is narrower than the per-input gain: [-10, +10] dB.
static std::string validate_output_gain_db(float gain_db)
{
    if (gain_db < OutputProcessor::OUTPUT_GAIN_MIN_DB ||
        gain_db > OutputProcessor::OUTPUT_GAIN_MAX_DB)
        return "gain_db must be in the range [-10.0, +10.0]";
    return "";
}

// Return an error string if the EQ band list is invalid, or "".
static std::string validate_eq_bands(const std::vector<EqBand>& bands)
{
    // Sanity-cap the number of bands to avoid runaway coefficient computation.
    if (bands.size() > 16)
        return "too many EQ bands (maximum 16)";

    const float nyquist = static_cast<float>(AudioMonitor::output_rate_hz()) / 2.0f;

    for (size_t i = 0; i < bands.size(); ++i)
    {
        if (bands[i].freq_hz <= 0.0f || bands[i].freq_hz >= nyquist)
            return "freq_hz must be > 0 and < " + std::to_string(static_cast<int>(nyquist)) + " Hz";

        if (bands[i].q <= 0.0f)
            return "q must be > 0";

        if (bands[i].gain_db < -12.0f || bands[i].gain_db > 12.0f)
            return "gain_db must be in the range [-12.0, +12.0]";
    }

    return "";
}


// ── API methods ───────────────────────────────────────────────────────────────

std::string AudioMonitor::api_list_devices()
{
    std::vector<AlsaDeviceInfo> devices = list_alsa_capture_devices();
    LOG_DEBUG("[monitor] list_devices returning %zu device(s)", devices.size());

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"list_devices\",\"ok\":true,\"devices\":[";

    for (size_t i = 0; i < devices.size(); ++i)
    {
        if (i > 0) oss << ",";
        oss << "{"
            << "\"hw\":\""   << json_escape(devices[i].hw_name)    << "\","
            << "\"card\":\""  << json_escape(devices[i].card_name)  << "\","
            << "\"name\":\""  << json_escape(devices[i].device_name) << "\""
            << "}";
    }

    oss << "]}";
    return oss.str();
}

std::string AudioMonitor::api_configure_input(int input_index, const InputConfig& cfg)
{
    InputChannel* ch = get_input(input_index);
    if (!ch)
    {
        LOG_WARN("[monitor] configure_input rejected for invalid input index %d", input_index);
        return "{\"type\":\"ack\",\"command\":\"configure_input\","
               "\"ok\":false,\"error\":\"input index must be 1 or 2\"}";
    }

    // Validate all supplied values before touching any channel state.
    std::string validation_error = validate_input_config(cfg);
    if (!validation_error.empty())
    {
        LOG_WARN("[monitor] configure_input(%d) rejected: %s",
                 input_index, validation_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"configure_input\","
            << "\"ok\":false,\"error\":\"" << json_escape(validation_error) << "\"}";
        return oss.str();
    }

    // configure() enforces the startup-only / runtime-tunable distinction.
    if (!ch->configure(cfg))
    {
        LOG_WARN("[monitor] configure_input(%d) rejected: stop input before changing device",
                 input_index);
        return "{\"type\":\"ack\",\"command\":\"configure_input\","
               "\"ok\":false,\"error\":\"stop the input before changing device\"}";
    }

    LOG_INFO("[monitor] configure_input(%d) applied", input_index);

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"configure_input\","
        << "\"input\":" << input_index << ","
        << "\"ok\":true}";
    return oss.str();
}

std::string AudioMonitor::api_set_fifo(const std::string& path)
{
    std::string validation_error = validate_fifo_path(path);
    if (!validation_error.empty())
    {
        LOG_WARN("[monitor] set_fifo rejected: %s", validation_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"set_fifo\","
            << "\"ok\":false,\"error\":\"" << json_escape(validation_error) << "\"}";
        return oss.str();
    }

    // Acquire _fifo_mutex so this is properly serialised with any concurrent
    // write() calls from the InputChannel process threads.
    {
        std::lock_guard<std::mutex> lock(_fifo_mutex);
        _fifo_writer.set_path(path);
    }

    LOG_INFO("[monitor] FIFO path set to '%s'", path.c_str());
    return "{\"type\":\"ack\",\"command\":\"set_fifo\",\"ok\":true}";
}

std::string AudioMonitor::api_start_input(int input_index)
{
    InputChannel* ch = get_input(input_index);
    if (!ch)
    {
        LOG_WARN("[monitor] start_input rejected for invalid input index %d", input_index);
        return "{\"type\":\"ack\",\"command\":\"start_input\","
               "\"ok\":false,\"error\":\"input index must be 1 or 2\"}";
    }

    // Guard against both the normal "already running" case and the
    // "crashed but not yet cleaned up" case where the capture thread has
    // self-stopped (_running = false) but stop() has not been called, leaving
    // joinable thread objects and live SRC state.  Assigning a new std::thread
    // to a joinable thread would call std::terminate, so we must reject start
    // in both cases and require the caller to issue stop_input first.
    if (ch->is_started())
    {
        LOG_WARN("[monitor] start_input(%d) rejected: input already started", input_index);
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"start_input\","
            << "\"input\":" << input_index << ","
            << "\"ok\":false,\"error\":"
            << (ch->is_running()
                    ? "\"input is already running\""
                    : "\"input stopped unexpectedly; call stop_input first\"")
            << "}";
        return oss.str();
    }

    std::string start_error;
    bool started = ch->start(&start_error);
    if (started)
        LOG_INFO("[monitor] start_input(%d) succeeded", input_index);
    else
        LOG_WARN("[monitor] start_input(%d) failed: %s",
                 input_index, start_error.empty() ? "failed to start input" : start_error.c_str());

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"start_input\","
        << "\"input\":" << input_index << ","
        << "\"ok\":" << (started ? "true" : "false");
    if (!started)
        oss << ",\"error\":\""
            << json_escape(start_error.empty() ? "failed to start input" : start_error)
            << "\"";
    oss << "}";
    return oss.str();
}

std::string AudioMonitor::api_stop_input(int input_index)
{
    InputChannel* ch = get_input(input_index);
    if (!ch)
    {
        LOG_WARN("[monitor] stop_input rejected for invalid input index %d", input_index);
        return "{\"type\":\"ack\",\"command\":\"stop_input\","
               "\"ok\":false,\"error\":\"input index must be 1 or 2\"}";
    }

    // Read _allow_capture *before* stop() so we know whether this was the
    // active FIFO writer.  stop() joins the process thread, which is safe to
    // do with _allow_capture still set; the thread exits cleanly.  We must not
    // reset the shared auto-trim for the inactive (monitoring-only) input,
    // because doing so would discard the trim that was learned for the currently
    // active input's session — exactly the bug the fix is designed to prevent.
    const bool was_active = ch->allow_capture_enabled();

    ch->stop();

    // Reset auto-trim only when the stopped input was the one feeding the FIFO.
    // Stopping the idle monitoring input must not disturb trim accumulated by
    // the active session on the other input.
    if (was_active)
        _output_processor.reset_auto_trim();

    LOG_INFO("[monitor] stop_input(%d) completed (was_active=%s)",
             input_index, was_active ? "true" : "false");

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"stop_input\","
        << "\"input\":" << input_index << ","
        << "\"ok\":true}";
    return oss.str();
}

std::string AudioMonitor::api_set_allow_capture(int input_index, bool allow)
{
    InputChannel* ch = get_input(input_index);
    if (!ch)
    {
        LOG_WARN("[monitor] set_allow_capture rejected for invalid input index %d", input_index);
        return "{\"type\":\"ack\",\"command\":\"set_allow_capture\","
               "\"ok\":false,\"error\":\"input index must be 1 or 2\"}";
    }

    // Only one input may write to the shared FIFO at a time.  Allowing two
    // concurrent capture sessions would interleave their PCM blocks in the
    // pipe, producing a corrupted stream for OwnTone.  Enforce mutual
    // exclusion here: enabling capture on one input disables it on all others.
    //
    // Sequence for a handoff (allow == true):
    //   1. Read which other inputs, if any, are currently marked as the active
    //      writer.  This determines whether this call is a true handoff (a
    //      different source is taking over) or an idempotent reassertion of the
    //      already-active input.  Auto-trim must only be reset on a true handoff;
    //      resetting on an idempotent call would discard the trim learned for the
    //      session that is still running.
    //   2. Store _allow_capture = false on all other inputs.  Their process
    //      threads re-check this flag under _fifo_mutex before calling apply()
    //      or writing, so any apply()/write that begins after this store will be
    //      suppressed.
    //   3. Acquire _fifo_mutex.  This blocks until any in-flight apply()+write
    //      from a just-disabled thread completes (that thread also holds
    //      _fifo_mutex during apply() and the FIFO write).
    //   4. If this is a true handoff, reset auto-trim while holding _fifo_mutex.
    //      Because apply() — including the auto-trim CAS update — only runs
    //      under _fifo_mutex, holding the lock here guarantees that no outgoing
    //      process thread can write a stale negative trim after this reset.
    //   5. Enable the new input while still under _fifo_mutex, so the first
    //      apply()/write from the new input cannot race with a trailing write
    //      from the old input.
    if (allow)
    {
        // Step 1: detect a real handoff before mutating any state.
        bool is_handoff = false;
        for (int i = 0; i < NUM_INPUTS; ++i)
        {
            if (_inputs[i].get() != ch && _inputs[i]->allow_capture_enabled())
                is_handoff = true;
        }

        // Step 2: disable all other inputs.
        for (int i = 0; i < NUM_INPUTS; ++i)
        {
            if (_inputs[i].get() != ch)
                _inputs[i]->set_allow_capture(false);
        }

        // Steps 3-5: acquire mutex, conditionally reset trim, enable new input.
        {
            std::lock_guard<std::mutex> lock(_fifo_mutex);

            // Step 4: reset trim inside the mutex so no outgoing apply() call
            // can write a negative trim after this point (apply() is also under
            // _fifo_mutex; see process_thread_func for the full invariant).
            if (is_handoff)
                _output_processor.reset_auto_trim();

            // Step 5: enable the new input while holding the lock.
            ch->set_allow_capture(true);
        }
    }
    else
    {
        ch->set_allow_capture(false);
    }

    LOG_DEBUG("[monitor] set_allow_capture(%d, %s) applied",
              input_index, allow ? "true" : "false");

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"set_allow_capture\","
        << "\"input\":"  << input_index << ","
        << "\"allow\":"  << (allow ? "true" : "false") << ","
        << "\"ok\":true}";
    return oss.str();
}

std::string AudioMonitor::api_set_eq(int input_index, const std::vector<EqBand>& bands)
{
    InputChannel* ch = get_input(input_index);
    if (!ch)
    {
        LOG_WARN("[monitor] set_eq rejected for invalid input index %d", input_index);
        return "{\"type\":\"ack\",\"command\":\"set_eq\","
               "\"ok\":false,\"error\":\"input index must be 1 or 2\"}";
    }

    std::string validation_error = validate_eq_bands(bands);
    if (!validation_error.empty())
    {
        LOG_WARN("[monitor] set_eq(%d) rejected: %s",
                 input_index, validation_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"set_eq\","
            << "\"ok\":false,\"error\":\"" << json_escape(validation_error) << "\"}";
        return oss.str();
    }

    ch->set_eq(bands);
    LOG_DEBUG("[monitor] set_eq(%d) applied %zu band(s)", input_index, bands.size());

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"set_eq\","
        << "\"input\":"        << input_index << ","
        << "\"bands_applied\":" << bands.size() << ","
        << "\"ok\":true}";
    return oss.str();
}

std::string AudioMonitor::api_set_output_eq(const std::vector<EqBand>& bands)
{
    std::string validation_error = validate_eq_bands(bands);
    if (!validation_error.empty())
    {
        LOG_WARN("[monitor] set_output_eq rejected: %s", validation_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"set_output_eq\","
            << "\"ok\":false,\"error\":\"" << json_escape(validation_error) << "\"}";
        return oss.str();
    }

    _output_processor.set_bands(bands, static_cast<float>(OUTPUT_RATE));
    LOG_DEBUG("[monitor] set_output_eq applied %zu band(s)", bands.size());

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"set_output_eq\","
        << "\"bands_applied\":" << bands.size() << ","
        << "\"ok\":true}";
    return oss.str();
}

std::string AudioMonitor::api_set_output_gain(float gain_db)
{
    std::string validation_error = validate_output_gain_db(gain_db);
    if (!validation_error.empty())
    {
        LOG_WARN("[monitor] set_output_gain rejected: %s", validation_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"set_output_gain\","
            << "\"ok\":false,\"error\":\"" << json_escape(validation_error) << "\"}";
        return oss.str();
    }

    _output_processor.set_manual_gain(gain_db);

    OutputGainState gs = _output_processor.get_gain_state();
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    oss << "{\"type\":\"ack\",\"command\":\"set_output_gain\","
        << "\"ok\":true,"
        << "\"output_gain_db\":"           << gs.manual_gain_db    << ","
        << "\"output_auto_trim_db\":"      << gs.auto_trim_db      << ","
        << "\"effective_output_gain_db\":" << gs.effective_gain_db << "}";
    return oss.str();
}

std::string AudioMonitor::api_set_output_auto_trim(bool enabled)
{
    _output_processor.set_auto_trim_enabled(enabled);

    OutputGainState gs = _output_processor.get_gain_state();
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    oss << "{\"type\":\"ack\",\"command\":\"set_output_auto_trim\","
        << "\"ok\":true,"
        << "\"output_auto_trim_enabled\":"  << (gs.auto_trim_enabled ? "true" : "false") << ","
        << "\"output_auto_trim_db\":"       << gs.auto_trim_db      << ","
        << "\"effective_output_gain_db\":"  << gs.effective_gain_db << "}";
    return oss.str();
}

std::string AudioMonitor::api_set_gain(int input_index, float gain_db)
{
    InputChannel* ch = get_input(input_index);
    if (!ch)
    {
        LOG_WARN("[monitor] set_gain rejected for invalid input index %d", input_index);
        return "{\"type\":\"ack\",\"command\":\"set_gain\","
               "\"ok\":false,\"error\":\"input index must be 1 or 2\"}";
    }

    std::string validation_error = validate_gain_db(gain_db);
    if (!validation_error.empty())
    {
        LOG_WARN("[monitor] set_gain(%d) rejected: %s",
                 input_index, validation_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"set_gain\","
            << "\"ok\":false,\"error\":\"" << json_escape(validation_error) << "\"}";
        return oss.str();
    }

    ch->set_gain(gain_db);
    LOG_DEBUG("[monitor] set_gain(%d) applied %.2f dB", input_index, gain_db);

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"set_gain\","
        << "\"input\":"   << input_index << ","
        << "\"gain_db\":" << gain_db     << ","
        << "\"ok\":true}";
    return oss.str();
}

std::string AudioMonitor::api_set_log_level(const std::string& level_text)
{
    MonitorLogLevel level;
    if (!parse_monitor_log_level(level_text, &level))
    {
        LOG_WARN("[monitor] set_log_level rejected: unsupported level %s",
                 level_text.empty() ? "<empty>" : level_text.c_str());
        return "{\"type\":\"ack\",\"command\":\"set_log_level\","
               "\"ok\":false,\"error\":\"unsupported log level\"}";
    }

    MonitorLogLevel applied = logger_set_level(level);
    LOG_INFO("[monitor] Log level changed to %s", protocol_log_level_name(applied));

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"set_log_level\","
        << "\"ok\":true,"
        << "\"level\":\"" << protocol_log_level_name(applied) << "\"}";
    return oss.str();
}


// ── api_get_id_snapshot ───────────────────────────────────────────────────────
//
// Copies up to max_seconds * ID_BUF_RATE frames from the rolling ID snapshot
// buffer into *binary_out and returns a JSON ack with metadata.
//
// On success the JSON line is followed by raw binary data (s16le mono 22050 Hz)
// sent by handle_client().  On error the JSON line has "ok":false and no binary
// data follows.
//
std::string AudioMonitor::api_get_id_snapshot(int input_index, int max_seconds,
                                               std::vector<int16_t>* binary_out)
{
    InputChannel* ch = get_input(input_index);
    if (!ch)
    {
        LOG_WARN("[monitor] get_id_snapshot rejected for invalid input index %d", input_index);
        return "{\"type\":\"ack\",\"command\":\"get_id_snapshot\","
               "\"ok\":false,\"error\":\"input index must be 1 or 2\"}";
    }

    // Clamp max_seconds to a sane range so the caller cannot request an
    // unbounded allocation.
    if (max_seconds < 1)  max_seconds = 1;
    if (max_seconds > 20) max_seconds = 20;

    unsigned max_frames = static_cast<unsigned>(max_seconds) * InputChannel::ID_BUF_RATE;

    binary_out->resize(max_frames);
    unsigned frames = ch->get_id_snapshot(binary_out->data(), max_frames);
    binary_out->resize(frames);

    if (frames == 0)
    {
        LOG_DEBUG("[monitor] get_id_snapshot(%d) has no snapshot data", input_index);
        return "{\"type\":\"ack\",\"command\":\"get_id_snapshot\","
               "\"input\":"  + std::to_string(input_index) + ","
               "\"ok\":false,\"error\":\"no snapshot data available\"}";
    }

    LOG_DEBUG("[monitor] get_id_snapshot(%d) returning %u frame(s)", input_index, frames);

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"get_id_snapshot\","
        << "\"input\":"    << input_index   << ","
        << "\"ok\":true,"
        << "\"format\":\"s16le\","
        << "\"rate\":"     << InputChannel::ID_BUF_RATE << ","
        << "\"channels\":1,"
        << "\"frames\":"   << frames        << "}";
    return oss.str();
}


// ── api_start_output_dump ─────────────────────────────────────────────────────
//
// Validates path, then delegates to OutputDumpWriter::start().  The dump tap
// in InputChannel::process_thread_func() is gated by OutputDumpWriter::is_active(),
// so recording begins on the next processed audio block after this returns.
//
std::string AudioMonitor::api_start_output_dump(const std::string& path, bool overwrite)
{
    std::string validation_error = validate_dump_path(path, overwrite);
    if (!validation_error.empty())
    {
        LOG_WARN("[monitor] start_output_dump rejected: %s", validation_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"start_output_dump\","
            << "\"ok\":false,\"error\":\"" << json_escape(validation_error) << "\"}";
        return oss.str();
    }

    std::string start_error = _dump_writer.start(path, overwrite);
    if (!start_error.empty())
    {
        LOG_WARN("[monitor] start_output_dump failed: %s", start_error.c_str());
        std::ostringstream oss;
        oss << "{\"type\":\"ack\",\"command\":\"start_output_dump\","
            << "\"ok\":false,\"error\":\"" << json_escape(start_error) << "\"}";
        return oss.str();
    }

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"start_output_dump\","
        << "\"ok\":true,"
        << "\"path\":\"" << json_escape(path) << "\"}";
    return oss.str();
}


// ── api_stop_output_dump ──────────────────────────────────────────────────────
//
// Signals OutputDumpWriter to stop, waits for the writer thread to drain and
// exit, patches the WAV header, and closes the file.  Returns a JSON ack
// with the final frame and drop counts regardless of whether a dump was active.
//
std::string AudioMonitor::api_stop_output_dump()
{
    bool was_active = false;
    _dump_writer.stop(&was_active);

    OutputDumpWriter::Status s = _dump_writer.get_status();

    std::ostringstream oss;
    oss << "{\"type\":\"ack\",\"command\":\"stop_output_dump\","
        << "\"ok\":true,"
        << "\"was_active\":"     << (was_active ? "true" : "false") << ","
        << "\"frames_written\":" << s.frames_written                << ","
        << "\"dropped_frames\":" << s.dropped_frames                << "}";
    return oss.str();
}


// =============================================================================
// main
// =============================================================================

int main(int argc, char* argv[])
{
    // Parse command-line arguments.
    // Usage: autostream_monitor [--socket PATH] [--log-level LEVEL]
    std::string socket_path = "/tmp/autostream_monitor.sock";
    std::string log_level_arg;

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
        {
            socket_path = argv[++i];
        }
        else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc)
        {
            log_level_arg = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            fprintf(stdout,
                    "Usage: autostream_monitor [--socket PATH] [--log-level LEVEL]\n"
                    "\n"
                    "  --socket PATH   Unix domain socket path (default: %s)\n"
                    "  --log-level L   Override log level: warn|warning|info|debug|spam\n"
                    "\n"
                    "The monitor starts with no audio device connected.\n"
                    "Configure it via the socket using JSON commands.\n"
                    "See autostream_monitor.h for the full protocol.\n",
                    socket_path.c_str());
            return 0;
        }
        else
        {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", argv[i]);
            return 1;
        }
    }

    MonitorLogLevel log_level = MonitorLogLevel::Warn;
    if (!log_level_arg.empty())
    {
        if (!parse_monitor_log_level(log_level_arg, &log_level))
        {
            fprintf(stderr, "Invalid --log-level value: %s\n", log_level_arg.c_str());
            return 1;
        }
    }

    logger_init(log_level);

    // Install signal handlers so we shut down cleanly on Ctrl-C or systemd stop.
    // sigaction() is used instead of signal() for deterministic behaviour:
    // signal() has implementation-defined SA_RESETHAND/SA_RESTART semantics,
    // while sigaction() lets us specify them explicitly.  SA_RESTART causes
    // the kernel to restart interrupted syscalls where possible (e.g. ALSA
    // reads), avoiding spurious EINTR errors in normal operation.
    {
        struct sigaction sa;
        sa.sa_handler = signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        sigaction(SIGINT,  &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }

    // SIGPIPE would terminate the process if writing to a broken pipe (e.g. the
    // FIFO has no reader).  We handle that in FifoWriter::write() instead.
    {
        struct sigaction sa_ign;
        sa_ign.sa_handler = SIG_IGN;
        sigemptyset(&sa_ign.sa_mask);
        sa_ign.sa_flags = 0;
        sigaction(SIGPIPE, &sa_ign, nullptr);
    }

    LOG_INFO("[monitor] autostream_monitor starting (socket: %s)",
             socket_path.c_str());
    LOG_INFO("[monitor] Log level set to %s (%s)",
             protocol_log_level_name(log_level),
             log_level_arg.empty() ? "default" : "command line");

    AudioMonitor monitor(socket_path);
    monitor.run();
    logger_flush_repeats();

    return 0;
}
