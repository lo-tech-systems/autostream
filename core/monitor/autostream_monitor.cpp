// =============================================================================
// autostream_monitor.cpp
//
// Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
//
// Implementation of the autostream audio monitor daemon.
// See autostream_monitor.h for the full design description.
//
// Build:
//   g++ -std=c++17 -O2 -o autostream_monitor autostream_monitor.cpp \
//       -lasound -lsamplerate -lpthread
// =============================================================================

#include "autostream_monitor.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <csignal>
#include <cerrno>
#include <cstdarg>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <optional>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <chrono>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>


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
// Timing helper
// =============================================================================

// Returns the current monotonic clock time in seconds.
// Monotonic time is used throughout so that NTP adjustments or system clock
// changes do not affect silence detection timing.
static double get_monotonic_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1.0e9;
}


// =============================================================================
// Logging
// =============================================================================

enum class MonitorLogLevel
{
    Warn = 0,
    Info = 1,
    Debug = 2,
    Spam = 3,
};

struct MonitorLoggerState
{
    std::mutex      mutex;
    std::atomic<MonitorLogLevel> level{MonitorLogLevel::Warn};
    std::string     last_key;
    unsigned int    last_printed = 0;
    unsigned int    suppressed = 0;
};

static MonitorLoggerState g_logger;
static constexpr unsigned int DUPLICATE_LOG_LIMIT = 5;
static const char* log_level_name(MonitorLogLevel level)
{
    switch (level)
    {
    case MonitorLogLevel::Warn:  return "WARN";
    case MonitorLogLevel::Info:  return "INFO";
    case MonitorLogLevel::Debug: return "DEBUG";
    case MonitorLogLevel::Spam:  return "SPAM";
    }
    return "WARN";
}

static bool log_level_enabled(MonitorLogLevel level)
{
    return static_cast<int>(level)
        <= static_cast<int>(g_logger.level.load(std::memory_order_relaxed));
}

static void logger_init(MonitorLogLevel level)
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    g_logger.level.store(level, std::memory_order_relaxed);
    g_logger.last_key.clear();
    g_logger.last_printed = 0;
    g_logger.suppressed   = 0;
}

static std::string trim_copy(const std::string& text)
{
    size_t start = 0;
    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])))
        ++start;

    size_t end = text.size();
    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1])))
        --end;

    return text.substr(start, end - start);
}

static std::string lowercase_copy(std::string text)
{
    for (char& ch : text)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return text;
}

static bool parse_monitor_log_level(const std::string& text, MonitorLogLevel* out_level)
{
    const std::string value = lowercase_copy(trim_copy(text));
    if (value.empty())
        return false;

    if (value == "fatal" || value == "log" || value == "warning" || value == "warn")
    {
        *out_level = MonitorLogLevel::Warn;
        return true;
    }
    if (value == "info")
    {
        *out_level = MonitorLogLevel::Info;
        return true;
    }
    if (value == "debug")
    {
        *out_level = MonitorLogLevel::Debug;
        return true;
    }
    if (value == "spam")
    {
        *out_level = MonitorLogLevel::Spam;
        return true;
    }
    return false;
}

static std::string make_timestamp()
{
    std::time_t now = ::time(nullptr);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char buf[32];
    if (::strftime(buf, sizeof(buf), "%d-%b-%y %H:%M:%S", &tm_now) == 0)
        return "00-Jan-00 00:00:00";
    return buf;
}

static void logger_emit_raw_line(const std::string& key)
{
    std::string line = make_timestamp();
    line += ": ";
    line += key;
    line += '\n';
    std::fwrite(line.data(), 1, line.size(), stderr);
    std::fflush(stderr);
}

static void logger_emit_repeat_summary_locked()
{
    if (g_logger.suppressed == 0 || g_logger.last_key.empty())
        return;

    std::ostringstream oss;
    oss << g_logger.last_key
        << " (suppressed " << g_logger.suppressed << " duplicate entr"
        << (g_logger.suppressed == 1 ? "y" : "ies") << ")";
    logger_emit_raw_line(oss.str());
    g_logger.suppressed = 0;
}

static void logger_flush_repeats()
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
}

static MonitorLogLevel logger_get_level()
{
    return g_logger.level.load(std::memory_order_relaxed);
}

static MonitorLogLevel logger_set_level(MonitorLogLevel level)
{
    std::lock_guard<std::mutex> lock(g_logger.mutex);
    logger_emit_repeat_summary_locked();
    g_logger.last_key.clear();
    g_logger.last_printed = 0;
    g_logger.level.store(level, std::memory_order_relaxed);
    return level;
}

static const char* protocol_log_level_name(MonitorLogLevel level)
{
    switch (level)
    {
    case MonitorLogLevel::Warn:  return "warning";
    case MonitorLogLevel::Info:  return "info";
    case MonitorLogLevel::Debug: return "debug";
    case MonitorLogLevel::Spam:  return "spam";
    }
    return "warning";
}

static void logger_vlog(MonitorLogLevel level, const char* fmt, va_list args)
{
    if (!log_level_enabled(level))
        return;

    char stack_buf[1024];
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = std::vsnprintf(stack_buf, sizeof(stack_buf), fmt, args_copy);
    va_end(args_copy);

    if (needed < 0)
        return;

    std::string message;
    if (static_cast<size_t>(needed) < sizeof(stack_buf))
    {
        message.assign(stack_buf, static_cast<size_t>(needed));
    }
    else
    {
        std::vector<char> dynamic_buf(static_cast<size_t>(needed) + 1);
        std::vsnprintf(dynamic_buf.data(), dynamic_buf.size(), fmt, args);
        message.assign(dynamic_buf.data(), static_cast<size_t>(needed));
    }

    std::string key = "[";
    key += log_level_name(level);
    key += "] ";
    key += message;

    std::lock_guard<std::mutex> lock(g_logger.mutex);
    if (key == g_logger.last_key)
    {
        ++g_logger.last_printed;
        if (g_logger.last_printed <= DUPLICATE_LOG_LIMIT)
        {
            logger_emit_raw_line(key);
            return;
        }

        ++g_logger.suppressed;
        if (g_logger.last_printed == DUPLICATE_LOG_LIMIT + 1)
        {
            std::ostringstream oss;
            oss << key
                << " (suppressing further duplicates after "
                << DUPLICATE_LOG_LIMIT << " identical entries)";
            logger_emit_raw_line(oss.str());
        }
        return;
    }

    logger_emit_repeat_summary_locked();
    g_logger.last_key = key;
    g_logger.last_printed = 1;
    logger_emit_raw_line(key);
}

static void logger_log(MonitorLogLevel level, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    logger_vlog(level, fmt, args);
    va_end(args);
}

#define LOG_WARN(...)  logger_log(MonitorLogLevel::Warn, __VA_ARGS__)
#define LOG_INFO(...)  logger_log(MonitorLogLevel::Info, __VA_ARGS__)
#define LOG_DEBUG(...) logger_log(MonitorLogLevel::Debug, __VA_ARGS__)
#define LOG_SPAM(...)  logger_log(MonitorLogLevel::Spam, __VA_ARGS__)


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


// =============================================================================
// list_alsa_capture_devices
// =============================================================================

std::vector<AlsaDeviceInfo> list_alsa_capture_devices()
{
    std::vector<AlsaDeviceInfo> result;

    void** hints = nullptr;
    if (snd_device_name_hint(-1, "pcm", &hints) < 0)
    {
        LOG_WARN("[monitor] list_alsa_capture_devices: snd_device_name_hint failed");
        return result;
    }

    for (void** hint = hints; *hint != nullptr; ++hint)
    {
        char* name_cstr = snd_device_name_get_hint(*hint, "NAME");
        char* desc_cstr = snd_device_name_get_hint(*hint, "DESC");
        char* ioid_cstr = snd_device_name_get_hint(*hint, "IOID");

        // IOID is "Input", "Output", or nullptr (meaning both directions).
        // We want capture devices only.
        bool is_capture = (ioid_cstr == nullptr || strcmp(ioid_cstr, "Input") == 0);

        if (name_cstr && is_capture)
        {
            std::string hw_name(name_cstr);

            // Only include hw:X,Y devices — plughw, default, etc. are excluded
            // because we want to talk directly to hardware for clock measurement.
            if (hw_name.size() > 3 && hw_name.substr(0, 3) == "hw:")
            {
                AlsaDeviceInfo info;
                info.hw_name = hw_name;

                if (desc_cstr)
                {
                    // ALSA desc format is typically "Card Name\nSubdevice Name"
                    std::string full_desc(desc_cstr);
                    auto newline_pos = full_desc.find('\n');
                    if (newline_pos != std::string::npos)
                    {
                        info.card_name   = full_desc.substr(0, newline_pos);
                        info.device_name = full_desc.substr(newline_pos + 1);
                    }
                    else
                    {
                        info.card_name   = full_desc;
                        info.device_name = full_desc;
                    }
                }

                result.push_back(info);
            }
        }

        free(name_cstr);
        free(desc_cstr);
        free(ioid_cstr);
    }

    snd_device_name_free_hint(hints);
    LOG_DEBUG("[monitor] list_alsa_capture_devices found %zu capture device(s)", result.size());
    return result;
}


// =============================================================================
// BiquadFilter
// =============================================================================

BiquadFilter::BiquadFilter()
    : _b0(1.0f), _b1(0.0f), _b2(0.0f)
    , _a1(0.0f), _a2(0.0f)
{
    reset();
}

void BiquadFilter::set_coefficients(float b0, float b1, float b2, float a1, float a2)
{
    _b0 = b0;
    _b1 = b1;
    _b2 = b2;
    _a1 = a1;
    _a2 = a2;
}

void BiquadFilter::configure(const EqBand& band, float sample_rate)
{
    // All formulae from the RBJ Audio EQ Cookbook by Robert Bristow-Johnson.
    // https://www.w3.org/TR/audio-eq-cookbook/

    const float A       = std::pow(10.0f, band.gain_db / 40.0f);
    const float w0      = 2.0f * static_cast<float>(M_PI) * band.freq_hz / sample_rate;
    const float cos_w0  = std::cos(w0);
    const float sin_w0  = std::sin(w0);
    const float alpha   = sin_w0 / (2.0f * band.q);

    float b0, b1, b2, a0, a1, a2;

    switch (band.type)
    {
    case EqBand::Type::Peak:
        b0 =  1.0f + alpha * A;
        b1 = -2.0f * cos_w0;
        b2 =  1.0f - alpha * A;
        a0 =  1.0f + alpha / A;
        a1 = -2.0f * cos_w0;
        a2 =  1.0f - alpha / A;
        break;

    case EqBand::Type::LowShelf:
    {
        const float two_sqrt_A_alpha = 2.0f * std::sqrt(A) * alpha;
        b0 =      A * ((A + 1.0f) - (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        b1 = 2.0f*A * ((A - 1.0f) - (A + 1.0f) * cos_w0                   );
        b2 =      A * ((A + 1.0f) - (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        a0 =          ((A + 1.0f) + (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        a1 =   -2.0f * ((A - 1.0f) + (A + 1.0f) * cos_w0                  );
        a2 =          ((A + 1.0f) + (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        break;
    }

    case EqBand::Type::HighShelf:
    {
        const float two_sqrt_A_alpha = 2.0f * std::sqrt(A) * alpha;
        b0 =      A * ((A + 1.0f) + (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        b1 =-2.0f*A * ((A - 1.0f) + (A + 1.0f) * cos_w0                   );
        b2 =      A * ((A + 1.0f) + (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        a0 =          ((A + 1.0f) - (A - 1.0f) * cos_w0 + two_sqrt_A_alpha);
        a1 =    2.0f * ((A - 1.0f) - (A + 1.0f) * cos_w0                  );
        a2 =          ((A + 1.0f) - (A - 1.0f) * cos_w0 - two_sqrt_A_alpha);
        break;
    }

    case EqBand::Type::LowPass:
        b0 = (1.0f - cos_w0) / 2.0f;
        b1 =  1.0f - cos_w0;
        b2 = (1.0f - cos_w0) / 2.0f;
        a0 =  1.0f + alpha;
        a1 = -2.0f * cos_w0;
        a2 =  1.0f - alpha;
        break;

    case EqBand::Type::HighPass:
        b0 =  (1.0f + cos_w0) / 2.0f;
        b1 = -(1.0f + cos_w0);
        b2 =  (1.0f + cos_w0) / 2.0f;
        a0 =  1.0f + alpha;
        a1 = -2.0f * cos_w0;
        a2 =  1.0f - alpha;
        break;

    default:
        // Unity gain passthrough if type is unrecognised.
        set_coefficients(1.0f, 0.0f, 0.0f, 0.0f, 0.0f);
        return;
    }

    // Normalise all coefficients by a0 so the feedback path has unity a0.
    set_coefficients(b0 / a0, b1 / a0, b2 / a0, a1 / a0, a2 / a0);
}

void BiquadFilter::process(float* samples, int n_frames)
{
    // Direct Form I.  For each frame, process the left channel (index 0)
    // and the right channel (index 1) independently.
    for (int frame = 0; frame < n_frames; ++frame)
    {
        for (int ch = 0; ch < 2; ++ch)
        {
            float x = samples[frame * 2 + ch];
            float y = _b0 * x
                    + _b1 * _x1[ch]
                    + _b2 * _x2[ch]
                    - _a1 * _y1[ch]
                    - _a2 * _y2[ch];

            _x2[ch] = _x1[ch];
            _x1[ch] = x;
            _y2[ch] = _y1[ch];
            _y1[ch] = y;

            samples[frame * 2 + ch] = y;
        }
    }
}

void BiquadFilter::reset()
{
    _x1[0] = _x1[1] = 0.0f;
    _x2[0] = _x2[1] = 0.0f;
    _y1[0] = _y1[1] = 0.0f;
    _y2[0] = _y2[1] = 0.0f;
}


// =============================================================================
// EqChain
// =============================================================================

EqChain::EqChain()
    : _bands(std::make_shared<const std::vector<EqBand>>())
{
}

void EqChain::set_bands(const std::vector<EqBand>& bands, float sample_rate)
{
    // Build the new immutable band list outside the mutex so the lock hold is
    // as short as possible.
    auto new_bands = std::make_shared<const std::vector<EqBand>>(bands);

    std::lock_guard<std::mutex> lock(_mutex);
    _bands       = std::move(new_bands);
    _sample_rate = sample_rate;
}

std::shared_ptr<const std::vector<EqBand>> EqChain::get_bands() const
{
    // Return a copy of the shared_ptr; the refcount increment is the only
    // work done under the mutex.
    std::lock_guard<std::mutex> lock(_mutex);
    return _bands;
}

float EqChain::sample_rate() const
{
    std::lock_guard<std::mutex> lock(_mutex);
    return _sample_rate;
}


// =============================================================================
// RateEstimator
// =============================================================================

RateEstimator::RateEstimator()
    : _input_rate(48000)
    , _output_rate(44100)
    , _smoothed_rate(48000.0)
    , _window_start_time(0.0)
    , _window_frame_count(0)
    , _initialised(false)
    , _adjustment_count(0)
    , _published_ratio(44100.0 / 48000.0)
    , _published_rate(48000.0)
{
}

void RateEstimator::reset(int input_rate, int output_rate)
{
    // Called from the capture thread only — plain writes to capture-only fields.
    _input_rate         = input_rate;
    _output_rate        = output_rate;
    _smoothed_rate      = static_cast<double>(input_rate);
    _window_start_time  = 0.0;
    _window_frame_count = 0;
    _initialised        = false;
    _adjustment_count   = 0;

    // Publish safe initial values so any thread that reads before the first
    // measurement window completes gets a sensible initial ratio.
    double initial_ratio = (input_rate > 0)
                           ? static_cast<double>(output_rate) / static_cast<double>(input_rate)
                           : 1.0;
    _published_ratio.store(initial_ratio, std::memory_order_relaxed);
    _published_rate.store(static_cast<double>(input_rate), std::memory_order_relaxed);
}

void RateEstimator::feed(int n_frames, double wall_time)
{
    // This method is called only from the capture thread.
    // All reads and writes to _smoothed_rate, _window_* and _initialised are
    // safe without locks.  Only the final atomic stores cross thread boundaries.

    if (!_initialised)
    {
        _window_start_time  = wall_time;
        _window_frame_count = 0;
        _initialised        = true;
        return;
    }

    _window_frame_count += n_frames;

    // Ramp the window duration from 1 s up to WINDOW_SECONDS over the first
    // WINDOW_SECONDS completed windows (i.e. 1 s, 2 s, … 10 s).  This lets
    // the first SRC ratio correction arrive after just one second rather than
    // ten, while the longer steady-state windows keep ratio changes smooth.
    double current_window = std::min(
        static_cast<double>(_adjustment_count + 1),
        WINDOW_SECONDS);

    double elapsed = wall_time - _window_start_time;
    if (elapsed < current_window)
        return;

    // We have a full window of data.  Compute the measured rate and blend
    // it into the running IIR-smoothed estimate.
    double measured_rate = static_cast<double>(_window_frame_count) / elapsed;

    // Sanity-check: reject measurements that are implausibly far from the
    // initial input rate (e.g. if the process was suspended, elapsed could be
    // very large).
    double deviation = std::abs(measured_rate - static_cast<double>(_input_rate))
                       / static_cast<double>(_input_rate);
    if (deviation < 0.05)  // within ±5% of nominal
    {
        _smoothed_rate = ALPHA * measured_rate + (1.0 - ALPHA) * _smoothed_rate;
    }

    // Advance the ramp counter (saturates at WINDOW_SECONDS so the cast is safe).
    if (_adjustment_count < static_cast<int>(WINDOW_SECONDS))
        ++_adjustment_count;

    // Reset the window for the next measurement period.
    _window_start_time  = wall_time;
    _window_frame_count = 0;

    // Publish the updated values so other threads can read them safely.
    // memory_order_relaxed is sufficient: there is no ordering dependency
    // between these two stores and any other shared state.
    double new_ratio = (_smoothed_rate > 0.0)
                       ? static_cast<double>(_output_rate) / _smoothed_rate
                       : 1.0;
    _published_ratio.store(new_ratio,      std::memory_order_relaxed);
    _published_rate.store(_smoothed_rate,  std::memory_order_relaxed);
}

double RateEstimator::src_ratio() const
{
    return _published_ratio.load(std::memory_order_relaxed);
}

double RateEstimator::estimated_input_rate() const
{
    return _published_rate.load(std::memory_order_relaxed);
}


// =============================================================================
// AlsaCapture
// =============================================================================

static constexpr unsigned int AUTO_CAPTURE_RATE_MAX_HZ = 48000;

AlsaCapture::AlsaCapture() = default;

AlsaCapture::~AlsaCapture()
{
    close();
}

bool AlsaCapture::open(const std::string& hw_device, int channels)
{
    if (_pcm)
    {
        LOG_WARN("[alsa] open() called while device already open; closing first");
        close();
    }

    int err;

    err = snd_pcm_open(&_pcm, hw_device.c_str(), SND_PCM_STREAM_CAPTURE, 0);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot open device '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        _pcm = nullptr;
        return false;
    }

    // Allocate hardware parameter space on the stack.
    snd_pcm_hw_params_t* hw_params = nullptr;
    snd_pcm_hw_params_alloca(&hw_params);

    int selected_rate_hz = 0;

    err = snd_pcm_hw_params_any(_pcm, hw_params);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot initialise hw_params for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    err = snd_pcm_hw_params_set_access(_pcm, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot set interleaved access for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    err = snd_pcm_hw_params_set_format(_pcm, hw_params, SND_PCM_FORMAT_S16_LE);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot set S16_LE format for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    err = snd_pcm_hw_params_set_channels(_pcm, hw_params,
                                          static_cast<unsigned int>(channels));
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot set %d channels for '%s': %s",
                 channels, hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    {
        unsigned int rate_max = AUTO_CAPTURE_RATE_MAX_HZ;
        int          dir      = 0;

        // Constrain capture to rates at or below the product ceiling, then
        // choose the highest rate ALSA can satisfy within that range.
        err = snd_pcm_hw_params_set_rate_max(_pcm, hw_params, &rate_max, &dir);
        if (err < 0)
        {
            LOG_WARN("[alsa] No supported capture rate <= %u Hz for '%s'",
                     AUTO_CAPTURE_RATE_MAX_HZ, hw_device.c_str());
            goto fail;
        }

        unsigned int selected_rate = rate_max;
        dir = -1;
        err = snd_pcm_hw_params_set_rate_near(_pcm, hw_params, &selected_rate, &dir);
        if (err < 0)
        {
            LOG_WARN("[alsa] Cannot select capture rate <= %u Hz for '%s': %s",
                     AUTO_CAPTURE_RATE_MAX_HZ, hw_device.c_str(), snd_strerror(err));
            goto fail;
        }

        selected_rate_hz = static_cast<int>(selected_rate);
        _actual_rate     = selected_rate_hz;

        if (_actual_rate <= 0 || _actual_rate > static_cast<int>(AUTO_CAPTURE_RATE_MAX_HZ))
        {
            LOG_WARN("[alsa] Invalid selected capture rate %d Hz for '%s'",
                     _actual_rate, hw_device.c_str());
            goto fail;
        }
    }

    {
        // Request a ~1024-frame period.  This gives ~21 ms latency at 48 kHz
        // which is a good balance between CPU overhead and responsiveness.
        snd_pcm_uframes_t period = 1024;
        err = snd_pcm_hw_params_set_period_size_near(_pcm, hw_params, &period, nullptr);
        if (err < 0)
        {
            LOG_WARN("[alsa] Cannot set period size for '%s': %s",
                     hw_device.c_str(), snd_strerror(err));
            goto fail;
        }
        _period_frames = static_cast<int>(period);
    }

    err = snd_pcm_hw_params(_pcm, hw_params);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot apply hw_params for '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    err = snd_pcm_prepare(_pcm);
    if (err < 0)
    {
        LOG_WARN("[alsa] Cannot prepare '%s': %s",
                 hw_device.c_str(), snd_strerror(err));
        goto fail;
    }

    LOG_INFO("[alsa] Opened '%s': selected=%d Hz, negotiated=%d Hz, %d ch, period=%d frames",
             hw_device.c_str(), selected_rate_hz, _actual_rate, channels, _period_frames);
    return true;

fail:
    snd_pcm_close(_pcm);
    _pcm = nullptr;
    _period_frames = 0;
    _actual_rate   = 0;
    return false;
}

void AlsaCapture::close()
{
    // Hold _read_mutex so that close() cannot run concurrently with the
    // body of read() (between the _pcm null-check and snd_pcm_readi).
    // If a read is in progress, close() waits for it to finish (at most one
    // hardware period, ~21 ms) before setting _pcm = nullptr.
    std::lock_guard<std::mutex> lock(_read_mutex);
    if (_pcm)
    {
        snd_pcm_close(_pcm);
        _pcm = nullptr;
    }
    _period_frames = 0;
    _actual_rate   = 0;
}

int AlsaCapture::read(int16_t* buf, int n_frames)
{
    // Hold _read_mutex for the duration of the check + snd_pcm_readi call.
    // This prevents close() from setting _pcm = nullptr between the guard
    // and the actual use of _pcm.  The lock is uncontended in normal
    // operation (only the capture thread calls read()), so the overhead
    // is negligible.
    std::lock_guard<std::mutex> lock(_read_mutex);

    if (!_pcm)
        return -1;

    snd_pcm_sframes_t frames_read = snd_pcm_readi(_pcm, buf, n_frames);

    if (frames_read >= 0)
        return static_cast<int>(frames_read);

    // Handle recoverable errors (xrun, suspended).
    int err = snd_pcm_recover(_pcm, static_cast<int>(frames_read),
                               /*silent=*/1);
    if (err == 0)
    {
        // Recovered from xrun; the caller should retry rather than treating
        // the zero return as silence.
        return 0;
    }

    LOG_WARN("[alsa] Unrecoverable read error: %s", snd_strerror(err));
    return -1;
}

bool AlsaCapture::is_open() const
{
    std::lock_guard<std::mutex> lock(_read_mutex);
    return _pcm != nullptr;
}

int AlsaCapture::period_frames() const
{
    std::lock_guard<std::mutex> lock(_read_mutex);
    return _period_frames;
}

int AlsaCapture::actual_rate() const
{
    std::lock_guard<std::mutex> lock(_read_mutex);
    return _actual_rate;
}


// =============================================================================
// FifoWriter
// =============================================================================

FifoWriter::FifoWriter() = default;

FifoWriter::~FifoWriter()
{
    close();
}

void FifoWriter::set_path(const std::string& path)
{
    close();
    _path = path;
}

bool FifoWriter::try_open()
{
    if (_path.empty())
        return false;

    // O_NONBLOCK is kept permanently on the fd (never cleared).  This means:
    //   - If OwnTone has not opened its read end yet, open() returns ENXIO and
    //     we return false silently; the caller retries on the next block.
    //   - Once open, if the pipe buffer is full, write() returns EAGAIN rather
    //     than blocking the process thread indefinitely.
    int fd = ::open(_path.c_str(), O_WRONLY | O_NONBLOCK);
    if (fd < 0)
    {
        if (errno != ENXIO && errno != ENOENT)
        {
            LOG_WARN("[fifo] Cannot open '%s': %s",
                     _path.c_str(), strerror(errno));
        }
        return false;
    }

    // Verify the path is actually a named pipe.  O_NONBLOCK lets us open a
    // regular file without blocking, so we must reject it here before we
    // start writing raw PCM into it and silently fill the disk.
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISFIFO(st.st_mode))
    {
        LOG_WARN("[fifo] '%s' is not a named pipe; rejecting", _path.c_str());
        ::close(fd);
        return false;
    }

    _fd = fd;
    LOG_INFO("[fifo] Opened '%s' for writing", _path.c_str());
    return true;
}

bool FifoWriter::write(const void* data, size_t len)
{
    if (_fd < 0)
    {
        // Not yet open — try to open now.  If this fails (OwnTone not ready),
        // silently discard the data and wait for the next call.
        if (!try_open())
            return false;
    }

    const char* ptr     = static_cast<const char*>(data);
    size_t      written = 0;

    while (written < len)
    {
        ssize_t n = ::write(_fd, ptr + written, len - written);
        if (n > 0)
        {
            written += static_cast<size_t>(n);
        }
        else if (n == 0)
        {
            break;
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                if (written > 0)
                {
                    // A partial block was already written before the pipe
                    // buffer filled.  The PCM frame boundary is now lost.
                    // Close the fd so the next write() call reopens it from
                    // the beginning, giving OwnTone a chance to re-sync.
                    LOG_WARN("[fifo] Partial write on '%s' (%zu/%zu bytes); closing to re-sync stream",
                             _path.c_str(), written, len);
                    close();
                }
                else
                {
                    // Pipe buffer full before any bytes written — safe to
                    // drop the whole block.  Throttle to once per 5 seconds.
                    double now = get_monotonic_time();
                    if (now - _stall_last_log_time >= 5.0)
                    {
                        LOG_WARN("[fifo] Pipe buffer full on '%s'; dropping block",
                                 _path.c_str());
                        _stall_last_log_time = now;
                    }
                }
                return false;
            }
            else if (errno == EPIPE || errno == EBADF)
            {
                // OwnTone has closed its read end.  Close our fd so try_open()
                // will reopen it on the next write attempt.
                LOG_WARN("[fifo] Broken pipe on '%s'; will reopen on next write",
                         _path.c_str());
                close();
            }
            else
            {
                LOG_WARN("[fifo] Write error on '%s': %s",
                         _path.c_str(), strerror(errno));
            }
            return false;
        }
    }

    return written == len;
}

void FifoWriter::close()
{
    if (_fd >= 0)
    {
        ::close(_fd);
        _fd = -1;
    }
}


// =============================================================================
// InputChannel
// =============================================================================

InputChannel::InputChannel(int         index,
                           FifoWriter& shared_fifo,
                           std::mutex& fifo_mutex)
    : _index(index)
    , _shared_fifo(shared_fifo)
    , _fifo_mutex(fifo_mutex)
    , _ring_buf(RING_BUF_SAMPLES, 0)
{
    _status.index = index;
}

InputChannel::~InputChannel()
{
    stop();
}

// Convert a dBFS threshold to the equivalent integer sample amplitude (0..32767).
// Computed once at configure() time so the hot path can use a plain integer compare.
static int dbfs_to_sample_threshold(float dbfs)
{
    if (dbfs >= 0.0f)
        return 32767;
    float linear    = std::pow(10.0f, dbfs / 20.0f);
    int   threshold = static_cast<int>(linear * 32768.0f);
    return std::max(1, std::min(32767, threshold));
}

// Convert an integer sample amplitude back to dBFS for reporting.
// Only called from get_status() (~10 times/second), not from the hot path.
static float sample_to_dbfs(int peak)
{
    if (peak <= 0)
        return -90.0f;
    float ratio = static_cast<float>(peak) / 32768.0f;
    return std::max(-90.0f, 20.0f * std::log10(ratio));
}

// Convert a linear float peak amplitude to dBFS.
// Used for the effective peak, which lives in float domain after gain and EQ.
static float linear_to_dbfs(float peak_linear)
{
    if (peak_linear <= 0.0f)
        return -90.0f;
    return std::max(-90.0f, 20.0f * std::log10(peak_linear));
}

bool InputChannel::configure(const InputConfig& cfg)
{
    std::lock_guard<std::mutex> lock(_config_mutex);

    if (_running.load() && _config_valid)
    {
        // The channel is already running.  Changing alsa_device requires a
        // stop/start cycle because it is used only at open() time.  Reject
        // the call rather than silently ignoring part of it.
        if (cfg.alsa_device != _config.alsa_device)
        {
            LOG_WARN("[input%d] configure() rejected: stop the input before changing device",
                     _index);
            return false;
        }
    }

    _config                   = cfg;
    _config_valid             = true;
    _silence_threshold_sample.store(dbfs_to_sample_threshold(cfg.silence_threshold_dbfs),
                                    std::memory_order_relaxed);
    LOG_INFO("[input%d] Configured device='%s', silence_threshold=%.1f dBFS, silence_seconds=%d",
             _index, cfg.alsa_device.c_str(), cfg.silence_threshold_dbfs, cfg.silence_seconds);
    return true;
}

void InputChannel::set_eq(const std::vector<EqBand>& bands)
{
    // EQ operates on the resampled output, so the sample rate is always the
    // fixed output rate.  The process thread picks up the change lazily.
    _eq_chain.set_bands(bands, static_cast<float>(AudioMonitor::output_rate_hz()));
    LOG_DEBUG("[input%d] Applied %zu EQ band(s)", _index, bands.size());
}

void InputChannel::set_gain(float gain_db)
{
    // Convert once from dB to linear here so the process thread only needs
    // a single multiply per sample; no pow() on the hot path.
    float linear = std::pow(10.0f, gain_db / 20.0f);
    _gain_linear.store(linear, std::memory_order_relaxed);
    LOG_DEBUG("[input%d] Gain set to %.2f dB", _index, gain_db);
}

bool InputChannel::start(std::string* error_out)
{
    if (_running.load())
    {
        LOG_WARN("[input%d] start() called while already running", _index);
        if (error_out)
            *error_out = "input is already running";
        return false;
    }

    // Read and validate configuration under the lock.
    InputConfig cfg;
    {
        std::lock_guard<std::mutex> lock(_config_mutex);
        if (!_config_valid)
        {
            LOG_WARN("[input%d] start() called before configure()", _index);
            if (error_out)
                *error_out = "input is not configured";
            return false;
        }
        cfg = _config;
    }

    // Open the ALSA device.
    if (!_alsa.open(cfg.alsa_device, /*channels=*/2))
    {
        LOG_WARN("[input%d] Failed to open ALSA device '%s'",
                 _index, cfg.alsa_device.c_str());
        if (error_out)
            *error_out = "failed to open ALSA device";
        return false;
    }

    // Create a libsamplerate state for stereo conversion.
    // SRC_SINC_FASTEST provides good quality with moderate CPU usage.
    // On a Pi Zero, SRC_LINEAR can be substituted if CPU becomes a bottleneck.
    int src_error = 0;
    _src_state = src_new(SRC_SINC_FASTEST, /*channels=*/2, &src_error);
    if (!_src_state)
    {
        LOG_WARN("[input%d] src_new failed: %s",
                 _index, src_strerror(src_error));
        _alsa.close();
        if (error_out)
            *error_out = "failed to initialise sample-rate converter";
        return false;
    }

    // Seed the rate estimator with the rate ALSA actually negotiated rather
    // than the nominal target rate. This keeps the first plausibility check in
    // RateEstimator::feed() anchored to the real device rate.
    _rate_estimator.reset(_alsa.actual_rate(), AudioMonitor::output_rate_hz());

    // Reset silence tracking and capture-thread private state.
    _last_above_threshold_time   = 0.0;
    _ring_overflow_last_log_time = 0.0;

    // Ensure the ramp starts fresh; it will be armed when the first capture
    // session begins inside process_thread_func().
    _ramp_frames_remaining = 0;

    // Reset per-channel EQ state.  Setting _current_eq_bands to nullptr forces
    // process_thread_func() to rebuild _local_filters from scratch on the first
    // block, ensuring the new session starts with zeroed delay-line state.
    _local_filters.clear();
    _current_eq_bands.reset();

    // Reset session peak accumulators so the new session starts from scratch.
    _session_raw_peak_sample.store(0,     std::memory_order_relaxed);
    _session_effective_peak_linear.store(0.0f, std::memory_order_relaxed);

    // Clear ring buffer.
    _ring_write_pos.store(0, std::memory_order_relaxed);
    _ring_read_pos.store(0,  std::memory_order_relaxed);

    // Allocate and reset the identification snapshot buffer.
    // Done here rather than in the constructor so the ~1 MB allocation only
    // happens if the channel is ever started.
    {
        std::lock_guard<std::mutex> lock(_id_mutex);
        if (_id_buf.empty())
            _id_buf.resize(ID_BUF_FRAMES);
        _id_write_pos    = 0;
        _id_frames_avail = 0;
    }

    // Set _started before spawning threads.  stop() guards on
    // _started.exchange(false), so setting it first ensures that any
    // concurrent stop() call after this point always performs full cleanup —
    // including joining the threads we are about to create.  If stop() wins
    // the exchange before the threads exist, the joinable() checks make the
    // joins harmless no-ops.
    _started.store(true);
    _running.store(true);

    try
    {
        _capture_thr = std::thread(&InputChannel::capture_thread_func, this);
        _process_thr = std::thread(&InputChannel::process_thread_func, this);
    }
    catch (const std::system_error& e)
    {
        // Thread creation failed (e.g. EAGAIN under resource pressure).
        // Signal any thread that did start to exit, join it, then undo the
        // flags so the channel is left in a clean stopped state.
        _running.store(false);
        _alsa.close();              // unblocks a blocked snd_pcm_readi()
        if (_capture_thr.joinable())
            _capture_thr.join();
        // _process_thr is not joinable if its construction was what threw.
        if (_src_state)
        {
            src_delete(_src_state);
            _src_state = nullptr;
        }
        _started.store(false);
        LOG_WARN("[input%d] Thread creation failed: %s", _index, e.what());
        if (error_out)
            *error_out = std::string("thread creation failed: ") + e.what();
        return false;
    }

    LOG_INFO("[input%d] Started on device '%s' at %d Hz (auto-selected <= %u Hz)",
             _index, cfg.alsa_device.c_str(), _alsa.actual_rate(), AUTO_CAPTURE_RATE_MAX_HZ);
    return true;
}

void InputChannel::stop()
{
    // Guard on _started, not _running.  The capture thread may have already
    // stored _running = false (after an unrecoverable ALSA error) and exited,
    // leaving _capture_thr and _process_thr joinable and _src_state allocated.
    // Using _started.exchange(false) ensures stop() runs exactly once and
    // always performs the full cleanup regardless of how _running got cleared.
    if (!_started.exchange(false))
        return;

    // Signal the process thread to exit (the capture thread may have already
    // cleared this after an ALSA error, but a redundant store is harmless).
    _running.store(false);

    // Wake the process thread immediately so it does not wait out its condvar
    // timeout after _running is cleared.
    _ring_cv.notify_all();

    // Close the ALSA device to unblock any snd_pcm_readi() in progress.
    // AlsaCapture::close() holds _read_mutex, so it either runs before the
    // next read() call or waits for the current one to finish (at most ~21 ms).
    _alsa.close();

    if (_capture_thr.joinable())
        _capture_thr.join();
    if (_process_thr.joinable())
        _process_thr.join();

    if (_src_state)
    {
        src_delete(_src_state);
        _src_state = nullptr;
    }

    _capturing.store(false);
    _current_peak_sample.store(0, std::memory_order_relaxed);
    _session_raw_peak_sample.store(0, std::memory_order_relaxed);
    _session_effective_peak_linear.store(0.0f, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lock(_status_mutex);
        _status.is_silent    = true;
        _status.is_capturing = false;
        _status.detected_hz  = 0.0;
    }

    // Do NOT reset _id_write_pos or _id_frames_avail here.  The snapshot
    // buffer retains the final audio so a get_id_snapshot request issued
    // immediately after stop() still returns valid data.  start() resets
    // both counters to 0 before the next capture session begins.

    LOG_INFO("[input%d] Stopped", _index);
}

void InputChannel::set_allow_capture(bool allow)
{
    _allow_capture.store(allow);
    LOG_DEBUG("[input%d] allow_capture=%s", _index, allow ? "true" : "false");
}

InputChannelStatus InputChannel::get_status() const
{
    // All log10 conversions happen here, not in the hot path.
    // get_status() is called ~10 times/second so the cost is negligible.
    InputChannelStatus s;
    {
        std::lock_guard<std::mutex> lock(_status_mutex);
        s = _status;
    }
    s.level_dbfs             = sample_to_dbfs(_current_peak_sample.load(std::memory_order_relaxed));
    s.raw_peak_dbfs          = sample_to_dbfs(_session_raw_peak_sample.load(std::memory_order_relaxed));
    s.effective_peak_dbfs    = linear_to_dbfs(_session_effective_peak_linear.load(std::memory_order_relaxed));
    s.is_started             = _started.load(std::memory_order_relaxed);
    s.is_running             = _running.load(std::memory_order_relaxed);
    return s;
}

int InputChannel::compute_peak_sample(const int16_t* samples,
                                       int            n_frames,
                                       int            n_channels) const
{
    // Pure integer scan — no float arithmetic.
    int peak = 0;
    for (int frame = 0; frame < n_frames; ++frame)
    {
        for (int ch = 0; ch < n_channels; ++ch)
        {
            int sample     = samples[frame * n_channels + ch];
            int abs_sample = (sample < 0) ? -sample : sample;
            if (abs_sample > peak)
                peak = abs_sample;
        }
    }
    return peak;
}

unsigned InputChannel::get_id_snapshot(int16_t* out, unsigned max_frames) const
{
    std::lock_guard<std::mutex> lock(_id_mutex);

    if (_id_buf.empty())
        return 0;

    unsigned avail = std::min(_id_frames_avail, max_frames);
    if (avail == 0)
        return 0;

    // The most recent `avail` frames end at _id_write_pos.
    // Walking backwards: start = (_id_write_pos - avail), masked.
    unsigned start  = (_id_write_pos - avail) & ID_BUF_MASK;
    unsigned to_end = ID_BUF_FRAMES - start;

    if (avail <= to_end)
    {
        memcpy(out, _id_buf.data() + start, avail * sizeof(int16_t));
    }
    else
    {
        // Copy wraps around the end of the circular buffer.
        memcpy(out,           _id_buf.data() + start, to_end           * sizeof(int16_t));
        memcpy(out + to_end,  _id_buf.data(),          (avail - to_end) * sizeof(int16_t));
    }

    return avail;
}


// ── Capture thread ────────────────────────────────────────────────────────────
//
// Reads hardware periods from ALSA and writes interleaved int16 stereo samples
// into the ring buffer.  This thread runs at close to real time and should do
// as little work as possible to avoid causing ALSA xruns.
//
void InputChannel::capture_thread_func()
{
    // Size the local read buffer to one hardware period.
    // We re-read the period size after open; it will not change during a session.
    std::vector<int16_t> period_buf;

    while (_running.load(std::memory_order_relaxed))
    {
        if (!_alsa.is_open())
        {
            // The ALSA device was closed (probably by stop()).
            break;
        }

        // Ensure the buffer is sized to the negotiated period.
        int period = _alsa.period_frames();
        if (period <= 0)
            break;

        if (static_cast<int>(period_buf.size()) != period * 2)
            period_buf.resize(period * 2);

        int frames_read = _alsa.read(period_buf.data(), period);

        if (frames_read < 0)
        {
            // Unrecoverable ALSA error; stop the capture session.
            LOG_WARN("[input%d] ALSA read error; stopping capture thread", _index);
            _running.store(false);
            break;
        }

        if (frames_read == 0)
        {
            // Recovered from xrun; skip this period to let the hardware re-sync.
            continue;
        }

        int samples_to_write = frames_read * 2;  // stereo

        // Check that there is space in the ring buffer.  If the process thread
        // is falling behind, we drop the oldest data (overwrite) rather than
        // blocking, which would cause an ALSA xrun.
        unsigned write_pos = _ring_write_pos.load(std::memory_order_relaxed);
        unsigned read_pos  = _ring_read_pos.load(std::memory_order_acquire);
        unsigned used      = write_pos - read_pos;   // unsigned subtraction wraps correctly
        unsigned free      = RING_BUF_SAMPLES - used;

        if (static_cast<unsigned>(samples_to_write) > free)
        {
            // Ring buffer is full — the process thread is falling behind.
            // Drop this incoming period rather than advancing _ring_read_pos
            // from the capture thread.  _ring_read_pos must only be written
            // by the process thread to preserve the SPSC invariant; the
            // capture thread writing it (even atomically) can race with the
            // process thread's store and silently corrupt the read position.
            // Throttle the log to once every 5 seconds to avoid log spam
            // under sustained CPU load.
            {
                double now = get_monotonic_time();
                if (now - _ring_overflow_last_log_time >= 5.0)
                {
                    LOG_WARN("[input%d] Ring buffer full; dropping periods", _index);
                    _ring_overflow_last_log_time = now;
                }
            }
            continue;
        }

        // Write samples into the ring buffer, handling wrap-around with two copies.
        unsigned write_idx     = write_pos & RING_BUF_MASK;
        unsigned to_end        = RING_BUF_SAMPLES - write_idx;
        unsigned first_chunk   = std::min(static_cast<unsigned>(samples_to_write), to_end);
        unsigned second_chunk  = static_cast<unsigned>(samples_to_write) - first_chunk;

        memcpy(&_ring_buf[write_idx],
               period_buf.data(),
               first_chunk * sizeof(int16_t));

        if (second_chunk > 0)
        {
            memcpy(&_ring_buf[0],
                   period_buf.data() + first_chunk,
                   second_chunk * sizeof(int16_t));
        }

        // Update write position — this is the release point for the process thread.
        _ring_write_pos.fetch_add(static_cast<unsigned>(samples_to_write),
                                   std::memory_order_release);

        // Wake the process thread if it is waiting for data.  notify_one() is
        // called without holding _ring_cv_mutex; this is safe — if the process
        // thread is between its availability check and its wait_for call, the
        // predicate will find enough data on the next evaluation.
        _ring_cv.notify_one();

        // Feed the rate estimator now, while we know exactly how many frames
        // the hardware delivered and at what wall-clock time.
        _rate_estimator.feed(frames_read, get_monotonic_time());
    }
}

// ── Process thread ────────────────────────────────────────────────────────────
//
// Drains the ring buffer, measures the audio level, runs the silence state
// machine, and when capturing is active: resamples via libsamplerate, applies
// the EQ chain, and writes the result to the shared FIFO.
//
void InputChannel::process_thread_func()
{
    // Pre-allocate processing buffers.  Avoid heap allocation on the hot path.
    const int MAX_FRAMES          = 2048;   // maximum input frames per loop iteration
    const int MAX_SRC_OUTPUT      = 4096;   // maximum output frames from libsamplerate

    // Duration of the fade-in ramp in output frames (one second at 44100 Hz).
    const int RAMP_DURATION_FRAMES = AudioMonitor::output_rate_hz();

    // Number of output frames to accumulate before the first FIFO write.
    // 0.5 s at 44100 Hz = 22050 frames = ~172 KB of int16 stereo data.
    // This gives OwnTone a full initial buffer so it can start streaming
    // without the starvation-induced skips that occur when the pipe is
    // cold and the first few writes are each only a single period (~1024 frames).
    const int PREFILL_DURATION_FRAMES = AudioMonitor::output_rate_hz() / 2;

    std::vector<int16_t> pcm_in(MAX_FRAMES * 2);          // interleaved int16
    std::vector<float>   float_in(MAX_FRAMES * 2);        // interleaved float
    std::vector<float>   float_out(MAX_SRC_OUTPUT * 2);   // post-SRC float
    std::vector<int16_t> pcm_out(MAX_SRC_OUTPUT * 2);     // final int16
    std::vector<int16_t> id_tmp(MAX_SRC_OUTPUT / 2);      // mono ID frames (pre-gain/EQ tap)

    // Minimum number of samples to accumulate before processing.
    // 512 samples = 256 stereo frames = ~5 ms at 48 kHz.
    const unsigned MIN_SAMPLES = 512;

    while (_running.load(std::memory_order_relaxed))
    {
        // ── Wait for data ────────────────────────────────────────────────────
        unsigned write_pos = _ring_write_pos.load(std::memory_order_acquire);
        unsigned read_pos  = _ring_read_pos.load(std::memory_order_relaxed);
        unsigned available = write_pos - read_pos;

        if (available < MIN_SAMPLES)
        {
            // Sleep until the capture thread signals new data or up to 5 ms
            // (the timeout handles the case where notify_one() was called just
            // before we entered wait_for — at most one missed notification).
            std::unique_lock<std::mutex> lk(_ring_cv_mutex);
            _ring_cv.wait_for(lk, std::chrono::milliseconds(5),
                [this, MIN_SAMPLES]()
                {
                    return !_running.load(std::memory_order_relaxed) ||
                           (_ring_write_pos.load(std::memory_order_acquire) -
                            _ring_read_pos.load(std::memory_order_relaxed)) >= MIN_SAMPLES;
                });
            continue;
        }

        // ── Copy a block from the ring buffer ────────────────────────────────
        unsigned samples_to_read = std::min(available,
                                             static_cast<unsigned>(MAX_FRAMES * 2));
        samples_to_read &= ~1u;  // ensure we read complete stereo frames

        unsigned read_idx   = read_pos & RING_BUF_MASK;
        unsigned to_end     = RING_BUF_SAMPLES - read_idx;
        unsigned first_chunk  = std::min(samples_to_read, to_end);
        unsigned second_chunk = samples_to_read - first_chunk;

        memcpy(pcm_in.data(),
               &_ring_buf[read_idx],
               first_chunk * sizeof(int16_t));

        if (second_chunk > 0)
        {
            memcpy(pcm_in.data() + first_chunk,
                   &_ring_buf[0],
                   second_chunk * sizeof(int16_t));
        }

        // Advance the read position to release space for the capture thread.
        _ring_read_pos.store(read_pos + samples_to_read, std::memory_order_release);

        int frames_in = static_cast<int>(samples_to_read / 2);

        // ── Compute peak sample level (pure integer, no float) ───────────────
        int peak_sample = compute_peak_sample(pcm_in.data(), frames_in, /*channels=*/2);
        _current_peak_sample.store(peak_sample, std::memory_order_relaxed);

        // Accumulate session raw peak (no float / log10 — integer compare only).
        {
            int prev = _session_raw_peak_sample.load(std::memory_order_relaxed);
            if (peak_sample > prev)
                _session_raw_peak_sample.store(peak_sample, std::memory_order_relaxed);
        }

        // ── Silence state machine ─────────────────────────────────────────────
        double now = get_monotonic_time();

        // _silence_threshold_sample is published atomically by configure(), so
        // we only need to lock here to read silence_seconds.
        int silence_seconds;
        {
            std::lock_guard<std::mutex> lock(_config_mutex);
            silence_seconds = _config.silence_seconds;
        }
        int silence_threshold_sample = _silence_threshold_sample.load(std::memory_order_relaxed);

        // Integer comparison — no float arithmetic on the hot path.
        if (peak_sample >= silence_threshold_sample)
            _last_above_threshold_time = now;

        bool is_above_threshold = (_last_above_threshold_time > 0.0)
                               && ((now - _last_above_threshold_time)
                                   < static_cast<double>(silence_seconds));

        bool should_capture = is_above_threshold
                           && _allow_capture.load(std::memory_order_relaxed);

        // ── Start or stop the capture session ────────────────────────────────
        if (should_capture && !_capturing.load())
        {
            if (_src_state)
                src_reset(_src_state);
            _ramp_frames_remaining    = RAMP_DURATION_FRAMES;
            _prefill_frames_remaining = PREFILL_DURATION_FRAMES;
            _prefill_buf.clear();
            _prefill_buf.reserve(static_cast<size_t>(PREFILL_DURATION_FRAMES) * 2);
            _capturing.store(true);
            LOG_INFO("[input%d] Capture session started (peak=%d, threshold=%d)",
                     _index, peak_sample, silence_threshold_sample);
        }
        else if (!should_capture && _capturing.load())
        {
            _capturing.store(false);
            LOG_INFO("[input%d] Capture session stopped (silence=%.1f s)",
                     _index, now - _last_above_threshold_time);
        }

        // ── Feed through SRC → EQ → FIFO when capturing ──────────────────────
        if (_capturing.load() && _src_state)
        {
            // Convert int16 to float in the range [-1.0, +1.0].
            src_short_to_float_array(pcm_in.data(), float_in.data(), frames_in * 2);

            // Resample in a loop.  libsamplerate may not consume all input frames
            // in a single call if the output buffer would overflow (this can happen
            // with high upsampling ratios, e.g. 8 kHz input → 44.1 kHz output).
            // We iterate until all input frames are consumed, writing each chunk
            // to the FIFO as it is produced.  src_ratio is read once per block
            // so it is consistent across all iterations.
            const float* in_ptr      = float_in.data();
            int          frames_left = frames_in;
            const double ratio       = _rate_estimator.src_ratio();

            while (frames_left > 0)
            {
            SRC_DATA src_data;
            memset(&src_data, 0, sizeof(src_data));
            src_data.data_in       = in_ptr;
            src_data.input_frames  = frames_left;
            src_data.data_out      = float_out.data();
            src_data.output_frames = MAX_SRC_OUTPUT;
            src_data.src_ratio     = ratio;
            src_data.end_of_input  = 0;

            int src_err = src_process(_src_state, &src_data);
            if (src_err != 0)
            {
                LOG_WARN("[input%d] libsamplerate error: %s",
                         _index, src_strerror(src_err));
                break;
            }

            in_ptr      += src_data.input_frames_used * 2;  // stereo
            frames_left -= static_cast<int>(src_data.input_frames_used);

            if (src_data.output_frames_gen <= 0)
                continue;   // no output this iteration; keep consuming input

            {
                int out_frames = static_cast<int>(src_data.output_frames_gen);

                // ── ID snapshot tap (post-SRC, pre-gain, pre-EQ) ─────────
                // Tap here to capture uncolored audio: gain and EQ reflect
                // user preference and would skew frequency-domain fingerprints.
                // Downsample 44100 Hz stereo → 22050 Hz mono:
                //   - Take every other frame (2:1 decimation; no anti-aliasing
                //     filter needed — fingerprint content is ≤ 5 kHz, well
                //     below the 11025 Hz Nyquist of the tap output rate).
                //   - Average L+R channels to produce a mono signal.
                // Written under _id_mutex (held for microseconds); the control
                // thread holds _id_mutex only during an explicit snapshot
                // request, so contention is negligible.
                if (!_id_buf.empty())
                {
                    int id_count = out_frames / 2;
                    for (int i = 0; i < id_count; ++i)
                    {
                        float L    = float_out[i * 4];      // frame i*2, left channel
                        float R    = float_out[i * 4 + 1];  // frame i*2, right channel
                        float mono = (L + R) * 0.5f;
                        // Clamp before int16 conversion to guard against any
                        // marginal SRC overshoot.
                        if (mono >  1.0f) mono =  1.0f;
                        if (mono < -1.0f) mono = -1.0f;
                        id_tmp[i] = static_cast<int16_t>(mono * 32767.0f);
                    }
                    if (id_count > 0)
                    {
                        std::lock_guard<std::mutex> id_lock(_id_mutex);
                        unsigned wp = _id_write_pos;
                        for (int i = 0; i < id_count; ++i)
                            _id_buf[(wp + static_cast<unsigned>(i)) & ID_BUF_MASK] = id_tmp[i];
                        _id_write_pos     = wp + static_cast<unsigned>(id_count);
                        _id_frames_avail  = std::min(
                            _id_frames_avail + static_cast<unsigned>(id_count),
                            ID_BUF_FRAMES);
                    }
                }

                // ── Apply pre-amp gain and fade-in ramp ──────────────────
                // Read gain once so it is consistent across the block.
                // memory_order_relaxed is fine: a one-block lag is imperceptible.
                float gain = _gain_linear.load(std::memory_order_relaxed);

                if (_ramp_frames_remaining > 0)
                {
                    // Ramp is active.  Apply a per-frame multiplier that rises
                    // linearly from 0.0 at session start to 1.0 at ramp end,
                    // combined with _gain_linear in a single multiply per sample.
                    //
                    // ramp_pos is the frame index into the full ramp, counting
                    // from 0 (session start) to RAMP_DURATION_FRAMES (ramp end).
                    // Frames within this block that fall inside the ramp use the
                    // interpolated gain; any frames after the ramp completes
                    // within the same block receive the full gain.
                    int frames_in_ramp = std::min(out_frames, _ramp_frames_remaining);
                    int ramp_pos       = RAMP_DURATION_FRAMES - _ramp_frames_remaining;

                    for (int f = 0; f < frames_in_ramp; ++f)
                    {
                        float ramp_gain = gain * static_cast<float>(ramp_pos + f)
                                                / static_cast<float>(RAMP_DURATION_FRAMES);
                        float_out[f * 2]     *= ramp_gain;
                        float_out[f * 2 + 1] *= ramp_gain;
                    }
                    _ramp_frames_remaining -= frames_in_ramp;

                    // Apply uniform gain to any remaining frames in this block
                    // (those that fall after the ramp completes).
                    if (gain != 1.0f)
                    {
                        for (int f = frames_in_ramp; f < out_frames; ++f)
                        {
                            float_out[f * 2]     *= gain;
                            float_out[f * 2 + 1] *= gain;
                        }
                    }
                }
                else if (gain != 1.0f)
                {
                    // No ramp — apply uniform gain to the whole block.
                    int total_samples = out_frames * 2;
                    for (int s = 0; s < total_samples; ++s)
                        float_out[s] *= gain;
                }

                // ── Apply per-channel EQ ──────────────────────────────────
                // Check whether _eq_chain has published a new band list since
                // the last block.  If so, rebuild local filters with freshly
                // zeroed delay-line state.  The shared_ptr comparison is a
                // pointer equality check — no allocation.
                auto latest_bands = _eq_chain.get_bands();
                if (latest_bands != _current_eq_bands)
                {
                    _current_eq_bands = latest_bands;
                    _local_filters.clear();
                    if (latest_bands)
                    {
                        float sr = _eq_chain.sample_rate();
                        for (const auto& band : *latest_bands)
                        {
                            BiquadFilter f;
                            f.configure(band, sr);
                            _local_filters.push_back(f);
                        }
                    }
                }
                for (auto& filter : _local_filters)
                    filter.process(float_out.data(), out_frames);

                // ── Accumulate session effective peak ─────────────────────
                // Scan the post-gain, post-EQ float samples.  Deferred to
                // get_status() for the dBFS conversion (no log10 here).
                {
                    float eff_peak = 0.0f;
                    int total_samples = out_frames * 2;
                    for (int s = 0; s < total_samples; ++s)
                    {
                        float v = std::fabs(float_out[s]);
                        if (v > eff_peak)
                            eff_peak = v;
                    }
                    float prev = _session_effective_peak_linear.load(std::memory_order_relaxed);
                    if (eff_peak > prev)
                        _session_effective_peak_linear.store(eff_peak, std::memory_order_relaxed);
                }

                // Convert back to int16.
                src_float_to_short_array(float_out.data(), pcm_out.data(), out_frames * 2);

                // Re-check _allow_capture under _fifo_mutex.  The outer check
                // at the top of this block is an optimisation (skip SRC/EQ
                // entirely when disabled), but it is not race-free: a handoff
                // via api_set_allow_capture() could disable this input between
                // the outer check and here.  Holding _fifo_mutex for the write
                // and re-checking while holding it means the disable store is
                // either observed here and the write is skipped, or it is not
                // yet visible and the write completes before the handoff
                // enables the new input (api_set_allow_capture acquires
                // _fifo_mutex before calling ch->set_allow_capture(true)).
                {
                    std::lock_guard<std::mutex> lock(_fifo_mutex);
                    if (_allow_capture.load(std::memory_order_relaxed))
                    {
                        if (_prefill_frames_remaining > 0)
                        {
                            // Accumulation phase: append to the pre-fill buffer.
                            // Do not write to the FIFO yet.
                            const int16_t* src_ptr = pcm_out.data();
                            int to_add = std::min(out_frames, _prefill_frames_remaining);
                            _prefill_buf.insert(_prefill_buf.end(),
                                                src_ptr,
                                                src_ptr + static_cast<size_t>(to_add) * 2);
                            _prefill_frames_remaining -= to_add;

                            if (_prefill_frames_remaining == 0)
                            {
                                // Pre-fill complete: flush the whole buffer in one
                                // write, then write any frames from this block that
                                // came after the pre-fill threshold.
                                _shared_fifo.write(_prefill_buf.data(),
                                                   _prefill_buf.size() * sizeof(int16_t));
                                _prefill_buf.clear();
                                _prefill_buf.shrink_to_fit();

                                int remainder = out_frames - to_add;
                                if (remainder > 0)
                                    _shared_fifo.write(src_ptr + static_cast<size_t>(to_add) * 2,
                                                       static_cast<size_t>(remainder) * 2 * sizeof(int16_t));

                                LOG_DEBUG("[input%d] Pre-fill complete; first FIFO write done",
                                          _index);
                            }
                        }
                        else
                        {
                            // Normal phase: write directly to the FIFO.
                            _shared_fifo.write(pcm_out.data(),
                                               static_cast<size_t>(out_frames) * 2 * sizeof(int16_t));
                        }
                    }
                }
            }   // gain/EQ/peak/FIFO block

            }   // while (frames_left > 0)
        }       // if (_capturing.load() && _src_state)

        // ── Update the status snapshot ────────────────────────────────────────
        // level_dbfs is intentionally omitted here; get_status() converts
        // _current_peak_sample to dBFS at read time to keep log10 off this path.
        {
            std::lock_guard<std::mutex> lock(_status_mutex);
            _status.is_silent    = !is_above_threshold;
            _status.is_capturing = _capturing.load();
            _status.detected_hz  = _rate_estimator.estimated_input_rate();
        }
    }
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
    else if (type == "set_gain")
    {
        int   idx     = json_get_int(json_command, "input", 0);
        float gain_db = json_get_float(json_command, "gain_db", 0.0f);
        return _monitor.api_set_gain(idx, gain_db);
    }
    else if (type == "set_log_level")
    {
        std::string level_text = json_get_string(json_command, "level");
        return _monitor.api_set_log_level(level_text);
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
            i + 1,          // 1-based index
            _fifo_writer,
            _fifo_mutex
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
// Returns a JSON status snapshot for all inputs.
// Called in response to a {"type":"get_status"} command.  Python polls this
// at whatever rate the UI requires.
//
std::string AudioMonitor::api_get_status()
{
    LOG_SPAM("[monitor] get_status requested");
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1);
    oss << "{\"type\":\"status\",\"log_level\":\""
        << protocol_log_level_name(logger_get_level())
        << "\",\"inputs\":[";

    for (int i = 0; i < NUM_INPUTS; ++i)
    {
        if (i > 0)
            oss << ",";

        InputChannelStatus s = _inputs[i]->get_status();

        oss << "{"
            << "\"index\":"               << s.index                << ","
            << "\"level_dbfs\":"          << s.level_dbfs            << ","
            << "\"silent\":"              << (s.is_silent    ? "true" : "false") << ","
            << "\"capturing\":"           << (s.is_capturing ? "true" : "false") << ","
            << "\"detected_hz\":"         << s.detected_hz           << ","
            << "\"raw_peak_dbfs\":"       << s.raw_peak_dbfs         << ","
            << "\"effective_peak_dbfs\":" << s.effective_peak_dbfs   << ","
            << "\"started\":"             << (s.is_started   ? "true" : "false") << ","
            << "\"running\":"             << (s.is_running   ? "true" : "false")
            << "}";
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

// Return an error string if gain_db is out of range, or "".
// This validates the per-input pre-amplifier gain, which spans [-24, +24] dB.
// EQ band gain has its own tighter range check in validate_eq_bands().
static std::string validate_gain_db(float gain_db)
{
    if (gain_db < -24.0f || gain_db > 24.0f)
        return "gain_db must be in the range [-24.0, +24.0]";
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

    ch->stop();
    LOG_INFO("[monitor] stop_input(%d) completed", input_index);

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
    //   1. Store _allow_capture = false on all other inputs.  Their process
    //      threads re-check this flag under _fifo_mutex immediately before
    //      each write, so any write that begins after this store will be
    //      suppressed.
    //   2. Acquire _fifo_mutex before enabling the new input.  This ensures
    //      that if a just-disabled thread is mid-write (holding _fifo_mutex),
    //      we wait for that write to finish before step 3.
    //   3. Enable the new input while still under _fifo_mutex, so the first
    //      write from the new input cannot race with a trailing write from the
    //      old input.
    if (allow)
    {
        for (int i = 0; i < NUM_INPUTS; ++i)
        {
            if (_inputs[i].get() != ch)
                _inputs[i]->set_allow_capture(false);
        }
        // Acquire _fifo_mutex before enabling the new input so that any
        // in-flight write from a just-disabled thread completes first.
        // The process thread re-checks _allow_capture while holding this
        // mutex, so no stale write can follow once we release it.
        std::lock_guard<std::mutex> lock(_fifo_mutex);
        ch->set_allow_capture(true);
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
