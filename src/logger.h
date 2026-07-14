#pragma once

#include "types.h"
#include <fstream>
#include <iostream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstring>

class Logger {
public:
    enum class Level : uint8_t {
        DEBUG = 0,
        INFO  = 1,
        WARN  = 2,
        ERROR = 3,
        FATAL = 4
    };

    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    bool init(const std::string& log_file, Level min_level = Level::INFO) {
        std::lock_guard<std::mutex> lock(mu_);
        min_level_ = min_level;
        if (!log_file.empty()) {
            file_.open(log_file, std::ios::app);
            if (!file_.is_open()) {
                std::cerr << "[Logger] Failed to open: " << log_file << std::endl;
                return false;
            }
        }
        return true;
    }

    void log(Level level, const std::string& msg) {
        if (level < min_level_) return;
        std::lock_guard<std::mutex> lock(mu_);

        std::string timestamp = get_timestamp();
        std::string prefix = level_str(level);
        std::string line = "[" + timestamp + "] [" + prefix + "] " + msg;

        if (file_.is_open()) {
            file_ << line << std::endl;
            file_.flush();
        }

        if (level >= Level::WARN) {
            std::cerr << line << std::endl;
        } else {
            std::cout << line << std::endl;
        }
    }

    void log_packet(const PacketInfo& pkt, Action action,
                    const std::string& rule_name = "") {
        std::ostringstream oss;
        oss << "PKT "
            << pkt.src_ip_str() << ":" << pkt.src_port
            << " -> "
            << pkt.dst_ip_str() << ":" << pkt.dst_port
            << " [" << pkt.proto_str() << "] "
            << "len=" << pkt.packet_len
            << " action=" << action_str(action);
        if (!rule_name.empty())
            oss << " rule=\"" << rule_name << "\"";
        if (pkt.protocol == IPPROTO_TCP)
            oss << " flags=" << PacketParser::get_tcp_flag_str(pkt.tcp_flags);

        log(Level::INFO, oss.str());
    }

    void log_packet_json(const PacketInfo& pkt, Action action,
                         uint32_t rule_id) {
        std::ostringstream oss;
        oss << "{"
            << "\"ts\":\"" << get_timestamp() << "\","
            << "\"src\":\"" << pkt.src_ip_str() << "\","
            << "\"src_port\":" << pkt.src_port << ","
            << "\"dst\":\"" << pkt.dst_ip_str() << "\","
            << "\"dst_port\":" << pkt.dst_port << ","
            << "\"proto\":\"" << pkt.proto_str() << "\","
            << "\"len\":" << pkt.packet_len << ","
            << "\"action\":\"" << action_str(action) << "\","
            << "\"rule_id\":" << rule_id
            << "}";
        log(Level::INFO, oss.str());
    }

    void debug(const std::string& msg) { log(Level::DEBUG, msg); }
    void info(const std::string& msg)  { log(Level::INFO, msg); }
    void warn(const std::string& msg)  { log(Level::WARN, msg); }
    void error(const std::string& msg) { log(Level::ERROR, msg); }
    void fatal(const std::string& msg) { log(Level::FATAL, msg); }

    void close() {
        std::lock_guard<std::mutex> lock(mu_);
        if (file_.is_open()) file_.close();
    }

private:
    std::ofstream file_;
    Level min_level_ = Level::INFO;
    std::mutex mu_;

    Logger() = default;

    static std::string get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        std::tm tm_buf;
        localtime_r(&time, &tm_buf);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
            tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
            static_cast<int>(ms.count()));
        return std::string(buf);
    }

    static std::string level_str(Level l) {
        switch (l) {
            case Level::DEBUG: return "DEBUG";
            case Level::INFO:  return "INFO ";
            case Level::WARN:  return "WARN ";
            case Level::ERROR: return "ERROR";
            case Level::FATAL: return "FATAL";
        }
        return "?????";
    }

    static std::string action_str(Action a) {
        switch (a) {
            case Action::ACCEPT: return "ACCEPT";
            case Action::DROP:   return "DROP";
            case Action::REJECT: return "REJECT";
            case Action::LOG:    return "LOG";
        }
        return "UNKNOWN";
    }
};

#define FW_LOG_INFO(msg)  Logger::instance().info(msg)
#define FW_LOG_WARN(msg)  Logger::instance().warn(msg)
#define FW_LOG_ERROR(msg) Logger::instance().error(msg)
#define FW_LOG_DEBUG(msg) Logger::instance().debug(msg)
#define FW_LOG_FATAL(msg) Logger::instance().fatal(msg)
