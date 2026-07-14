#pragma once

#include <cstdint>
#include <string>
#include <arpa/inet.h>
#include <linux/in.h>
#include <netinet/in.h>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <mutex>

enum class Protocol : uint8_t {
    TCP  = 6,
    UDP  = 17,
    ICMP = 1,
    ANY  = 0xFF
};

enum class Action : uint8_t {
    ACCEPT = 0,
    DROP   = 1,
    LOG    = 2,
    REJECT = 3
};

enum class Direction : uint8_t {
    INBOUND  = 0,
    OUTBOUND = 1,
    BIDIRECTIONAL = 2
};

struct Rule {
    uint32_t    id;
    std::string name;
    std::string src_ip;
    std::string dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    Protocol    protocol;
    Direction   direction;
    Action      action;
    bool        log_packets;
    uint64_t    bytes_matched;
    uint64_t    packets_matched;

    Rule() : id(0), src_port(0), dst_port(0),
             protocol(Protocol::ANY), direction(Direction::BIDIRECTIONAL),
             action(Action::DROP), log_packets(false),
             bytes_matched(0), packets_matched(0) {}
};

struct RateLimitEntry {
    uint64_t packet_count;
    uint64_t syn_count;
    uint64_t icmp_count;
    uint64_t conn_count;
    std::chrono::steady_clock::time_point window_start;

    RateLimitEntry() : packet_count(0), syn_count(0),
        icmp_count(0), conn_count(0),
        window_start(std::chrono::steady_clock::now()) {}
};

struct PacketInfo {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint16_t packet_len;
    uint8_t  tcp_flags;
    uint32_t mark;
    const uint8_t* raw_data;
    size_t   raw_len;

    PacketInfo() : src_ip(0), dst_ip(0), src_port(0), dst_port(0),
                   protocol(0), packet_len(0), tcp_flags(0), mark(0),
                   raw_data(nullptr), raw_len(0) {}

    std::string src_ip_str() const {
        return ip_to_string(src_ip);
    }

    std::string dst_ip_str() const {
        return ip_to_string(dst_ip);
    }

    std::string proto_str() const {
        switch (protocol) {
            case 6:  return "TCP";
            case 17: return "UDP";
            case 1:  return "ICMP";
            default: return "OTHER";
        }
    }

    static std::string ip_to_string(uint32_t ip) {
        uint8_t* p = reinterpret_cast<uint8_t*>(&ip);
        return std::to_string(p[0]) + "." + std::to_string(p[1]) +
               "." + std::to_string(p[2]) + "." + std::to_string(p[3]);
    }

    static uint32_t string_to_ip(const std::string& s) {
        uint32_t ip = 0;
        int shift = 0;
        size_t start = 0;
        for (int i = 0; i < 4; ++i) {
            size_t pos = s.find('.', start);
            if (pos == std::string::npos) pos = s.length();
            uint8_t octet = static_cast<uint8_t>(std::stoi(s.substr(start, pos - start)));
            ip |= (static_cast<uint32_t>(octet) << shift);
            shift += 8;
            start = pos + 1;
        }
        return ip;
    }
};

struct FirewallStats {
    uint64_t total_packets;
    uint64_t accepted_packets;
    uint64_t dropped_packets;
    uint64_t rejected_packets;
    uint64_t logged_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    std::chrono::steady_clock::time_point start_time;

    void reset() {
        total_packets = 0;
        accepted_packets = 0;
        dropped_packets = 0;
        rejected_packets = 0;
        logged_packets = 0;
        total_bytes = 0;
        tcp_packets = 0;
        udp_packets = 0;
        icmp_packets = 0;
        start_time = std::chrono::steady_clock::now();
    }

    double uptime_seconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(now - start_time).count();
    }
};
