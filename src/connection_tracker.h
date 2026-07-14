#pragma once

#include "types.h"
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <list>
#include <functional>

class ConnectionTracker {
public:
    enum class ConnState : uint8_t {
        NEW         = 0,
        ESTABLISHED = 1,
        RELATED     = 2,
        INVALID     = 3,
        CLOSED      = 4
    };

    struct ConnectionKey {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t  protocol;

        bool operator==(const ConnectionKey& o) const {
            return src_ip == o.src_ip && dst_ip == o.dst_ip &&
                   src_port == o.src_port && dst_port == o.dst_port &&
                   protocol == o.protocol;
        }
    };

    struct ConnectionKeyHash {
        size_t operator()(const ConnectionKey& k) const {
            size_t h = 0;
            h ^= std::hash<uint32_t>()(k.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint32_t>()(k.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint16_t>()(k.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint16_t>()(k.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint8_t>()(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    struct Connection {
        ConnectionKey key;
        ConnState     state;
        uint64_t      packets_seen;
        uint64_t      bytes_seen;
        std::chrono::steady_clock::time_point last_seen;
        std::chrono::steady_clock::time_point created;

        Connection() : state(ConnState::NEW), packets_seen(0), bytes_seen(0),
            last_seen(std::chrono::steady_clock::now()),
            created(std::chrono::steady_clock::now()) {}
    };

    ConnectionTracker() : max_entries_(65536), tcp_timeout_(300),
                          udp_timeout_(60), cleanup_interval_(30),
                          last_cleanup_(std::chrono::steady_clock::now()) {}

    void set_limits(size_t max_entries, int tcp_timeout, int udp_timeout) {
        max_entries_    = max_entries;
        tcp_timeout_    = tcp_timeout;
        udp_timeout_    = udp_timeout;
    }

    ConnState track_packet(const PacketInfo& pkt) {
        std::lock_guard<std::mutex> lock(mu_);

        cleanup_expired();

        ConnectionKey key;
        key.src_ip   = pkt.src_ip;
        key.dst_ip   = pkt.dst_ip;
        key.src_port = pkt.src_port;
        key.dst_port = pkt.dst_port;
        key.protocol = pkt.protocol;

        auto it = connections_.find(key);
        if (it != connections_.end()) {
            Connection& conn = it->second;
            conn.packets_seen++;
            conn.bytes_seen += pkt.packet_len;
            conn.last_seen = std::chrono::steady_clock::now();

            if (conn.state == ConnState::CLOSED)
                conn.state = ConnState::ESTABLISHED;

            return conn.state;
        }

        if (connections_.size() >= max_entries_) {
            evict_oldest();
        }

        Connection conn;
        conn.key = key;
        conn.state = ConnState::NEW;
        conn.packets_seen = 1;
        conn.bytes_seen = pkt.packet_len;

        if (pkt.protocol == IPPROTO_TCP) {
            if (pkt.tcp_flags & 0x02) {
                conn.state = ConnState::NEW;
            } else if (pkt.tcp_flags & 0x10) {
                conn.state = ConnState::ESTABLISHED;
            } else {
                conn.state = ConnState::ESTABLISHED;
            }
        } else {
            conn.state = ConnState::ESTABLISHED;
        }

        connections_[key] = conn;
        return conn.state;
    }

    bool is_established(const PacketInfo& pkt) const {
        std::lock_guard<std::mutex> lock(mu_);
        ConnectionKey key;
        key.src_ip   = pkt.src_ip;
        key.dst_ip   = pkt.dst_ip;
        key.src_port = pkt.src_port;
        key.dst_port = pkt.dst_port;
        key.protocol = pkt.protocol;

        auto it = connections_.find(key);
        if (it == connections_.end()) return false;

        return it->second.state == ConnState::ESTABLISHED ||
               it->second.state == ConnState::RELATED;
    }

    size_t active_connections() const {
        std::lock_guard<std::mutex> lock(mu_);
        return connections_.size();
    }

    size_t total_connections_tracked() const {
        std::lock_guard<std::mutex> lock(mu_);
        return total_tracked_;
    }

    void get_stats(uint64_t& tracked, uint64_t& expired) const {
        std::lock_guard<std::mutex> lock(mu_);
        tracked = total_tracked_;
        expired = total_expired_;
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<ConnectionKey, Connection, ConnectionKeyHash> connections_;
    size_t max_entries_;
    int tcp_timeout_;
    int udp_timeout_;
    int cleanup_interval_;
    std::chrono::steady_clock::time_point last_cleanup_;
    uint64_t total_tracked_ = 0;
    uint64_t total_expired_ = 0;

    void cleanup_expired() {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now - last_cleanup_).count() < cleanup_interval_)
            return;

        last_cleanup_ = now;
        for (auto it = connections_.begin(); it != connections_.end(); ) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last_seen).count();

            int timeout = (it->second.key.protocol == IPPROTO_TCP) ?
                tcp_timeout_ : udp_timeout_;

            if (elapsed > timeout) {
                it = connections_.erase(it);
                total_expired_++;
            } else {
                ++it;
            }
        }
    }

    void evict_oldest() {
        auto oldest = connections_.begin();
        for (auto it = connections_.begin(); it != connections_.end(); ++it) {
            if (it->second.last_seen < oldest->second.last_seen)
                oldest = it;
        }
        connections_.erase(oldest);
        total_expired_++;
    }
};
