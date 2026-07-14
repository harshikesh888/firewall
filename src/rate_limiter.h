#pragma once

#include "types.h"
#include <unordered_map>
#include <mutex>
#include <chrono>

class RateLimiter {
public:
    struct Config {
        uint64_t max_packets_per_second;
        uint64_t max_syn_per_second;
        uint64_t max_conn_per_source;
        uint64_t max_icmp_per_second;
        int      block_duration_seconds;

        Config() : max_packets_per_second(1000),
                   max_syn_per_second(50),
                   max_conn_per_source(100),
                   max_icmp_per_second(20),
                   block_duration_seconds(300) {}
    };

    RateLimiter() : global_pps_(0) {}

    void configure(const Config& cfg) {
        std::lock_guard<std::mutex> lock(mu_);
        config_ = cfg;
    }

    struct Decision {
        bool allowed;
        std::string reason;

        Decision() : allowed(true) {}
    };

    Decision check(const PacketInfo& pkt) {
        std::lock_guard<std::mutex> lock(mu_);
        cleanup_blocked();

        uint32_t src = pkt.src_ip;

        auto blocked_it = blocked_sources_.find(src);
        if (blocked_it != blocked_sources_.end()) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - blocked_it->second).count();
            if (elapsed < config_.block_duration_seconds) {
                Decision d;
                d.allowed = false;
                d.reason = "Source blocked for " +
                    std::to_string(config_.block_duration_seconds - elapsed) +
                    "s remaining";
                return d;
            }
            blocked_sources_.erase(blocked_it);
        }

        auto& entry = source_stats_[src];
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - entry.window_start).count();

        if (elapsed >= 1000) {
            entry.packet_count = 0;
            entry.syn_count = 0;
            entry.icmp_count = 0;
            entry.conn_count = 0;
            entry.window_start = now;
        }

        entry.packet_count++;
        global_pps_++;

        if (pkt.protocol == IPPROTO_TCP && (pkt.tcp_flags & 0x02)) {
            entry.syn_count++;
            if (entry.syn_count > config_.max_syn_per_second) {
                block_source(src, "SYN flood");
                Decision d;
                d.allowed = false;
                d.reason = "SYN rate exceeded";
                return d;
            }
        }

        if (pkt.protocol == IPPROTO_ICMP) {
            entry.icmp_count++;
            if (entry.icmp_count > config_.max_icmp_per_second) {
                block_source(src, "ICMP flood");
                Decision d;
                d.allowed = false;
                d.reason = "ICMP rate exceeded";
                return d;
            }
        }

        if (entry.packet_count > config_.max_packets_per_second) {
            block_source(src, "Packet rate exceeded");
            Decision d;
            d.allowed = false;
            d.reason = "Packet rate exceeded";
            return d;
        }

        return Decision();
    }

    size_t blocked_count() const {
        std::lock_guard<std::mutex> lock(mu_);
        return blocked_sources_.size();
    }

    bool is_blocked(uint32_t ip) const {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = blocked_sources_.find(ip);
        if (it == blocked_sources_.end()) return false;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second).count();
        return elapsed < config_.block_duration_seconds;
    }

    void block(uint32_t ip) {
        std::lock_guard<std::mutex> lock(mu_);
        blocked_sources_[ip] = std::chrono::steady_clock::now();
    }

    void unblock(uint32_t ip) {
        std::lock_guard<std::mutex> lock(mu_);
        blocked_sources_.erase(ip);
    }

private:
    mutable std::mutex mu_;
    Config config_;
    std::unordered_map<uint32_t, RateLimitEntry> source_stats_;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> blocked_sources_;
    uint64_t global_pps_;

    void block_source(uint32_t ip, const std::string& reason) {
        blocked_sources_[ip] = std::chrono::steady_clock::now();
        FW_LOG_WARN("BLOCKED source " + PacketInfo::ip_to_string(ip) +
                     " - " + reason);
    }

    void cleanup_blocked() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = blocked_sources_.begin(); it != blocked_sources_.end(); ) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second).count();
            if (elapsed >= config_.block_duration_seconds)
                it = blocked_sources_.erase(it);
            else
                ++it;
        }
    }
};
