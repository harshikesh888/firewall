#pragma once

#pragma once

#include "types.h"
#include "packet_parser.h"
#include "rule_engine.h"
#include "logger.h"
#include "connection_tracker.h"
#include "rate_limiter.h"

#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

class Firewall {
public:
    Firewall() : running_(false), queue_handle_(nullptr),
                 queue_num_(0), stats_{}, stateful_(true),
                 verbose_(false), json_log_(false) {
        stats_.reset();
    }

    ~Firewall() {
        stop();
    }

    void set_queue_num(uint16_t num) { queue_num_ = num; }
    void set_stateful(bool s)        { stateful_ = s; }
    void set_verbose(bool v)         { verbose_ = v; }
    void set_json_log(bool j)        { json_log_ = j; }
    void set_default_action(Action a) { rules_.set_default_action(a); }

    RuleEngine&       rule_engine()       { return rules_; }
    const RuleEngine& rule_engine() const { return rules_; }

    ConnectionTracker& conn_tracker() { return conn_tracker_; }
    RateLimiter&       rate_limiter() { return rate_limiter_; }

    bool init() {
        FW_LOG_INFO("=== Linux Packet Firewall v1.0 ===");
        FW_LOG_INFO("Initializing firewall engine...");

        if (!setup_nfqueue()) {
            FW_LOG_FATAL("Failed to initialize netfilter queue");
            return false;
        }

        FW_LOG_INFO("Netfilter queue initialized (queue=" +
                     std::to_string(queue_num_) + ")");
        FW_LOG_INFO("Stateful mode: " + std::string(stateful_ ? "ON" : "OFF"));
        FW_LOG_INFO("Default action: " + action_str(rules_.default_action()));
        return true;
    }

    void start() {
        if (running_) return;
        running_ = true;

        FW_LOG_INFO("Firewall starting packet processing...");

        stats_thread_ = std::thread(&Firewall::stats_reporter, this);

        process_packets();
    }

    void stop() {
        if (!running_) return;
        running_ = false;

        FW_LOG_INFO("Firewall shutting down...");

        if (stats_thread_.joinable())
            stats_thread_.join();

        if (queue_handle_) {
            nfq_destroy_queue(queue_handle_);
            queue_handle_ = nullptr;
        }
    }

    bool is_running() const { return running_; }

    void print_stats() const {
        std::cout << "\n=== Firewall Statistics ===" << std::endl;
        std::cout << "Uptime:              " << std::fixed << std::setprecision(1)
                  << stats_.uptime_seconds() << "s" << std::endl;
        std::cout << "Total packets:       " << stats_.total_packets << std::endl;
        std::cout << "Accepted:            " << stats_.accepted_packets << std::endl;
        std::cout << "Dropped:             " << stats_.dropped_packets << std::endl;
        std::cout << "Rejected:            " << stats_.rejected_packets << std::endl;
        std::cout << "Logged:              " << stats_.logged_packets << std::endl;
        std::cout << "Total bytes:         " << stats_.total_bytes << std::endl;
        std::cout << "TCP packets:         " << stats_.tcp_packets << std::endl;
        std::cout << "UDP packets:         " << stats_.udp_packets << std::endl;
        std::cout << "ICMP packets:        " << stats_.icmp_packets << std::endl;
        std::cout << "Active connections:  " << conn_tracker_.active_connections() << std::endl;
        std::cout << "Rate-limited hosts:  " << rate_limiter_.blocked_count() << std::endl;
        std::cout << "Active rules:        " << rules_.rules().size() << std::endl;
        std::cout << "===========================\n" << std::endl;
    }

    void print_rules() const {
        std::cout << "\n=== Firewall Rules ===" << std::endl;
        std::cout << std::left
                  << std::setw(4)  << "ID"
                  << std::setw(16) << "NAME"
                  << std::setw(8)  << "ACTION"
                  << std::setw(8)  << "PROTO"
                  << std::setw(18) << "SRC"
                  << std::setw(6)  << "SPORT"
                  << std::setw(18) << "DST"
                  << std::setw(6)  << "DPORT"
                  << std::setw(5)  << "LOG"
                  << std::endl;
        std::cout << std::string(89, '-') << std::endl;

        for (const auto& rule : rules_.rules()) {
            std::cout << std::left
                      << std::setw(4)  << rule.id
                      << std::setw(16) << rule.name
                      << std::setw(8)  << action_str(rule.action)
                      << std::setw(8)  << proto_str(rule.protocol)
                      << std::setw(18) << (rule.src_ip.empty() ? "*" : rule.src_ip)
                      << std::setw(6)  << (rule.src_port == 0 ? "*" : std::to_string(rule.src_port))
                      << std::setw(18) << (rule.dst_ip.empty() ? "*" : rule.dst_ip)
                      << std::setw(6)  << (rule.dst_port == 0 ? "*" : std::to_string(rule.dst_port))
                      << std::setw(5)  << (rule.log_packets ? "Y" : "N")
                      << std::endl;
        }
        std::cout << "========================\n" << std::endl;
    }

private:
    std::atomic<bool>         running_;
    struct nfq_handle*        nfq_handle_;
    struct nfq_q_handle*      queue_handle_;
    uint16_t                  queue_num_;
    FirewallStats             stats_;
    bool                      stateful_;
    bool                      verbose_;
    bool                      json_log_;
    std::thread               stats_thread_;
    RuleEngine                rules_;
    ConnectionTracker         conn_tracker_;
    RateLimiter               rate_limiter_;
    struct nfq_handle*        nfq_handle_base_ = nullptr;

    bool setup_nfqueue() {
        nfq_handle_base_ = nfq_open();
        if (!nfq_handle_base_) {
            FW_LOG_ERROR("nfq_open() failed: " + std::string(strerror(errno)));
            return false;
        }

        if (nfq_unbind_pf(nfq_handle_base_, AF_INET) < 0) {
            FW_LOG_WARN("nfq_unbind_pf (may be first run): " +
                         std::string(strerror(errno)));
        }

        if (nfq_bind_pf(nfq_handle_base_, AF_INET) < 0) {
            FW_LOG_ERROR("nfq_bind_pf failed: " + std::string(strerror(errno)));
            nfq_close(nfq_handle_base_);
            return false;
        }

        queue_handle_ = nfq_create_queue(nfq_handle_base_, queue_num_,
                                          &Firewall::static_callback, this);
        if (!queue_handle_) {
            FW_LOG_ERROR("nfq_create_queue failed: " + std::string(strerror(errno)));
            nfq_close(nfq_handle_base_);
            return false;
        }

        nfq_set_mode(queue_handle_, NFQNL_COPY_PACKET, 0xFFFF);
        FW_LOG_INFO("NFQueue mode set to COPY_PACKET (max 65535 bytes)");
        return true;
    }

    static int static_callback(struct nfq_q_handle* qh,
                               struct nfgenmsg* nfmsg,
                               struct nfq_data* nfa,
                               void* data) {
        Firewall* self = static_cast<Firewall*>(data);
        return self->process_packet_callback(qh, nfmsg, nfa);
    }

    int process_packet_callback(struct nfq_q_handle* qh,
                                struct nfgenmsg* /* nfmsg */,
                                struct nfq_data* nfa) {
        uint32_t packet_id = 0;
        struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
        if (ph)
            packet_id = ntohl(ph->packet_id);

        unsigned char* raw_data = nullptr;
        int data_len = nfq_get_payload(nfa, &raw_data);
        if (data_len < 0 || !raw_data)
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);

        stats_.total_packets++;
        stats_.total_bytes += data_len;

        PacketInfo pkt;
        if (!PacketParser::parse(raw_data, data_len, pkt)) {
            stats_.accepted_packets++;
            return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
        }

        update_proto_stats(pkt);

        auto rate_decision = rate_limiter_.check(pkt);
        if (!rate_decision.allowed) {
            stats_.dropped_packets++;
            FW_LOG_WARN("Rate limit: " + rate_decision.reason + " from " +
                         pkt.src_ip_str());
            if (verbose_)
                log_packet(pkt, Action::DROP, "RATE_LIMIT");
            return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
        }

        if (stateful_) {
            auto conn_state = conn_tracker_.track_packet(pkt);

            if (conn_state == ConnectionTracker::ConnState::INVALID) {
                stats_.dropped_packets++;
                if (verbose_)
                    FW_LOG_WARN("Invalid connection from " + pkt.src_ip_str());
                return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
            }
        }

        auto result = rules_.evaluate(pkt);
        uint32_t verdict = NF_ACCEPT;

        switch (result.action) {
            case Action::ACCEPT:
                verdict = NF_ACCEPT;
                stats_.accepted_packets++;
                break;
            case Action::DROP:
                verdict = NF_DROP;
                stats_.dropped_packets++;
                break;
            case Action::REJECT:
                verdict = NF_DROP;
                stats_.rejected_packets++;
                break;
            case Action::LOG:
                verdict = NF_ACCEPT;
                stats_.logged_packets++;
                break;
        }

        if (result.log_it || json_log_) {
            std::string rule_name;
            for (const auto& r : rules_.rules()) {
                if (r.id == result.rule_id) { rule_name = r.name; break; }
            }

            if (json_log_)
                Logger::instance().log_packet_json(pkt, result.action, result.rule_id);
            else
                Logger::instance().log_packet(pkt, result.action, rule_name);
        }

        if (verbose_) {
            log_packet(pkt, result.action, "");
        }

        return nfq_set_verdict(qh, packet_id, verdict, 0, nullptr);
    }

    void process_packets() {
        int fd = nfq_fd(nfq_handle_base_);
        if (fd < 0) {
            FW_LOG_ERROR("Failed to get nfqueue file descriptor");
            return;
        }

        char buf[4096] __attribute__((aligned));
        while (running_) {
            int rv = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (rv < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                FW_LOG_ERROR("recv() error: " + std::string(strerror(errno)));
                break;
            }
            if (rv == 0) break;

            nfq_handle_packet(nfq_handle_base_, buf, rv);
        }
    }

    void stats_reporter() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            if (running_) {
                double pps = stats_.total_packets / stats_.uptime_seconds();
                FW_LOG_INFO("STATS pps=" + std::to_string((int)pps) +
                             " total=" + std::to_string(stats_.total_packets) +
                             " acc=" + std::to_string(stats_.accepted_packets) +
                             " drop=" + std::to_string(stats_.dropped_packets) +
                             " conns=" + std::to_string(conn_tracker_.active_connections()));
            }
        }
    }

    void update_proto_stats(const PacketInfo& pkt) {
        switch (pkt.protocol) {
            case IPPROTO_TCP:  stats_.tcp_packets++;  break;
            case IPPROTO_UDP:  stats_.udp_packets++;  break;
            case IPPROTO_ICMP: stats_.icmp_packets++; break;
        }
    }

    void log_packet(const PacketInfo& pkt, Action action,
                    const std::string& rule_name) {
        std::ostringstream oss;
        oss << "[VERDICT] "
            << pkt.src_ip_str() << ":" << pkt.src_port
            << " -> "
            << pkt.dst_ip_str() << ":" << pkt.dst_port
            << " [" << pkt.proto_str() << "] "
            << "action=" << action_str(action);
        if (!rule_name.empty())
            oss << " rule=\"" << rule_name << "\"";
        FW_LOG_INFO(oss.str());
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

    static std::string proto_str(Protocol p) {
        switch (p) {
            case Protocol::TCP:  return "TCP";
            case Protocol::UDP:  return "UDP";
            case Protocol::ICMP: return "ICMP";
            case Protocol::ANY:  return "ANY";
        }
        return "???";
    }
};
