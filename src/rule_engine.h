#pragma once

#include "types.h"
#include "packet_parser.h"
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>

class RuleEngine {
public:
    RuleEngine() : default_action_(Action::DROP) {}

    void set_default_action(Action a) { default_action_ = a; }
    Action default_action() const { return default_action_; }

    void add_rule(const Rule& rule) {
        rules_.push_back(rule);
        std::cout << "[+] Rule added: " << rule.name
                  << " #" << rule.id << std::endl;
    }

    void remove_rule(uint32_t id) {
        auto it = std::remove_if(rules_.begin(), rules_.end(),
            [id](const Rule& r) { return r.id == id; });
        if (it != rules_.end()) {
            rules_.erase(it, rules_.end());
            std::cout << "[-] Rule removed: #" << id << std::endl;
        }
    }

    void clear_rules() {
        rules_.clear();
        std::cout << "[*] All rules cleared" << std::endl;
    }

    const std::vector<Rule>& rules() const { return rules_; }

    struct MatchResult {
        bool     matched;
        Action   action;
        uint32_t rule_id;
        bool     log_it;

        MatchResult() : matched(false), action(Action::DROP),
                        rule_id(0), log_it(false) {}
    };

    MatchResult evaluate(const PacketInfo& pkt) const {
        for (const auto& rule : rules_) {
            if (match_rule(rule, pkt)) {
                MatchResult res;
                res.matched = true;
                res.action  = rule.action;
                res.rule_id = rule.id;
                res.log_it  = rule.log_packets;
                return res;
            }
        }
        MatchResult res;
        res.matched = false;
        res.action  = default_action_;
        res.log_it  = true;
        return res;
    }

    bool load_from_file(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "[!] Cannot open rules file: " << path << std::endl;
            return false;
        }

        std::string line;
        uint32_t next_id = rules_.empty() ? 1 :
            (*std::max_element(rules_.begin(), rules_.end(),
                [](const Rule& a, const Rule& b){ return a.id < b.id; })).id + 1;

        while (std::getline(file, line)) {
            line.erase(0, line.find_first_not_of(" \t"));
            if (line.empty() || line[0] == '#')
                continue;

            Rule rule = parse_rule_line(line, next_id);
            if (!rule.name.empty()) {
                add_rule(rule);
                next_id++;
            }
        }
        std::cout << "[*] Loaded " << rules_.size() << " rules from "
                  << path << std::endl;
        return true;
    }

private:
    std::vector<Rule> rules_;
    Action default_action_;

    bool match_rule(const Rule& rule, const PacketInfo& pkt) const {
        if (rule.protocol != Protocol::ANY) {
            if (static_cast<uint8_t>(rule.protocol) != pkt.protocol)
                return false;
        }

        if (!rule.src_ip.empty()) {
            uint32_t mask = 0xFFFFFFFF;
            size_t slash = rule.src_ip.find('/');
            std::string ip_part = (slash != std::string::npos) ?
                rule.src_ip.substr(0, slash) : rule.src_ip;
            if (slash != std::string::npos) {
                int bits = std::stoi(rule.src_ip.substr(slash + 1));
                mask <<= (32 - bits);
            }
            uint32_t rule_ip = PacketInfo::string_to_ip(ip_part);
            if ((pkt.src_ip & mask) != (rule_ip & mask))
                return false;
        }

        if (!rule.dst_ip.empty()) {
            uint32_t mask = 0xFFFFFFFF;
            size_t slash = rule.dst_ip.find('/');
            std::string ip_part = (slash != std::string::npos) ?
                rule.dst_ip.substr(0, slash) : rule.dst_ip;
            if (slash != std::string::npos) {
                int bits = std::stoi(rule.dst_ip.substr(slash + 1));
                mask <<= (32 - bits);
            }
            uint32_t rule_ip = PacketInfo::string_to_ip(ip_part);
            if ((pkt.dst_ip & mask) != (rule_ip & mask))
                return false;
        }

        if (rule.src_port != 0 && rule.src_port != pkt.src_port)
            return false;

        if (rule.dst_port != 0 && rule.dst_port != pkt.dst_port)
            return false;

        return true;
    }

    Rule parse_rule_line(const std::string& line, uint32_t id) {
        Rule rule;
        rule.id = id;

        std::istringstream iss(line);
        std::string token;
        std::vector<std::string> tokens;
        while (iss >> token) tokens.push_back(token);

        if (tokens.size() < 2) return rule;

        size_t i = 0;
        rule.name = tokens[i++];
        if (i >= tokens.size()) return rule;

        std::string action_str = tokens[i++];
        std::transform(action_str.begin(), action_str.end(),
                       action_str.begin(), ::tolower);
        if (action_str == "accept")       rule.action = Action::ACCEPT;
        else if (action_str == "drop")    rule.action = Action::DROP;
        else if (action_str == "reject")  rule.action = Action::REJECT;
        else if (action_str == "log")      rule.action = Action::LOG;

        for (; i < tokens.size(); i++) {
            const std::string& t = tokens[i];
            if (t == "proto" && i + 1 < tokens.size()) {
                i++;
                std::string p = tokens[i];
                std::transform(p.begin(), p.end(), p.begin(), ::tolower);
                if (p == "tcp")       rule.protocol = Protocol::TCP;
                else if (p == "udp")  rule.protocol = Protocol::UDP;
                else if (p == "icmp") rule.protocol = Protocol::ICMP;
            } else if (t == "src" && i + 1 < tokens.size()) {
                i++;
                rule.src_ip = tokens[i];
            } else if (t == "dst" && i + 1 < tokens.size()) {
                i++;
                rule.dst_ip = tokens[i];
            } else if (t == "sport" && i + 1 < tokens.size()) {
                i++;
                rule.src_port = static_cast<uint16_t>(std::stoi(tokens[i]));
            } else if (t == "dport" && i + 1 < tokens.size()) {
                i++;
                rule.dst_port = static_cast<uint16_t>(std::stoi(tokens[i]));
            } else if (t == "log") {
                rule.log_packets = true;
            } else if (t == "in") {
                rule.direction = Direction::INBOUND;
            } else if (t == "out") {
                rule.direction = Direction::OUTBOUND;
            }
        }
        return rule;
    }
};
