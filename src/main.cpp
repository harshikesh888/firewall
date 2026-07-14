#include "firewall.h"
#include "rule_engine.h"
#include "logger.h"
#include "types.h"
#include <csignal>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>

static Firewall g_firewall;
static std::atomic<bool> g_shutdown(false);

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        std::cout << "\n[!] Caught signal " << sig << ", shutting down..." << std::endl;
        g_shutdown = true;
        g_firewall.stop();
    }
}

static void print_banner() {
    std::cout << R"(
  _____ _                    _____
 |  ___(_)_ __  _   _  __ _|  ___|__  _ __ ___
 | |_  | | '_ \| | | |/ _` | |_ / _ \| '__/ __|
 |  _| | | | | | |_| | (_| |  _| (_) | | | (__
 |_|   |_|_| |_|\__, |\__,_|_|  \___/|_|  \___|
                 |___/
    )" << std::endl;
    std::cout << "  Linux Netfilter Queue Firewall v1.0" << std::endl;
    std::cout << "  Stateful Packet Inspection Engine\n" << std::endl;
}

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "\nOptions:\n"
              << "  -q, --queue <num>       NFQueue number (default: 0)\n"
              << "  -r, --rules <file>      Rules configuration file\n"
              << "  -l, --log <file>        Log file path\n"
              << "  -d, --default <action>  Default action: accept|drop (default: drop)\n"
              << "  -s, --stateful          Enable stateful tracking (default: on)\n"
              << "  -v, --verbose           Verbose output\n"
              << "  -j, --json              JSON log format\n"
              << "  -h, --help              Show this help\n"
              << "\nExample:\n"
              << "  sudo " << prog << " -q 0 -r /etc/firewall/rules.conf -l /var/log/firewall.log\n"
              << std::endl;
}

static void setup_default_rules(RuleEngine& engine) {
    Rule rule;
    uint32_t id = 1;

    rule.id = id++;
    rule.name = "allow_loopback";
    rule.src_ip = "127.0.0.0/8";
    rule.dst_ip = "127.0.0.0/8";
    rule.protocol = Protocol::ANY;
    rule.direction = Direction::BIDIRECTIONAL;
    rule.action = Action::ACCEPT;
    rule.log_packets = false;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "allow_established";
    rule.protocol = Protocol::TCP;
    rule.direction = Direction::INBOUND;
    rule.action = Action::ACCEPT;
    rule.log_packets = false;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "allow_ssh_inbound";
    rule.protocol = Protocol::TCP;
    rule.dst_port = 22;
    rule.direction = Direction::INBOUND;
    rule.action = Action::ACCEPT;
    rule.log_packets = true;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "allow_http";
    rule.protocol = Protocol::TCP;
    rule.dst_port = 80;
    rule.direction = Direction::INBOUND;
    rule.action = Action::ACCEPT;
    rule.log_packets = false;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "allow_https";
    rule.protocol = Protocol::TCP;
    rule.dst_port = 443;
    rule.direction = Direction::INBOUND;
    rule.action = Action::ACCEPT;
    rule.log_packets = false;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "allow_dns_udp";
    rule.protocol = Protocol::UDP;
    rule.dst_port = 53;
    rule.direction = Direction::BIDIRECTIONAL;
    rule.action = Action::ACCEPT;
    rule.log_packets = false;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "allow_dns_tcp";
    rule.protocol = Protocol::TCP;
    rule.dst_port = 53;
    rule.direction = Direction::BIDIRECTIONAL;
    rule.action = Action::ACCEPT;
    rule.log_packets = false;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "allow_icmp_echo";
    rule.protocol = Protocol::ICMP;
    rule.direction = Direction::BIDIRECTIONAL;
    rule.action = Action::ACCEPT;
    rule.log_packets = false;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "block_telnet";
    rule.protocol = Protocol::TCP;
    rule.dst_port = 23;
    rule.direction = Direction::INBOUND;
    rule.action = Action::DROP;
    rule.log_packets = true;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "block_ftp";
    rule.protocol = Protocol::TCP;
    rule.dst_port = 21;
    rule.direction = Direction::INBOUND;
    rule.action = Action::DROP;
    rule.log_packets = true;
    engine.add_rule(rule);

    rule = Rule();
    rule.id = id++;
    rule.name = "default_drop";
    rule.protocol = Protocol::ANY;
    rule.direction = Direction::BIDIRECTIONAL;
    rule.action = Action::DROP;
    rule.log_packets = true;
    engine.add_rule(rule);

    engine.set_default_action(Action::DROP);
}

static void interactive_shell(Firewall& fw) {
    std::string input;
    std::cout << "\n[Firewall Shell] Type 'help' for commands\n" << std::endl;

    while (!g_shutdown) {
        std::cout << "fw> " << std::flush;
        if (!std::getline(std::cin, input)) break;

        if (input.empty()) continue;

        if (input == "help" || input == "h") {
            std::cout << "Commands:\n"
                      << "  stats         Show firewall statistics\n"
                      << "  rules         List active rules\n"
                      << "  add           Add rule (interactive)\n"
                      << "  remove <id>   Remove rule by ID\n"
                      << "  clear         Clear all rules\n"
                      << "  block <ip>    Block an IP\n"
                      << "  unblock <ip>  Unblock an IP\n"
                      << "  load <file>   Load rules from file\n"
                      << "  verbose       Toggle verbose mode\n"
                      << "  quit          Shutdown firewall\n"
                      << std::endl;
        } else if (input == "stats" || input == "s") {
            fw.print_stats();
        } else if (input == "rules" || input == "r") {
            fw.print_rules();
        } else if (input == "verbose" || input == "v") {
            // Toggle verbose (access via command line flag)
            std::cout << "[*] Use --verbose flag on startup" << std::endl;
        } else if (input == "clear") {
            fw.rule_engine().clear_rules();
            std::cout << "[*] All rules cleared" << std::endl;
        } else if (input.substr(0, 7) == "remove ") {
            uint32_t id = std::stoul(input.substr(7));
            fw.rule_engine().remove_rule(id);
        } else if (input.substr(0, 6) == "block ") {
            std::string ip = input.substr(6);
            uint32_t ip_num = PacketInfo::string_to_ip(ip);
            fw.rate_limiter().block(ip_num);
            std::cout << "[*] Blocked " << ip << std::endl;
        } else if (input.substr(0, 8) == "unblock ") {
            std::string ip = input.substr(8);
            uint32_t ip_num = PacketInfo::string_to_ip(ip);
            fw.rate_limiter().unblock(ip_num);
            std::cout << "[*] Unblocked " << ip << std::endl;
        } else if (input.substr(0, 5) == "load ") {
            std::string file = input.substr(5);
            fw.rule_engine().load_from_file(file);
        } else if (input == "add") {
            Rule rule;
            rule.id = fw.rule_engine().rules().empty() ? 1 :
                (*std::max_element(fw.rule_engine().rules().begin(),
                    fw.rule_engine().rules().end(),
                    [](const Rule& a, const Rule& b){ return a.id < b.id; })).id + 1;

            std::cout << "  Name: "; std::getline(std::cin, rule.name);
            std::cout << "  Protocol (tcp/udp/icmp/any): ";
            std::string p; std::getline(std::cin, p);
            if (p == "tcp")       rule.protocol = Protocol::TCP;
            else if (p == "udp")  rule.protocol = Protocol::UDP;
            else if (p == "icmp") rule.protocol = Protocol::ICMP;
            else                  rule.protocol = Protocol::ANY;

            std::cout << "  Source IP (or * for any): ";
            std::getline(std::cin, rule.src_ip);
            if (rule.src_ip == "*") rule.src_ip = "";

            std::cout << "  Dest IP (or * for any): ";
            std::getline(std::cin, rule.dst_ip);
            if (rule.dst_ip == "*") rule.dst_ip = "";

            std::cout << "  Source port (0 for any): ";
            std::string sp; std::getline(std::cin, sp);
            rule.src_port = sp.empty() ? 0 : std::stoi(sp);

            std::cout << "  Dest port (0 for any): ";
            std::string dp; std::getline(std::cin, dp);
            rule.dst_port = dp.empty() ? 0 : std::stoi(dp);

            std::cout << "  Action (accept/drop/reject): ";
            std::string a; std::getline(std::cin, a);
            if (a == "accept")       rule.action = Action::ACCEPT;
            else if (a == "reject")  rule.action = Action::REJECT;
            else                     rule.action = Action::DROP;

            std::cout << "  Log? (y/n): ";
            std::string l; std::getline(std::cin, l);
            rule.log_packets = (l == "y" || l == "Y");

            fw.rule_engine().add_rule(rule);
        } else if (input == "quit" || input == "q" || input == "exit") {
            g_shutdown = true;
            fw.stop();
            break;
        } else {
            std::cout << "[!] Unknown command: " << input << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    print_banner();

    std::string rules_file;
    std::string log_file = "/var/log/firewall.log";
    uint16_t queue_num = 0;
    bool stateful = true;
    bool verbose = false;
    bool json_log = false;
    Action default_action = Action::DROP;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if ((arg == "-q" || arg == "--queue") && i + 1 < argc)
            queue_num = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if ((arg == "-r" || arg == "--rules") && i + 1 < argc)
            rules_file = argv[++i];
        else if ((arg == "-l" || arg == "--log") && i + 1 < argc)
            log_file = argv[++i];
        else if ((arg == "-d" || arg == "--default") && i + 1 < argc) {
            i++;
            if (std::string(argv[i]) == "accept")
                default_action = Action::ACCEPT;
            else
                default_action = Action::DROP;
        }
        else if (arg == "-s" || arg == "--stateful")
            stateful = true;
        else if (arg == "-v" || arg == "--verbose")
            verbose = true;
        else if (arg == "-j" || arg == "--json")
            json_log = true;
        else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    Logger::instance().init(log_file);

    g_firewall.set_queue_num(queue_num);
    g_firewall.set_stateful(stateful);
    g_firewall.set_verbose(verbose);
    g_firewall.set_json_log(json_log);
    g_firewall.set_default_action(default_action);

    RateLimiter::Config rl_cfg;
    rl_cfg.max_packets_per_second = 2000;
    rl_cfg.max_syn_per_second = 100;
    rl_cfg.max_conn_per_source = 200;
    rl_cfg.max_icmp_per_second = 30;
    rl_cfg.block_duration_seconds = 300;
    g_firewall.rate_limiter().configure(rl_cfg);

    g_firewall.conn_tracker().set_limits(131072, 300, 60);

    if (!rules_file.empty()) {
        g_firewall.rule_engine().load_from_file(rules_file);
    } else {
        std::cout << "[*] Loading default rules..." << std::endl;
        setup_default_rules(g_firewall.rule_engine());
    }

    g_firewall.print_rules();

    if (!g_firewall.init()) {
        FW_LOG_FATAL("Firewall initialization failed");
        return 1;
    }

    std::cout << "[*] Firewall is running. Press Ctrl+C to stop.\n" << std::endl;

    std::thread shell_thread(interactive_shell, std::ref(g_firewall));

    g_firewall.start();

    if (shell_thread.joinable())
        shell_thread.join();

    g_firewall.print_stats();
    Logger::instance().close();

    std::cout << "[*] Firewall stopped." << std::endl;
    return 0;
}
