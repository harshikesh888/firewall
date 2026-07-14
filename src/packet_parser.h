#pragma once

#include "types.h"
#include <cstring>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

class PacketParser {
public:
    static bool parse(const uint8_t* raw, size_t len, PacketInfo& info) {
        if (len < sizeof(struct iphdr))
            return false;

        const struct iphdr* ip = reinterpret_cast<const struct iphdr*>(raw);

        info.src_ip     = ip->saddr;
        info.dst_ip     = ip->daddr;
        info.protocol   = ip->protocol;
        info.packet_len = ntohs(ip->tot_len);
        info.raw_data   = raw;
        info.raw_len    = len;

        size_t ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || len < ip_hdr_len)
            return false;

        switch (ip->protocol) {
            case IPPROTO_TCP: {
                if (len < ip_hdr_len + sizeof(struct tcphdr))
                    return false;
                const struct tcphdr* tcp =
                    reinterpret_cast<const struct tcphdr*>(raw + ip_hdr_len);
                info.src_port = ntohs(tcp->source);
                info.dst_port = ntohs(tcp->dest);
                info.tcp_flags = *(reinterpret_cast<const unsigned char*>(tcp) + 13);
                break;
            }
            case IPPROTO_UDP: {
                if (len < ip_hdr_len + sizeof(struct udphdr))
                    return false;
                const struct udphdr* udp =
                    reinterpret_cast<const struct udphdr*>(raw + ip_hdr_len);
                info.src_port = ntohs(udp->source);
                info.dst_port = ntohs(udp->dest);
                break;
            }
            case IPPROTO_ICMP: {
                if (len < ip_hdr_len + sizeof(struct icmphdr))
                    return false;
                info.src_port = 0;
                info.dst_port = 0;
                break;
            }
            default:
                break;
        }
        return true;
    }

    static std::string get_tcp_flag_str(uint8_t flags) {
        std::string result;
        if (flags & 0x01) result += "FIN ";
        if (flags & 0x02) result += "SYN ";
        if (flags & 0x04) result += "RST ";
        if (flags & 0x08) result += "PSH ";
        if (flags & 0x10) result += "ACK ";
        if (flags & 0x20) result += "URG ";
        if (result.empty()) result = "NONE";
        else result.pop_back();
        return result;
    }
};
