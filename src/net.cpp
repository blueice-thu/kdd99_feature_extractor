#include "net.h"

namespace FeatureExtractor {
    bool ether_header_t::is_ethernet2() const {
        return (ntohs(type_length) >= MIN_ETH2);
    }

    bool ether_header_t::is_type_ipv4() const {
        return (ntohs(type_length) == IPV4);
    }

    uint8_t *ether_header_t::get_eth2_sdu() const {
        return (((uint8_t *) this) + ETH2_HEADER_LENGTH);
    }


    uint8_t ip_header_t::ihl() const {
        return (ver_ihl & 0x0F);
    }

    size_t ip_header_t::header_length() const {
        return ihl() * sizeof(uint32_t);
    }

    uint8_t ip_header_t::flags() const {
        return (ntohs(flags_fo) >> 13) & 0x7;
    }

    bool ip_header_t::flag_eb() const {
        return ((flags() & 0x1) != 0);
    }

    bool ip_header_t::flag_df() const {
        return ((flags() & 0x2) != 0);
    }

    bool ip_header_t::flag_mf() const {
        return ((flags() & 0x4) != 0);
    }

    size_t ip_header_t::frag_offset() const {
        return (ntohs(flags_fo) & 0x01FFF) << 3; // 1 unit = 8 bytes
    }

    const char *ip_header_t::protocol_str() const {
        switch (protocol) {
            case ICMP:
                return "ICMP";
                break;
            case TCP:
                return "TCP";
                break;
            case UDP:
                return "UDP";
                break;
            default:
                break;
        }
        return "other";
    }

    uint8_t *ip_header_t::get_sdu() const {
        return (((uint8_t *) this) + header_length());
    }

    size_t tcp_header_t::header_length() const {
        return (size_t)((data_offset >> 4) & (uint8_t)0x0f) * 4;
    }

    uint8_t *tcp_header_t::get_sdu() const {
//        char *sdu = (char*)(((uint8_t *) this) + header_length());
//        char *temp = sdu;
//        char a1 = *temp++;
//        char a2 = *temp++;
//        char a3 = *temp++;
//        char a4 = *temp++;
//        if (a1 == 'H' && a2 == 'T') {
//            for (size_t i = 0; i < 1280; i++) {
//                printf("%c", *sdu++);
//            }
//            a2 = a3;
//        }
        return (((uint8_t *) this) + header_length());
    }

    tcp_field_flags_t::tcp_field_flags_t(uint8_t flags)
            : flags(flags) {}

    tcp_field_flags_t::tcp_field_flags_t()
            : flags(0) {}

    bool tcp_field_flags_t::fin() const {
        return ((flags & 0x01) != 0);
    }

    bool tcp_field_flags_t::syn() const {
        return ((flags & 0x02) != 0);
    }

    bool tcp_field_flags_t::rst() const {
        return ((flags & 0x04) != 0);
    }

    bool tcp_field_flags_t::psh() const {
        return ((flags & 0x08) != 0);
    }

    bool tcp_field_flags_t::ack() const {
        return ((flags & 0x10) != 0);
    }

    bool tcp_field_flags_t::urg() const {
        return ((flags & 0x20) != 0);
    }

    bool tcp_field_flags_t::ece() const {
        return ((flags & 0x40) != 0);
    }

    bool tcp_field_flags_t::cwr() const {
        return ((flags & 0x80) != 0);
    }
}