#include <sstream>
#include <iostream>
#include <cmath>
#include "Conversation.h"

namespace FeatureExtractor {
    using namespace std;

    // Array for mapping service_t to string (char *)
    // ! Update with enum service_t (in Conversation.h)
    const char *const Conversation::SERVICE_NAMES[NUMBER_OF_SERVICES] = {
            // General
            "other",
            "private",

            // ICMP
            "ecr_i",
            "urp_i",
            "urh_i",
            "red_i",
            "eco_i",
            "tim_i",
            "oth_i",

            // UDP
            "domain_u",
            "tftp_u",
            "ntp_u",

            // TCP
            "IRC",
            "X11",
            "Z39_50",
            "aol",
            "auth",
            "bgp",
            "courier",
            "csnet_ns",
            "ctf",
            "daytime",
            "discard",
            "domain",
            "echo",
            "efs",
            "exec",
            "finger",
            "ftp",
            "ftp_data",
            "gopher",
            "harvest",
            "hostnames",
            "http",
            "http_2784",
            "http_443",
            "http_8001",
            "icmp",
            "imap4",
            "iso_tsap",
            "klogin",
            "kshell",
            "ldap",
            "link",
            "login",
            "mtp",
            "name",
            "netbios_dgm",
            "netbios_ns",
            "netbios_ssn",
            "netstat",
            "nnsp",
            "nntp",
            "pm_dump",
            "pop_2",
            "pop_3",
            "printer",
            "remote_job",
            "rje",
            "shell",
            "smtp",
            "sql_net",
            "ssh",
            "sunrpc",
            "supdup",
            "systat",
            "telnet",
            "time",
            "uucp",
            "uucp_path",
            "vmnet",
            "whois"
    };

    Conversation::Conversation()
            : five_tuple() {
        init_values();
    }

    Conversation::Conversation(const FiveTuple *tuple)
            : five_tuple(*tuple) {
        init_values();
    }

    Conversation::Conversation(const Packet *packet)
            : five_tuple(packet->get_five_tuple()) {
        init_values();
    }


    Conversation::~Conversation() = default;

    void Conversation::init_values() {
        state = INIT;

        src_packets = 0;
        src_bytes_sum = 0;
        src_bytes_max = 0;
        src_bytes_min = 0;
        src_bytes_squ = 0;
        src_start_ts = Timestamp();
        src_last_ts = Timestamp();
        src_gap_ms_sum = 0;
        src_gap_ms_max = 0;
        src_gap_ms_min = 0;
        src_gap_ms_squ = 0;

        dst_bytes_sum = 0;
        dst_bytes_max = 0;
        dst_bytes_min = 0;
        dst_bytes_squ = 0;
        dst_packets = 0;
        dst_start_ts = Timestamp();
        dst_last_ts = Timestamp();
        dst_gap_ms_sum = 0;
        dst_gap_ms_max = 0;
        dst_gap_ms_min = 0;
        dst_gap_ms_squ = 0;

        packets = 0;
        start_ts = Timestamp();
        last_ts = Timestamp();

        wrong_fragments = 0;
        urgent_packets = 0;
    }


    FiveTuple Conversation::get_five_tuple() const {
        return five_tuple;
    }

    const FiveTuple *Conversation::get_five_tuple_ptr() const {
        return &five_tuple;
    }

    conversation_state_t Conversation::get_internal_state() const {
        return state;
    }

    conversation_state_t Conversation::get_state() const {
        // Replace internal states
        switch (state) {
            case ESTAB:
                return S1;
                break;

            case S4:
                return OTH;
                break;

            case S2F:
                return S2;
                break;

            case S3F:
                return S3;
                break;

            default:
                return state;
                break;
        }
        return state;
    }

    bool Conversation::is_in_final_state() const {
        // By default conversation will not end by state transition.
        // TCP subclass will by the special case that will override this.
        return false;
    }

    // region Duration
    Timestamp Conversation::get_start_ts() const {
        return start_ts;
    }

    Timestamp Conversation::get_last_ts() const {
        return last_ts;
    }

    uint64_t Conversation::get_duration_ms() const {
        return (last_ts - start_ts).get_total_msecs();
    }

    uint64_t Conversation::get_src_duration_ms() const {
        return (src_last_ts - src_start_ts).get_total_msecs();
    }

    uint64_t Conversation::get_dst_duration_ms() const {
        return (dst_last_ts - dst_start_ts).get_total_msecs();
    }
    // endregion

    double calculate_standard_deviation(size_t n, double sum, double squ_sum) {
        return sqrt(squ_sum / n - (sum / n) * (sum / n));
    }

    // region Src bytes
    size_t Conversation::get_src_bytes_sum() const {
        return src_bytes_sum;
    }

    double Conversation::get_src_bytes_avg() const {
        return src_bytes_sum * 1.0 / src_packets;
    }

    size_t Conversation::get_src_bytes_max() const {
        return src_bytes_max;
    }

    size_t Conversation::get_src_bytes_min() const {
        return src_bytes_min;
    }

    double Conversation::get_src_bytes_std() const {
        if (src_packets == 0) return 0.0;
        return calculate_standard_deviation(src_packets, src_bytes_sum * 1.0, src_bytes_squ * 1.0);
    }

    double Conversation::get_src_bytes_rate() const {
        uint64_t duration = get_src_duration_ms();
        if (src_packets == 0 || duration == 0) return 0.0;
        return src_bytes_sum * 1.0 / duration;
    }
    // endregion

    // region Dst bytes
    size_t Conversation::get_dst_bytes_sum() const {
        return dst_bytes_sum;
    }

    double Conversation::get_dst_bytes_avg() const {
        return dst_bytes_sum * 1.0 / dst_packets;
    }

    size_t Conversation::get_dst_bytes_max() const {
        return dst_bytes_max;
    }

    size_t Conversation::get_dst_bytes_min() const {
        return dst_bytes_min;
    }

    double Conversation::get_dst_bytes_std() const {
        if (dst_packets == 0) return 0.0;
        return calculate_standard_deviation(dst_packets, dst_bytes_sum * 1.0, dst_bytes_squ * 1.0);
    }

    double Conversation::get_dst_bytes_rate() const {
        uint64_t duration = get_dst_duration_ms();
        if (dst_packets == 0 || duration == 0) return 0.0;
        return dst_bytes_sum * 1.0 / duration;
    }
    // endregion

    double Conversation::get_bytes_rate() const {
        uint64_t duration = get_duration_ms();
        if (src_packets + dst_packets == 0 || duration == 0) return 0.0;
        return (src_bytes_sum + dst_bytes_sum) * 1.0 / duration;
    }

    // region Packets
    uint32_t Conversation::get_packets() const {
        return packets;
    }

    uint32_t Conversation::get_src_packets() const {
        return src_packets;
    }

    uint32_t Conversation::get_dst_packets() const {
        return dst_packets;
    }

    double Conversation::get_packets_rate() const {
        uint64_t duration = get_duration_ms();
        if (src_packets + dst_packets == 0 || duration == 0) return 0.0;
        return packets * 1.0 / duration;
    }

    double Conversation::get_src_packets_rate() const {
        uint64_t duration = get_src_duration_ms();
        if (src_packets == 0 || duration == 0) return 0.0;
        return src_packets * 1.0 / duration;
    }

    double Conversation::get_dst_packets_rate() const {
        uint64_t duration = get_dst_duration_ms();
        if (dst_packets == 0 || duration == 0) return 0.0;
        return dst_packets * 1.0 / duration;
    }
    //endregion

    // region Src gap
    uint64_t Conversation::get_src_gap_sum() const {
        return src_gap_ms_sum;
    }

    double Conversation::get_src_gap_avg() const {
        if (src_packets < 2) return 0.0;
        return src_gap_ms_sum * 1.0 / (src_packets - 1);
    }

    uint64_t Conversation::get_src_gap_max() const {
        return src_gap_ms_max;
    }

    uint64_t Conversation::get_src_gap_min() const {
        return src_gap_ms_min;
    }

    double Conversation::get_src_gap_std() const {
        if (src_packets < 2) return 0.0;
        return calculate_standard_deviation(src_packets - 1, src_gap_ms_sum, src_gap_ms_squ);
    }
    //endregion

    // region Dst gap
    uint64_t Conversation::get_dst_gap_sum() const {
        return dst_gap_ms_sum;
    }

    double Conversation::get_dst_gap_avg() const {
        if (dst_packets < 2) return 0.0;
        return dst_gap_ms_sum * 1.0 / (dst_packets - 1);
    }

    uint64_t Conversation::get_dst_gap_max() const {
        return dst_gap_ms_max;
    }

    uint64_t Conversation::get_dst_gap_min() const {
        return dst_gap_ms_min;
    }

    double Conversation::get_dst_gap_std() const {
        if (dst_packets < 2) return 0.0;
        return calculate_standard_deviation(dst_packets - 1, dst_gap_ms_sum, dst_gap_ms_squ);
    }
    //endregion

    uint32_t Conversation::get_wrong_fragments() const {
        return wrong_fragments;
    }

    uint32_t Conversation::get_urgent_packets() const {
        return urgent_packets;
    }

    const char *Conversation::get_service_str() const {
        // Ensure size of strins matches number of values for enum at compilation time
#ifdef static_assert
        static_assert(sizeof(Conversation::SERVICE_NAMES) / sizeof(char *) == NUMBER_OF_SERVICES,
            "Mapping of services to strings failed: number of string does not match number of values");
#endif

        return SERVICE_NAMES[get_service()];
    }

    const char *Conversation::get_protocol_type_str() const {
        switch (five_tuple.get_ip_proto()) {
            case TCP:
                return "tcp";
                break;
            case UDP:
                return "udp";
                break;
            case ICMP:
                return "icmp";
                break;
            default:
                break;
        }
        return "UNKNOWN";
    }

    bool Conversation::land() const {
        return five_tuple.land();
    }

    bool Conversation::is_serror() const {
        switch (get_state()) {
            case S0:
            case S1:
            case S2:
            case S3:
                return true;
                break;

            default:
                break;
        }

        return false;
    }

    bool Conversation::is_rerror() const {
        return (get_state() == REJ);
    }

    bool Conversation::add_packet(const Packet *packet) {
        // Timestamps
        if (packets == 0)
            start_ts = packet->get_start_ts();
        last_ts = packet->get_end_ts();

        // Add byte counts for correct direction
        size_t packet_length = packet->get_length();
        if (packet->get_src_ip() == five_tuple.get_src_ip()) {
            if (src_packets == 0) {
                src_start_ts = packet->get_start_ts();
                src_last_ts = packet->get_end_ts();
                src_bytes_min = packet_length;
            } else {
                int64_t gap = (packet->get_start_ts() - src_last_ts).get_total_msecs();
                if (src_packets == 1) {
                    src_gap_ms_min = gap;
                }
                src_gap_ms_sum += gap;
                src_gap_ms_max = max(src_gap_ms_max, gap);
                src_gap_ms_min = min(src_gap_ms_min, gap);
                src_gap_ms_squ += gap * gap;
            }
            src_last_ts = packet->get_end_ts();

            src_bytes_sum += packet_length;
            src_bytes_max = max(src_bytes_max, packet_length);
            src_bytes_min = min(src_bytes_min, packet_length);
            src_bytes_squ += packet_length * packet_length;
            src_packets++;
        } else {
            if (dst_packets == 0) {
                dst_start_ts = packet->get_start_ts();
                dst_last_ts = packet->get_end_ts();
                dst_bytes_min = packet_length;
            } else {
                int64_t gap = (packet->get_start_ts() - dst_last_ts).get_total_msecs();
                if (dst_packets == 1) {
                    dst_gap_ms_min = gap;
                }
                dst_gap_ms_sum += gap;
                dst_gap_ms_max = max(dst_gap_ms_max, gap);
                dst_gap_ms_min = min(dst_gap_ms_min, gap);
                dst_gap_ms_squ += gap * gap;
            }
            dst_last_ts = packet->get_end_ts();

            dst_bytes_sum += packet->get_length();
            dst_bytes_max = max(dst_bytes_max, packet_length);
            dst_bytes_min = min(dst_bytes_min, packet_length);
            dst_bytes_squ += packet_length * packet_length;
            dst_packets++;
        }

        // Packet counts
        //TODO: wrong_fragments
        packets++;
        if (packet->get_tcp_flags().urg())
            urgent_packets++;

        // Make state transitions according to packet
        update_state(packet);

        return is_in_final_state();
    }

    void Conversation::update_state(const Packet *packet) {
        // By default conversation can only get to state SF (after any packet).
        // TCP subclass will by the special case that will override this.
        state = SF;
    }

    const char *Conversation::get_state_str() const {
        return state_to_str(get_state());
    }

    // TODO: use mapping by array fo char*s ?
    const char *Conversation::state_to_str(conversation_state_t state) {
        switch (state) {
            case INIT:
                return "INIT";
                break;
            case S0:
                return "S0";
                break;
            case S1:
                return "S1";
                break;
            case S2:
                return "S2";
                break;
            case S3:
                return "S3";
                break;
            case SF:
                return "SF";
                break;
            case REJ:
                return "REJ";
                break;
            case RSTOS0:
                return "RSTOS0";
                break;
            case RSTO:
                return "RSTO";
                break;
            case RSTR:
                return "RSTR";
                break;
            case SH:
                return "SH";
                break;
            case RSTRH:
                return "RSTRH";
                break;
            case SHR:
                return "SHR";
                break;
            case OTH:
                return "OTH";
                break;
            case ESTAB:
                return "ESTAB";
                break;
            case S4:
                return "S4";
                break;
            case S2F:
                return "S2F";
                break;
            case S3F:
                return "S3F";
                break;
            default:
                break;
        }

        return "UNKNOWN";
    }

    bool Conversation::operator<(const Conversation &other) const {
        return (this->get_last_ts() < other.get_last_ts());
    }


// Allow using localtime instead of localtime_s 
#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

    void Conversation::print_human() const {
        // TODO: WTF ugly code, just for debugging, so nasrac..
        stringstream ss;

        struct tm *ltime;
        //struct tm timeinfo;
        char timestr[16];
        time_t local_tv_sec;
        //local_tv_sec = start_ts.get_secs();
        ltime = localtime(&local_tv_sec);
        //localtime_s(&timeinfo, &local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
        //strftime(timestr, sizeof timestr, "%H:%M:%S", &timeinfo);

        ss << "CONVERSATION ";
        if (five_tuple.get_ip_proto() == ICMP) {
            ss << " > ICMP";
        } else if (five_tuple.get_ip_proto() == TCP) {
            ss << " > TCP ";
        } else if (five_tuple.get_ip_proto() == UDP) {
            ss << " > UDP ";
        }
        ss << " > " << get_service_str() << endl;
        ss << timestr;
        ss << " duration=" << get_duration_ms() << "ms" << endl;

        // Cast ips to arrays of octets
        // TODO: WTF ugly code, aaah..
        uint32_t src_ip = five_tuple.get_src_ip();
        uint32_t dst_ip = five_tuple.get_dst_ip();
        uint8_t *sip = (uint8_t *) &src_ip;
        uint8_t *dip = (uint8_t *) &dst_ip;

        ss << "  " << (int) sip[0] << "." << (int) sip[1] << "." << (int) sip[2] << "." << (int) sip[3] << ":"
           << five_tuple.get_src_port();
        ss << " --> " << (int) dip[0] << "." << (int) dip[1] << "." << (int) dip[2] << "." << (int) dip[3] << ":"
           << five_tuple.get_dst_port() << endl;
        ss << "  src_bytes_sum=" << src_bytes_sum << " dst_bytes_sum=" << dst_bytes_sum << " land=" << land() << endl;
        ss << "  pkts=" << packets << " src_pkts=" << src_packets << " dst_pkts=" << dst_packets << endl;
        ss << "  wrong_frags=" << wrong_fragments << " urg_pkts=" << urgent_packets << endl;
        ss << "  state=" << get_state_str() << " internal_state=" << state_to_str(state) << endl;
        ss << endl;

        cout << ss.str();
    }
}