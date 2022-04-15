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

        start_ts = Timestamp();
        last_ts = Timestamp();
        conn_packets = 0;
        conn_gap_ms_sum = 0;
        conn_gap_ms_max = 0;
        conn_gap_ms_min = 0;
        conn_gap_ms_squ = 0;

        wrong_fragments = 0;
        cwr_packets = 0;
        ece_packets = 0;
        urg_packets = 0;
        ack_packets = 0;
        psh_packets = 0;
        rst_packets = 0;
        syn_packets = 0;
        fin_packets = 0;

        src_cwr_packets = 0;
        src_ece_packets = 0;
        src_urg_packets = 0;
        src_ack_packets = 0;
        src_psh_packets = 0;
        src_rst_packets = 0;
        src_syn_packets = 0;
        src_fin_packets = 0;

        dst_cwr_packets = 0;
        dst_ece_packets = 0;
        dst_urg_packets = 0;
        dst_ack_packets = 0;
        dst_psh_packets = 0;
        dst_rst_packets = 0;
        dst_syn_packets = 0;
        dst_fin_packets = 0;

        src_init_window_size = -1;
        src_init_window_bytes = 0;
        dst_init_window_size = -1;
        dst_init_window_bytes = 0;
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
        if (src_bytes_sum == 0) return 0.0;
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
        if (dst_bytes_sum == 0) return 0.0;
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

    // region Connection bytes
    size_t Conversation::get_conn_bytes_sum() const {
        return src_bytes_sum + dst_bytes_sum;
    }

    double Conversation::get_conn_bytes_avg() const {
        return (src_bytes_sum + dst_bytes_sum) * 1.0 / conn_packets;
    }

    size_t Conversation::get_conn_bytes_max() const {
        return max(src_bytes_max, dst_bytes_max);
    }

    size_t Conversation::get_conn_bytes_min() const {
        return min(src_bytes_min, dst_bytes_min);
    }

    double Conversation::get_conn_bytes_std() const {
        return calculate_standard_deviation(conn_packets, (src_bytes_sum + dst_bytes_sum) * 1.0, (src_bytes_squ + dst_bytes_squ) * 1.0);
    }

    double Conversation::get_conn_bytes_rate() const {
        uint64_t duration = get_duration_ms();
        if (src_packets + dst_packets == 0 || duration == 0) return 0.0;
        return (src_bytes_sum + dst_bytes_sum) * 1.0 / duration;
    }
    //endregion

    // region Packets
    uint32_t Conversation::get_conn_packets() const {
        return conn_packets;
    }

    uint32_t Conversation::get_src_packets() const {
        return src_packets;
    }

    uint32_t Conversation::get_dst_packets() const {
        return dst_packets;
    }

    double Conversation::get_conn_packets_rate() const {
        uint64_t duration = get_duration_ms();
        if (src_packets + dst_packets == 0 || duration == 0) return 0.0;
        return conn_packets * 1.0 / duration;
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

    // region Gap
    uint64_t Conversation::get_conn_gap_sum() const {
        return conn_gap_ms_sum;
    }

    double Conversation::get_conn_gap_avg() const {
        if (conn_packets < 2) return 0.0;
        return conn_gap_ms_sum * 1.0 / (conn_packets - 1);
    }

    uint64_t Conversation::get_conn_gap_max() const {
        return conn_gap_ms_max;
    }

    uint64_t Conversation::get_conn_gap_min() const {
        return conn_gap_ms_min;
    }

    double Conversation::get_conn_gap_std() const {
        if (conn_packets < 2) return 0.0;
        return calculate_standard_deviation(conn_packets - 1, conn_gap_ms_sum, conn_gap_ms_squ);
    }
    // endregion

    uint32_t Conversation::get_wrong_fragments() const {
        return wrong_fragments;
    }

    double Conversation::get_down_up_bytes_ratio() const {
        if (src_bytes_sum == 0 || dst_bytes_sum == 0) return 0;
        return dst_bytes_sum * 1.0 / src_bytes_sum;
    }

    double Conversation::get_down_up_packets_ratio() const {
        if (src_packets == 0 || dst_packets == 0) return 0;
        return dst_packets * 1.0 / src_packets;
    }

    uint32_t Conversation::get_src_init_window_bytes() const {
        return src_init_window_bytes;
    }

    uint32_t Conversation::get_dst_init_window_bytes() const {
        return dst_init_window_bytes;
    }

    // region Tcp flags
    uint32_t Conversation::get_cwr_packets() const {
        return cwr_packets;
    }

    uint32_t Conversation::get_ece_packets() const {
        return ece_packets;
    }

    uint32_t Conversation::get_urg_packets() const {
        return urg_packets;
    }

    uint32_t Conversation::get_ack_packets() const {
        return ack_packets;
    }

    uint32_t Conversation::get_psh_packets() const {
        return psh_packets;
    }

    uint32_t Conversation::get_rst_packets() const {
        return rst_packets;
    }

    uint32_t Conversation::get_syn_packets() const {
        return syn_packets;
    }

    uint32_t Conversation::get_fin_packets() const {
        return fin_packets;
    }
    // endregion

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
            case UDP:
                return "udp";
            case ICMP:
                return "icmp";
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
        if (conn_packets == 0)
            start_ts = packet->get_start_ts();
        else {
            int64_t gap = (packet->get_start_ts() - last_ts).get_total_msecs();
            if (conn_packets == 1)
                conn_gap_ms_min = gap;
            conn_gap_ms_sum += gap;
            conn_gap_ms_max = max(conn_gap_ms_max, gap);
            conn_gap_ms_min = min(conn_gap_ms_min, gap);
            conn_gap_ms_squ += gap * gap;
        }
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

            if (packet->get_tcp_flags().cwr()) src_cwr_packets++;
            if (packet->get_tcp_flags().ece()) src_ece_packets++;
            if (packet->get_tcp_flags().urg()) src_urg_packets++;
            if (packet->get_tcp_flags().ack()) src_ack_packets++;
            if (packet->get_tcp_flags().psh()) src_psh_packets++;
            if (packet->get_tcp_flags().rst()) src_rst_packets++;
            if (packet->get_tcp_flags().syn()) src_syn_packets++;
            if (packet->get_tcp_flags().fin()) src_fin_packets++;

            if (packet->get_ip_proto() == TCP) {
                if (src_init_window_size == -1)
                    src_init_window_size = packet->get_tcp_window_size();
                if (src_init_window_size == packet->get_tcp_window_size())
                    src_init_window_bytes += packet_length;
                else
                    src_init_window_size = -2;
            }
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

            if (packet->get_tcp_flags().cwr()) dst_cwr_packets++;
            if (packet->get_tcp_flags().ece()) dst_ece_packets++;
            if (packet->get_tcp_flags().urg()) dst_urg_packets++;
            if (packet->get_tcp_flags().ack()) dst_ack_packets++;
            if (packet->get_tcp_flags().psh()) dst_psh_packets++;
            if (packet->get_tcp_flags().rst()) dst_rst_packets++;
            if (packet->get_tcp_flags().syn()) dst_syn_packets++;
            if (packet->get_tcp_flags().fin()) dst_fin_packets++;

            if (packet->get_ip_proto() == TCP) {
                if (dst_init_window_size == -1)
                    dst_init_window_size = packet->get_tcp_window_size();
                if (dst_init_window_size == packet->get_tcp_window_size())
                    dst_init_window_bytes += packet_length;
                else
                    dst_init_window_size = -2;
            }
        }

        // Packet counts
        //TODO: wrong_fragments
        conn_packets++;
        if (packet->get_tcp_flags().cwr()) cwr_packets++;
        if (packet->get_tcp_flags().ece()) ece_packets++;
        if (packet->get_tcp_flags().urg()) urg_packets++;
        if (packet->get_tcp_flags().ack()) ack_packets++;
        if (packet->get_tcp_flags().psh()) psh_packets++;
        if (packet->get_tcp_flags().rst()) rst_packets++;
        if (packet->get_tcp_flags().syn()) syn_packets++;
        if (packet->get_tcp_flags().fin()) fin_packets++;

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
            case S0:
                return "S0";
            case S1:
                return "S1";
            case S2:
                return "S2";
            case S3:
                return "S3";
            case SF:
                return "SF";
            case REJ:
                return "REJ";
            case RSTOS0:
                return "RSTOS0";
            case RSTO:
                return "RSTO";
            case RSTR:
                return "RSTR";
            case SH:
                return "SH";
            case RSTRH:
                return "RSTRH";
            case SHR:
                return "SHR";
            case OTH:
                return "OTH";
            case ESTAB:
                return "ESTAB";
            case S4:
                return "S4";
            case S2F:
                return "S2F";
            case S3F:
                return "S3F";
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
        ss << "  pkts=" << conn_packets << " src_pkts=" << src_packets << " dst_pkts=" << dst_packets << endl;
        ss << "  wrong_frags=" << wrong_fragments << " urg_pkts=" << urg_packets << endl;
        ss << "  state=" << get_state_str() << " internal_state=" << state_to_str(state) << endl;
        ss << endl;

        cout << ss.str();
    }

    uint32_t Conversation::get_src_cwr_packets() const {
        return src_cwr_packets;
    }

    uint32_t Conversation::get_src_ece_packets() const {
        return src_ece_packets;
    }

    uint32_t Conversation::get_src_urg_packets() const {
        return src_urg_packets;
    }

    uint32_t Conversation::get_src_ack_packets() const {
        return src_ack_packets;
    }

    uint32_t Conversation::get_src_psh_packets() const {
        return src_psh_packets;
    }

    uint32_t Conversation::get_src_rst_packets() const {
        return src_rst_packets;
    }

    uint32_t Conversation::get_src_syn_packets() const {
        return src_syn_packets;
    }

    uint32_t Conversation::get_src_fin_packets() const {
        return src_fin_packets;
    }

    uint32_t Conversation::get_dst_cwr_packets() const {
        return dst_cwr_packets;
    }

    uint32_t Conversation::get_dst_ece_packets() const {
        return dst_ece_packets;
    }

    uint32_t Conversation::get_dst_urg_packets() const {
        return dst_urg_packets;
    }

    uint32_t Conversation::get_dst_ack_packets() const {
        return dst_ack_packets;
    }

    uint32_t Conversation::get_dst_psh_packets() const {
        return dst_psh_packets;
    }

    uint32_t Conversation::get_dst_rst_packets() const {
        return dst_rst_packets;
    }

    uint32_t Conversation::get_dst_syn_packets() const {
        return dst_syn_packets;
    }

    uint32_t Conversation::get_dst_fin_packets() const {
        return dst_fin_packets;
    }
}