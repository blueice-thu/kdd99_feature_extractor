#pragma once

#include "net.h"
#include "ReferenceCounter.h"
#include "Packet.h"
#include "FiveTuple.h"
#include "Timestamp.h"

namespace FeatureExtractor {

    /**
     * Conversatiov states
     *	- INIT & SF for all protocols except TCP
     *	- other states specific to TCP
     * Description from https://www.bro.org/sphinx/scripts/base/protocols/conn/main.bro.html
     */
    enum conversation_state_t {
        // General states
        INIT,        // Nothing happened yet.
        SF,            // Normal establishment and termination. Note that this is the same
        // symbol as for state S1. You can tell the two apart because for S1 there
        // will not be any byte counts in the summary, while for SF there will be.

        // TCP specific
        S0,            // Connection attempt seen, no reply.
        S1,            // Connection established, not terminated.
        S2,            // Connection established and close attempt by originator seen (but no reply from responder).
        S3,            // Connection established and close attempt by responder seen (but no reply from originator).
        REJ,        // Connection attempt rejected.
        RSTOS0,        // Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.
        RSTO,        // Connection established, originator aborted (sent a RST).
        RSTR,        // Established, responder aborted.
        SH,            // Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder (hence the connection was �half� open).
        RSTRH,        // Responder sent a SYN ACK followed by a RST, we never saw a SYN from the (purported) originator.
        SHR,        // Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.
        OTH,        // No SYN seen, just midstream traffic (a "partial connection" that was not later closed).

        // Internal states (TCP-specific)
        ESTAB,        // Established - ACK send by originator in S1 state; externally represented as S1
        S4,            // SYN ACK seen - State between INIT and (RSTRH or SHR); externally represented as OTH
        S2F,        // FIN send by responder in state S2 - waiting for final ACK; externally represented as S2
        S3F            // FIN send by originator in state S3 - waiting for final ACK; externally represented as S3
    };

    /**
     * Services
     * ! order & number of services must be the same in string mapping
     * see Conversation::SERVICE_NAMES[] in Conversation.cpp
     */
    enum service_t {
        // General
        SRV_OTHER,
        SRV_PRIVATE,

        // ICMP
        SRV_ECR_I,
        SRV_URP_I,
        SRV_URH_I,
        SRV_RED_I,
        SRV_ECO_I,
        SRV_TIM_I,
        SRV_OTH_I,

        // UDP
        SRV_DOMAIN_U,
        SRV_TFTP_U,
        SRV_NTP_U,

        // TCP
        SRV_IRC,
        SRV_X11,
        SRV_Z39_50,
        SRV_AOL,
        SRV_AUTH,
        SRV_BGP,
        SRV_COURIER,
        SRV_CSNET_NS,
        SRV_CTF,
        SRV_DAYTIME,
        SRV_DISCARD,
        SRV_DOMAIN,
        SRV_ECHO,
        SRV_EFS,
        SRV_EXEC,
        SRV_FINGER,
        SRV_FTP,
        SRV_FTP_DATA,
        SRV_GOPHER,
        SRV_HARVEST,
        SRV_HOSTNAMES,
        SRV_HTTP,
        SRV_HTTP_2784,
        SRV_HTTP_443,
        SRV_HTTP_8001,
        SRV_ICMP,
        SRV_IMAP4,
        SRV_ISO_TSAP,
        SRV_KLOGIN,
        SRV_KSHELL,
        SRV_LDAP,
        SRV_LINK,
        SRV_LOGIN,
        SRV_MTP,
        SRV_NAME,
        SRV_NETBIOS_DGM,
        SRV_NETBIOS_NS,
        SRV_NETBIOS_SSN,
        SRV_NETSTAT,
        SRV_NNSP,
        SRV_NNTP,
        SRV_PM_DUMP,
        SRV_POP_2,
        SRV_POP_3,
        SRV_PRINTER,
        SRV_REMOTE_JOB,
        SRV_RJE,
        SRV_SHELL,
        SRV_SMTP,
        SRV_SQL_NET,
        SRV_SSH,
        SRV_SUNRPC,
        SRV_SUPDUP,
        SRV_SYSTAT,
        SRV_TELNET,
        SRV_TIME,
        SRV_UUCP,
        SRV_UUCP_PATH,
        SRV_VMNET,
        SRV_WHOIS,

        // This must be the last
        NUMBER_OF_SERVICES
    };


    /**
     * Abstract Conversation (incorrectly called connection when not talking about TCP)
     *
     * Every instance can keep the number of references(pointers) to itself. If the this number
     * is decremented to zero, the object commits suicide (delete this).
     * See class ReferenceCounter.
     */
    class Conversation : public ReferenceCounter {

        // Array for mapping service_t to string (char *)
        static const char *const SERVICE_NAMES[NUMBER_OF_SERVICES];

    protected:
        FiveTuple five_tuple;
        conversation_state_t state;

        uint32_t src_packets;
        size_t src_bytes_sum;
        size_t src_bytes_max;
        size_t src_bytes_min;
        size_t src_bytes_squ;
        Timestamp src_start_ts;
        Timestamp src_last_ts;
        int64_t src_gap_ms_sum;
        int64_t src_gap_ms_max;
        int64_t src_gap_ms_min;
        int64_t src_gap_ms_squ;

        uint32_t dst_packets;
        size_t dst_bytes_sum;
        size_t dst_bytes_max;
        size_t dst_bytes_min;
        size_t dst_bytes_squ;
        Timestamp dst_start_ts;
        Timestamp dst_last_ts;
        int64_t dst_gap_ms_sum;
        int64_t dst_gap_ms_max;
        int64_t dst_gap_ms_min;
        int64_t dst_gap_ms_squ;

        uint32_t conn_packets;
        Timestamp start_ts;
        Timestamp last_ts;
        int64_t conn_gap_ms_sum;
        int64_t conn_gap_ms_max;
        int64_t conn_gap_ms_min;
        int64_t conn_gap_ms_squ;

        uint32_t wrong_fragments;
        uint32_t cwr_packets;
        uint32_t ece_packets;
        uint32_t urg_packets;
        uint32_t ack_packets;
        uint32_t psh_packets;
        uint32_t rst_packets;
        uint32_t syn_packets;
        uint32_t fin_packets;

        uint32_t src_cwr_packets;
        uint32_t src_ece_packets;
        uint32_t src_urg_packets;
        uint32_t src_ack_packets;
        uint32_t src_psh_packets;
        uint32_t src_rst_packets;
        uint32_t src_syn_packets;
        uint32_t src_fin_packets;

        uint32_t dst_cwr_packets;
        uint32_t dst_ece_packets;
        uint32_t dst_urg_packets;
        uint32_t dst_ack_packets;
        uint32_t dst_psh_packets;
        uint32_t dst_rst_packets;
        uint32_t dst_syn_packets;
        uint32_t dst_fin_packets;

        int32_t src_init_window_size;
        uint32_t src_init_window_bytes;
        int32_t dst_init_window_size;
        uint32_t dst_init_window_bytes;

        uint32_t src_ttl_sum;
        uint8_t src_ttl_max;
        uint8_t src_ttl_min;
        uint32_t src_ttl_squ;

        uint32_t dst_ttl_sum;
        uint8_t dst_ttl_max;
        uint8_t dst_ttl_min;
        uint32_t dst_ttl_squ;

        Timestamp syn_ts;
        Timestamp syn_ack_ts;
        Timestamp ack_data_ts;

        virtual void update_state(const Packet *packet);

        static const char *state_to_str(conversation_state_t state);

    public:
        Conversation();

        Conversation(const FiveTuple *tuple);

        Conversation(const Packet *packet);

        virtual ~Conversation();

        void init_values();

        /**
         * Returns five tuple identifying the connection
         * (ip protocol, src ip, dst ip, src port, dst port)
         */
        FiveTuple get_five_tuple() const;

        /**
         * Returns const pointer to five tuple - see method get_five_tuple()
         */
        const FiveTuple *get_five_tuple_ptr() const;

        conversation_state_t get_state() const;

        conversation_state_t get_internal_state() const;

        const char *get_state_str() const;

        virtual bool is_in_final_state() const;

        Timestamp get_start_ts() const;

        Timestamp get_last_ts() const;

        uint32_t get_src_packets() const;
        size_t get_src_bytes_sum() const;
        double get_src_bytes_avg() const;
        size_t get_src_bytes_max() const;
        size_t get_src_bytes_min() const;
        double get_src_bytes_std() const;
        double get_src_bytes_rate() const;
        double get_src_packets_rate() const;
        uint64_t get_src_duration_ms() const;
        uint64_t get_src_gap_sum() const;
        double get_src_gap_avg() const;
        uint64_t get_src_gap_max() const;
        uint64_t get_src_gap_min() const;
        double get_src_gap_std() const;

        uint32_t get_dst_packets() const;
        size_t get_dst_bytes_sum() const;
        double get_dst_bytes_avg() const;
        size_t get_dst_bytes_max() const;
        size_t get_dst_bytes_min() const;
        double get_dst_bytes_std() const;
        double get_dst_bytes_rate() const;
        double get_dst_packets_rate() const;
        uint64_t get_dst_duration_ms() const;
        uint64_t get_dst_gap_sum() const;
        double get_dst_gap_avg() const;
        uint64_t get_dst_gap_max() const;
        uint64_t get_dst_gap_min() const;
        double get_dst_gap_std() const;

        uint64_t get_conn_gap_sum() const;
        double get_conn_gap_avg() const;
        uint64_t get_conn_gap_max() const;
        uint64_t get_conn_gap_min() const;
        double get_conn_gap_std() const;
        uint32_t get_conn_packets() const;
        double get_conn_packets_rate() const;
        size_t get_conn_bytes_sum() const;
        double get_conn_bytes_avg() const;
        size_t get_conn_bytes_max() const;
        size_t get_conn_bytes_min() const;
        double get_conn_bytes_std() const;
        double get_conn_bytes_rate() const;

        uint64_t get_duration_ms() const;

        uint32_t get_wrong_fragments() const;

        uint32_t get_cwr_packets() const;
        uint32_t get_ece_packets() const;
        uint32_t get_urg_packets() const;
        uint32_t get_ack_packets() const;
        uint32_t get_psh_packets() const;
        uint32_t get_rst_packets() const;
        uint32_t get_syn_packets() const;
        uint32_t get_fin_packets() const;

        uint32_t get_src_cwr_packets() const;
        uint32_t get_src_ece_packets() const;
        uint32_t get_src_urg_packets() const;
        uint32_t get_src_ack_packets() const;
        uint32_t get_src_psh_packets() const;
        uint32_t get_src_rst_packets() const;
        uint32_t get_src_syn_packets() const;
        uint32_t get_src_fin_packets() const;

        uint32_t get_dst_cwr_packets() const;
        uint32_t get_dst_ece_packets() const;
        uint32_t get_dst_urg_packets() const;
        uint32_t get_dst_ack_packets() const;
        uint32_t get_dst_psh_packets() const;
        uint32_t get_dst_rst_packets() const;
        uint32_t get_dst_syn_packets() const;
        uint32_t get_dst_fin_packets() const;

        double get_down_up_bytes_ratio() const;
        double get_down_up_packets_ratio() const;

        uint32_t get_src_init_window_bytes() const;
        uint32_t get_dst_init_window_bytes() const;

        double get_src_ttl_avg() const;
        uint8_t get_src_ttl_max() const;
        uint8_t get_src_ttl_min() const;
        double get_src_ttl_std() const;

        double get_dst_ttl_avg() const;
        uint8_t get_dst_ttl_max() const;
        uint8_t get_dst_ttl_min() const;
        double get_dst_ttl_std() const;

        uint64_t get_syn_ack_gap() const;
        uint64_t get_ack_data_gap() const;

        virtual service_t get_service() const = 0;    // Pure virtual function
        const char *get_service_str() const;

        const char *get_protocol_type_str() const;

        bool land() const;

        bool is_serror() const;

        bool is_rerror() const;

        /**
         * Adds next packet to connection (without checking sequence number)
         * Returns true if connection will get to final state
         */
        bool add_packet(const Packet *packet);

        /**
         * Compares using get_end_ts() values, used to sort conversation by last
         * fragment timestamp
         */
        bool operator<(const Conversation &other) const;

        /**
         * Output the class values in human readable format (e.g. for debuging purposes)
         */
        void print_human() const;
    };
}
