#pragma once

#include "Packet.h"

namespace FeatureExtractor {
    class IpFragment :
            public Packet {
        uint16_t ip_id;
        bool ip_flag_mf;
        uint16_t ip_frag_offset;
        size_t ip_payload_length;
        uint8_t ip_ttl;
        uint16_t ip_checksum;
        bool is_wrong_fragment;

    public:
        IpFragment();

        ~IpFragment();

        uint16_t get_ip_id() const;

        void set_ip_id(uint16_t ip_id);

        bool get_ip_flag_mf() const;

        void set_ip_flag_mf(bool ip_flag_mf);

        uint16_t get_ip_frag_offset() const;

        void set_ip_frag_offset(uint16_t ip_frag_offset);

        size_t get_ip_payload_length() const;

        void set_ip_payload_length(size_t ip_payload_length);

        void set_ip_ttl(uint8_t ip_ttl);

        uint8_t get_ip_ttl() const;

        void set_ip_checksum(uint16_t ip_checksum);

        uint16_t get_ip_checksum() const;

        void set_is_wrong_fragment(bool is_wrong);

        bool get_is_wrong_fragment() const;

        /**
         * Output the class values (e.g. for debuging purposes)
         * overriden
         */
        void print() const;
    };
}
