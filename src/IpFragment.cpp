#include <iostream>
#include "IpFragment.h"

namespace FeatureExtractor {
    using namespace std;

    IpFragment::IpFragment()
            : Packet(), ip_flag_mf(false), ip_frag_offset(0), ip_payload_length(0), is_wrong_fragment(false) {
    }

    IpFragment::~IpFragment() = default;

    uint16_t IpFragment::get_ip_id() const {
        return ip_id;
    }

    void IpFragment::set_ip_id(uint16_t ip_id) {
        this->ip_id = ip_id;
    }

    bool IpFragment::get_ip_flag_mf() const {
        return ip_flag_mf;
    }

    void IpFragment::set_ip_flag_mf(bool ip_flag_mf) {
        this->ip_flag_mf = ip_flag_mf;
    }

    uint16_t IpFragment::get_ip_frag_offset() const {
        return ip_frag_offset;
    }

    void IpFragment::set_ip_frag_offset(uint16_t ip_frag_offset) {
        this->ip_frag_offset = ip_frag_offset;
    }

    size_t IpFragment::get_ip_payload_length() const {
        return ip_payload_length;
    }

    void IpFragment::set_ip_payload_length(size_t ip_payload_length) {
        this->ip_payload_length = ip_payload_length;
    }

    void IpFragment::set_ip_ttl(uint8_t ip_ttl) {
        this->ip_ttl = ip_ttl;
    }

    uint8_t IpFragment::get_ip_ttl() const {
        return ip_ttl;
    }

    void IpFragment::set_ip_checksum(uint16_t ip_checksum) {
        this->ip_checksum = ip_checksum;
    }

    uint16_t IpFragment::get_ip_checksum() const {
        return ip_checksum;
    }

    void IpFragment::set_is_wrong_fragment(bool is_wrong) {
        this->is_wrong_fragment = is_wrong;
    }

    bool IpFragment::get_is_wrong_fragment() const {
        return this->is_wrong_fragment;
    }

    void IpFragment::print() const {
        Packet::print_human();

        if (get_eth_type() == IPV4) {
            cout << "  ip.flag_mf=" << get_ip_flag_mf()
                 << ", ip.frag_offset=" << get_ip_frag_offset()
                 << ", ip.id=0x" << hex << get_ip_id() << dec
                 << ", payload_length=" << get_ip_payload_length() << endl;
        }
    }
}