#include <sstream>
#include <iostream>
#include <iomanip>
#include "ConversationFeatures.h"


namespace FeatureExtractor {
    using namespace std;

    ConversationFeatures::ConversationFeatures(Conversation *conv)
            : conv(conv) {
        conv->register_reference();
    }


    ConversationFeatures::~ConversationFeatures() {
        // Conversation object commits suicide when nobody needs it anymore
        conv->deregister_reference();
    }


    Conversation *ConversationFeatures::get_conversation() {
        return conv;
    }

    /**
     * Getters, setters, inc & dec for derived feature values
     */
    uint32_t ConversationFeatures::get_count() const {
        return count;
    }

    void ConversationFeatures::set_count(uint32_t count) {
        this->count = count;
    }

    uint32_t ConversationFeatures::get_srv_count() const {
        return srv_count;
    }

    void ConversationFeatures::set_srv_count(uint32_t srv_count) {
        this->srv_count = srv_count;
    }

    double ConversationFeatures::get_serror_rate() const {
        return serror_rate;
    }

    void ConversationFeatures::set_serror_rate(double serror_rate) {
        this->serror_rate = serror_rate;
    }

    double ConversationFeatures::get_srv_serror_rate() const {
        return srv_serror_rate;
    }

    void ConversationFeatures::set_srv_serror_rate(double srv_serror_rate) {
        this->srv_serror_rate = srv_serror_rate;
    }

    double ConversationFeatures::get_rerror_rate() const {
        return rerror_rate;
    }

    void ConversationFeatures::set_rerror_rate(double rerror_rate) {
        this->rerror_rate = rerror_rate;
    }

    double ConversationFeatures::get_srv_rerror_rate() const {
        return srv_rerror_rate;
    }

    void ConversationFeatures::set_srv_rerror_rate(double srv_rerror_rate) {
        this->srv_rerror_rate = srv_rerror_rate;
    }

    double ConversationFeatures::get_same_srv_rate() const {
        return same_srv_rate;
    }

    void ConversationFeatures::set_same_srv_rate(double same_srv_rate) {
        this->same_srv_rate = same_srv_rate;
    }

    double ConversationFeatures::get_diff_srv_rate() const {
        return diff_srv_rate;
    }

    void ConversationFeatures::set_diff_srv_rate(double diff_srv_rate) {
        this->diff_srv_rate = diff_srv_rate;
    }

    double ConversationFeatures::get_srv_diff_host_rate() const {
        return (srv_count == 0) ? 0.0 : ((srv_count - same_srv_count) / (double) srv_count);
    }

    uint32_t ConversationFeatures::get_same_srv_count() const {
        return same_srv_count;
    }

    void ConversationFeatures::set_same_srv_count(uint32_t same_srv_count) {
        this->same_srv_count = same_srv_count;
    }

    uint32_t ConversationFeatures::get_dst_host_count() const {
        return dst_host_count;
    }

    void ConversationFeatures::set_dst_host_count(uint32_t dst_host_count) {
        this->dst_host_count = dst_host_count;
    }

    uint32_t ConversationFeatures::get_dst_host_srv_count() const {
        return dst_host_srv_count;
    }

    void ConversationFeatures::set_dst_host_srv_count(uint32_t dst_host_srv_count) {
        this->dst_host_srv_count = dst_host_srv_count;
    }

    double ConversationFeatures::get_dst_host_same_srv_rate() const {
        return dst_host_same_srv_rate;
    }

    void ConversationFeatures::set_dst_host_same_srv_rate(double dst_host_same_srv_rate) {
        this->dst_host_same_srv_rate = dst_host_same_srv_rate;
    }

    double ConversationFeatures::get_dst_host_diff_srv_rate() const {
        return dst_host_diff_srv_rate;
    }

    void ConversationFeatures::set_dst_host_diff_srv_rate(double dst_host_diff_srv_rate) {
        this->dst_host_diff_srv_rate = dst_host_diff_srv_rate;
    }

    double ConversationFeatures::get_dst_host_same_src_port_rate() const {
        return dst_host_same_src_port_rate;
    }

    void ConversationFeatures::set_dst_host_same_src_port_rate(double dst_host_same_src_port_rate) {
        this->dst_host_same_src_port_rate = dst_host_same_src_port_rate;
    }

    double ConversationFeatures::get_dst_host_serror_rate() const {
        return dst_host_serror_rate;
    }

    void ConversationFeatures::set_dst_host_serror_rate(double dst_host_serror_rate) {
        this->dst_host_serror_rate = dst_host_serror_rate;
    }

    double ConversationFeatures::get_dst_host_srv_serror_rate() const {
        return dst_host_srv_serror_rate;
    }

    void ConversationFeatures::set_dst_host_srv_serror_rate(double dst_host_srv_serror_rate) {
        this->dst_host_srv_serror_rate = dst_host_srv_serror_rate;
    }

    double ConversationFeatures::get_dst_host_rerror_rate() const {
        return dst_host_rerror_rate;
    }

    void ConversationFeatures::set_dst_host_rerror_rate(double dst_host_rerror_rate) {
        this->dst_host_rerror_rate = dst_host_rerror_rate;
    }

    double ConversationFeatures::get_dst_host_srv_rerror_rate() const {
        return dst_host_srv_rerror_rate;
    }

    void ConversationFeatures::set_dst_host_srv_rerror_rate(double dst_host_srv_rerror_rate) {
        this->dst_host_srv_rerror_rate = dst_host_srv_rerror_rate;
    }

    double ConversationFeatures::get_dst_host_srv_diff_host_rate() const {
        return (dst_host_srv_count == 0) ? 0.0 : ((dst_host_srv_count - dst_host_same_srv_count) /
                                                  (double) dst_host_srv_count);
    }

    uint32_t ConversationFeatures::get_dst_host_same_srv_count() const {
        return dst_host_same_srv_count;
    }

    void ConversationFeatures::set_dst_host_same_srv_count(uint32_t dst_host_same_srv_count) {
        this->dst_host_same_srv_count = dst_host_same_srv_count;
    }

    // Allow using localtime instead of localtime_s
#pragma warning(disable : 4996)

    void ConversationFeatures::print_header(bool print_extra_features) const {
        stringstream ss;

        ss << "duration" << "," << "protocol" << "," << "service" << "," << "state" << ",";

        ss << "src_packets" << "," << "src_packets_rate" << "," << "src_bytes_sum" << "," << "src_bytes_avg" << "," << "src_bytes_max" << "," << "src_bytes_min" << "," << "src_bytes_std" << "," << "src_bytes_rate" << ",";
        ss << "dst_packets" << "," << "dst_packets_rate" << "," << "dst_bytes_sum" << "," << "dst_bytes_avg" << "," << "dst_bytes_max" << "," << "dst_bytes_min" << "," << "dst_bytes_std" << "," << "dst_bytes_rate" << ",";
        ss << "conn_packets" << "," << "conn_packets_rate" << "," << "conn_bytes_sum" << "," << "conn_bytes_avg" << "," << "conn_bytes_max" << "," << "conn_bytes_min" << "," << "conn_bytes_std" << "," << "conn_bytes_rate" << ",";

        ss << "src_gap_sum" << "," << "src_gap_avg" << "," << "src_gap_max" << "," << "src_gap_min" << "," << "src_gap_std" << ",";
        ss << "dst_gap_sum" << "," << "dst_gap_avg" << "," << "dst_gap_max" << "," << "dst_gap_min" << "," << "dst_gap_std" << ",";
        ss << "conn_gap_sum" << "," << "conn_gap_avg" << "," << "conn_gap_max" << "," << "conn_gap_min" << "," << "conn_gap_std" << ",";

        ss << "syn_ack_gap" << "," << "get_ack_data_gap" << "," << "land" << "," << "get_wrong_fragments" << ",";

        ss << "cwr_packets" << "," << "ece_packets" << "," << "urg_packets" << "," << "ack_packets" << "," << "psh_packets" << "," << "rst_packets" << "," << "syn_packets" << "," << "fin_packets" << ",";
        ss << "src_cwr" << "," << "src_ece" << "," << "src_urg" << "," << "src_ack" << "," << "src_psh" << "," << "src_rst" << "," << "src_syn" << "," << "src_fin" << ",";
        ss << "dst_cwr" << "," << "dst_ece" << "," << "dst_urg" << "," << "dst_ack" << "," << "dst_psh" << "," << "dst_rst" << "," << "dst_syn" << "," << "dst_fin" << ",";

        ss << "src_init_window_bytes" << "," << "dst_init_window_bytes" << ",";
        ss << "down_up_bytes_ratio" << "," << "down_up_packets_ratio" << ",";

        ss << "src_ttl_avg" << "," << "src_ttl_max" << "," << "src_ttl_min" << "," << "src_ttl_std" << ",";
        ss << "dst_ttl_avg" << "," << "dst_ttl_max" << "," << "dst_ttl_min" << "," << "dst_ttl_std" << ',';

        ss << "count" << ',';
        ss << "srv_count" << ',';
        ss << "serror_rate" << ',';
        ss << "srv_serror_rate" << ',';
        ss << "rerror_rate" << ',';
        ss << "srv_rerror_rate" << ',';
        ss << "same_srv_rate" << ',';
        ss << "diff_srv_rate" << ',';
        ss << "get_srv_diff_host_rate" << ',';

        ss << "dst_host_count" << ',';
        ss << "dst_host_srv_count" << ',';
        ss << "dst_host_same_srv_rate" << ',';
        ss << "dst_host_diff_srv_rate" << ',';
        ss << "dst_host_same_src_port_rate" << ',';
        ss << "dst_host_srv_diff_host_rate" << ',';
        ss << "dst_host_serror_rate" << ',';
        ss << "dst_host_srv_serror_rate" << ',';
        ss << "dst_host_rerror_rate" << ',';
        ss << "dst_host_srv_rerror_rate";

        if (print_extra_features) {
            ss << ",";
            ss << "src_ip" << "," << "src_port" << ",";
            ss << "dst_ip" << "," << "dst_port" << ",";
            ss << "start_time" << "," << "end_time";
        }

        cout << ss.str() << endl;
    }

    void ConversationFeatures::print(bool print_extra_features) const {
        stringstream ss;

        // Intrinsic features
        ss << noshowpoint << setprecision(0) << (conv->get_duration_ms() / 1000) << ','; // Cut fractional part
        ss << conv->get_protocol_type_str() << ',';
        ss << conv->get_service_str() << ',';
        ss << conv->get_state_str() << ',';

        ss << fixed << showpoint << setprecision(2);
        ss << conv->get_src_packets() << ',';
        ss << conv->get_src_packets_rate() << ',';
        ss << conv->get_src_bytes_sum() << ',';
        ss << conv->get_src_bytes_avg() << ',';
        ss << conv->get_src_bytes_max() << ',';
        ss << conv->get_src_bytes_min() << ',';
        ss << conv->get_src_bytes_std() << ',';
        ss << conv->get_src_bytes_rate() << ',';

        ss << conv->get_dst_packets() << ',';
        ss << conv->get_dst_packets_rate() << ',';
        ss << conv->get_dst_bytes_sum() << ',';
        ss << conv->get_dst_bytes_avg() << ',';
        ss << conv->get_dst_bytes_max() << ',';
        ss << conv->get_dst_bytes_min() << ',';
        ss << conv->get_dst_bytes_std() << ',';
        ss << conv->get_dst_bytes_rate() << ',';

        ss << conv->get_conn_packets() << ',';
        ss << conv->get_conn_packets_rate() << ',';
        ss << conv->get_conn_bytes_sum() << ',';
        ss << conv->get_conn_bytes_avg() << ',';
        ss << conv->get_conn_bytes_max() << ',';
        ss << conv->get_conn_bytes_min() << ',';
        ss << conv->get_conn_bytes_std() << ',';
        ss << conv->get_conn_bytes_rate() << ',';

        ss << conv->get_src_gap_sum() << ',';
        ss << conv->get_src_gap_avg() << ',';
        ss << conv->get_src_gap_max() << ',';
        ss << conv->get_src_gap_min() << ',';
        ss << conv->get_src_gap_std() << ',';

        ss << conv->get_dst_gap_sum() << ',';
        ss << conv->get_dst_gap_avg() << ',';
        ss << conv->get_dst_gap_max() << ',';
        ss << conv->get_dst_gap_min() << ',';
        ss << conv->get_dst_gap_std() << ',';

        ss << conv->get_conn_gap_sum() << ',';
        ss << conv->get_conn_gap_avg() << ',';
        ss << conv->get_conn_gap_max() << ',';
        ss << conv->get_conn_gap_min() << ',';
        ss << conv->get_conn_gap_std() << ',';

        ss << conv->get_syn_ack_gap() << ",";
        ss << conv->get_ack_data_gap() << ",";

        ss << conv->land() << ',';
        ss << conv->get_wrong_fragments() << ',';

        ss << conv->get_cwr_packets() << ',';
        ss << conv->get_ece_packets() << ',';
        ss << conv->get_urg_packets() << ',';
        ss << conv->get_ack_packets() << ',';
        ss << conv->get_psh_packets() << ',';
        ss << conv->get_rst_packets() << ',';
        ss << conv->get_syn_packets() << ',';
        ss << conv->get_fin_packets() << ',';

        ss << conv->get_src_cwr_packets() << ',';
        ss << conv->get_src_ece_packets() << ',';
        ss << conv->get_src_urg_packets() << ',';
        ss << conv->get_src_ack_packets() << ',';
        ss << conv->get_src_psh_packets() << ',';
        ss << conv->get_src_rst_packets() << ',';
        ss << conv->get_src_syn_packets() << ',';
        ss << conv->get_src_fin_packets() << ',';

        ss << conv->get_dst_cwr_packets() << ',';
        ss << conv->get_dst_ece_packets() << ',';
        ss << conv->get_dst_urg_packets() << ',';
        ss << conv->get_dst_ack_packets() << ',';
        ss << conv->get_dst_psh_packets() << ',';
        ss << conv->get_dst_rst_packets() << ',';
        ss << conv->get_dst_syn_packets() << ',';
        ss << conv->get_dst_fin_packets() << ',';

        ss << conv->get_src_init_window_bytes() << ',';
        ss << conv->get_dst_init_window_bytes() << ',';

        ss << conv->get_down_up_bytes_ratio() << ',';
        ss << conv->get_down_up_packets_ratio() << ',';

        ss << conv->get_src_ttl_avg() << ',';
        ss << (uint16_t)conv->get_src_ttl_max() << ',';
        ss << (uint16_t)conv->get_src_ttl_min() << ',';
        ss << conv->get_src_ttl_std() << ',';

        ss << conv->get_dst_ttl_avg() << ',';
        ss << (uint16_t)conv->get_dst_ttl_max() << ',';
        ss << (uint16_t)conv->get_dst_ttl_min() << ',';
        ss << conv->get_dst_ttl_std() << ',';

        // Derived time windows features
        ss << count << ',';
        ss << srv_count << ',';
        ss << serror_rate << ',';
        ss << srv_serror_rate << ',';
        ss << rerror_rate << ',';
        ss << srv_rerror_rate << ',';
        ss << same_srv_rate << ',';
        ss << diff_srv_rate << ',';
        ss << get_srv_diff_host_rate() << ',';

        // Derived connection count window features
        ss << dst_host_count << ',';
        ss << dst_host_srv_count << ',';
        ss << dst_host_same_srv_rate << ',';
        ss << dst_host_diff_srv_rate << ',';
        ss << dst_host_same_src_port_rate << ',';
        ss << get_dst_host_srv_diff_host_rate() << ',';
        ss << dst_host_serror_rate << ',';
        ss << dst_host_srv_serror_rate << ',';
        ss << dst_host_rerror_rate << ',';
        ss << dst_host_srv_rerror_rate;

        if (print_extra_features) {
            const FiveTuple *ft = conv->get_five_tuple_ptr();

            // TODO: ugly wtf, but working
            uint32_t src_ip = ft->get_src_ip();
            uint32_t dst_ip = ft->get_dst_ip();
            uint8_t *sip = (uint8_t *) &src_ip;
            uint8_t *dip = (uint8_t *) &dst_ip;
            ss << ',';
            ss << (int) sip[0] << "." << (int) sip[1] << "." << (int) sip[2] << "." << (int) sip[3] << ',';
            ss << ft->get_src_port() << ',';
            ss << (int) dip[0] << "." << (int) dip[1] << "." << (int) dip[2] << "." << (int) dip[3] << ',';
            ss << ft->get_dst_port() << ',';

            // Time (e.g.: 2010-06-14T00:11:23)
//            struct tm *ltime;
//            char timestr[20];
//            time_t local_tv_sec;
//            local_tv_sec = conv->get_last_ts().get_secs();
//            ltime = localtime(&local_tv_sec);
//            strftime(timestr, sizeof timestr, "%Y-%m-%dT%H:%M:%S", ltime);
            ss << conv->get_start_ts().get_secs() << ",";
            ss << conv->get_last_ts().get_secs();
        }

        cout << ss.str() << endl;
    }


    void ConversationFeatures::print_human() const {
        conv->print_human();

        stringstream ss;
        ss << fixed << setprecision(2);
        ss << "count = " << count << endl;
        ss << "srv_count = " << srv_count << endl;
        ss << "serror_rate = " << serror_rate << endl;
        ss << "srv_serror_rate = " << srv_serror_rate << endl;
        ss << "rerror_rate = " << rerror_rate << endl;
        ss << "srv_rerror_rate = " << srv_rerror_rate << endl;
        ss << "same_srv_rate = " << same_srv_rate << endl;
        ss << "diff_srv_rate = " << diff_srv_rate << endl;
        ss << "get_srv_diff_host_rate = " << get_srv_diff_host_rate() << endl;
        ss << "dst_host_count = " << dst_host_count << endl;
        ss << "dst_host_srv_count = " << dst_host_srv_count << endl;
        ss << "dst_host_same_srv_rate = " << dst_host_same_srv_rate << endl;
        ss << "dst_host_diff_srv_rate = " << dst_host_diff_srv_rate << endl;
        ss << "dst_host_same_src_port_rate = " << dst_host_same_src_port_rate << endl;
        ss << "get_dst_host_srv_diff_host_rate = " << get_dst_host_srv_diff_host_rate() << endl;
        ss << "dst_host_serror_rate = " << dst_host_serror_rate << endl;
        ss << "dst_host_srv_serror_rate = " << dst_host_srv_serror_rate << endl;
        ss << "dst_host_rerror_rate = " << dst_host_rerror_rate << endl;
        ss << "dst_host_srv_rerror_rate = " << dst_host_srv_rerror_rate << endl;
        cout << ss.str() << endl;
    }

}
