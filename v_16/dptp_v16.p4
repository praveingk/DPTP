/* -*- P4_16 -*- */
/*******************************************************************************
 * DPTP : Data-Plane Time-synchronization Protocol
 *
 *
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "parser.p4"

#define COMMAND_TIMESYNC_RESET 0x1
#define COMMAND_TIMESYNC_REQUEST 0x2
#define COMMAND_TIMESYNC_RESPONSE 0x3

#define COMMAND_TIMESYNC_CAPTURE_TX 0x6
#define COMMAND_TIMESYNCS2S_GENREQUEST 0x11
#define COMMAND_TIMESYNCS2S_REQUEST 0x12
#define COMMAND_TIMESYNCS2S_RESPONSE 0x13

#define MAX_32BIT 4294967295
#define MAX_LINKS 512
#define MAX_SWITCHES 20
#define MAX_NS 1000000000
#define SWITCH_CPU 192

Register<bit<32>, bit<32>>(32w20) ts_hi;

Register<bit<32>, bit<32>>(32w20) ts_lo;

control dptp_reference (inout header_t hdr, inout metadata_t meta) {
    RegisterAction<bit<32>, bit<32>, bit<32>>(ts_hi) ts_hi_get = {
        void apply (inout bit<32> value, out bit<32> result) {
            result = value;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(ts_lo) ts_lo_get = {
        void apply (inout bit<32> value, out bit<32> result) {
            result = value;
        }
    };

    action timesync_hi_request() {
        meta.mdata.reference_ts_hi = ts_hi_get.execute(meta.mdata.switch_id);
    }

    action timesync_request() {
        meta.mdata.reference_ts_lo = ts_lo_get.execute(meta.mdata.switch_id);
    }
    table timesync_hi_now {
        actions = {
            timesync_hi_request();
        }
        default_action = timesync_hi_request();
    }

    table timesync_now {
        actions = {
            timesync_request();
        }
        default_action = timesync_request();
    }

    apply {
        timesync_now.apply();
        timesync_hi_now.apply();
    }
}

Register<bit<32>, bit<32>>(1) dptp_now_hi;

Register<bit<32>, bit<32>>(1) dptp_now_lo;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_capture_tx;

Register<bit<32>, bit<32>>(1) timesyncs2s_cp_flag;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_egts_lo;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_elapsed_lo;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_igts_hi;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_igts_lo;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_macts_lo;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_now_macts_lo;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_reference_hi;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_reference_lo;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_updts_lo;

Register<bit<32>, bit<32>>(1) test1;

Register<bit<32>, bit<32>>(1) test2;


control DptpIngress(
    inout header_t hdr, 
    inout metadata_t meta, 
    in ingress_intrinsic_metadata_t ig_intr_md, 
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_parser_aux, 
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr, 
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    RegisterAction<bit<32>, bit<32>, bit<32>>(test1) test1_set = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(test2) test2_set = {
        void apply(inout bit<32> value) {
            value = value + 1;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(dptp_now_hi) dptp_now_hi_set = {
        void apply(inout bit<32> value) {
            value = meta.mdata.dptp_now_hi;
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(dptp_now_lo) dptp_now_lo_set = {
        void apply(inout bit<32> value) {
            value = meta.mdata.dptp_now_lo;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_capture_tx) timesyncs2s_capture_tx_set = {
        void apply(inout bit<32> value) {
            value = hdr.timesync.reference_ts_hi;
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_egts_lo) timesyncs2s_egts_lo_set = {
        void apply(inout bit<32> value) {
            value = (bit<32>)hdr.timesync.egts[31:0];
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_elapsed_lo) timesyncs2s_elapsed_lo_set = {
        void apply(inout bit<32> value) {
            value = (bit<32>)hdr.timesync.igts[31:0];
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_cp_flag) timesyncs2s_flag_set = {
        void apply(inout bit<32> value) {
            value = meta.mdata.switch_id;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_igts_hi) timesyncs2s_igts_hi_set = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = (bit<32>)ig_intr_md_from_parser_aux.global_tstamp[47:32];
            result = value;
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_igts_lo) timesyncs2s_igts_lo_set = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = (bit<32>)ig_intr_md_from_parser_aux.global_tstamp[31:0];
            result = value;
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_macts_lo) timesyncs2s_macts_lo_set = {
        void apply(inout bit<32> value) {
            value = (bit<32>)hdr.timesync.igmacts;
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_now_macts_lo) timesyncs2s_now_macts_lo_set = {
        void apply(inout bit<32> value) {
            value = (bit<32>)ig_intr_md.ingress_mac_tstamp[31:0];
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_reference_hi) timesyncs2s_reference_hi_set = {
        void apply(inout bit<32> value) {
            value = hdr.timesync.reference_ts_hi;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_reference_lo) timesyncs2s_reference_lo_set = {
        void apply(inout bit<32> value) {
            value = hdr.timesync.reference_ts_lo;
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_updts_lo) timesyncs2s_updts_lo_set = {
        void apply(inout bit<32> value) {
            value = (bit<32>)hdr.timesync.capturets;
        }
    };

    action _drop() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
    }

    action nop() {}

    action classify_switch(bit<32> switch_id) {
        meta.mdata.switch_id = switch_id;
    }
    
    action classify_src_switch(bit<32> switch_id) {
        meta.mdata.src_switch_id = switch_id;
    }
    
    action dptp_packet() {
        hdr.timesync.reference_ts_lo = meta.mdata.dptp_now_lo;
        hdr.timesync.reference_ts_hi = meta.mdata.dptp_now_hi;
        hdr.timesync.era_ts_hi = meta.mdata.era_ts_hi;
        hdr.timesync.igmacts = ig_intr_md.ingress_mac_tstamp;
        hdr.timesync.igts = ig_intr_md_from_parser_aux.global_tstamp;
    }
    
    action do_dptp_add_elapsed_hi() {
        meta.mdata.dptp_now_hi = meta.mdata.reference_ts_hi + meta.mdata.ingress_timestamp_clipped_hi;
    }

    action do_dptp_add_elapsed_lo() {
        meta.mdata.dptp_now_lo = meta.mdata.reference_ts_lo + meta.mdata.ingress_timestamp_clipped;
    }

    action do_dptp_calc_residue() {
        meta.mdata.dptp_residue = MAX_32BIT - meta.mdata.reference_ts_lo;
    }
    
    action do_dptp_compare_igts() {
        meta.mdata.dptp_compare_residue = meta.mdata.ingress_timestamp_clipped - meta.mdata.dptp_overflow_compare;
    }

    action do_dptp_compare_residue() {
        meta.mdata.dptp_overflow_compare = (meta.mdata.dptp_residue <= meta.mdata.ingress_timestamp_clipped ? meta.mdata.dptp_residue : meta.mdata.ingress_timestamp_clipped);
    }
    
    action do_dptp_handle_overflow() {
        meta.mdata.dptp_now_hi = meta.mdata.dptp_now_hi + 1;
    }
    
    action do_dptp_store_now_hi() {
        dptp_now_hi_set.execute(0);
    }
    
    action do_dptp_store_now_lo() {
        dptp_now_lo_set.execute(0);
    }
    
    action reverse_packet() {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = 48w0x11;
    }

    action set_egr(bit<16> egress_spec) {
        ig_intr_md_for_tm.ucast_egress_port = (bit<9>)egress_spec;
        meta.mdata.egress_port = egress_spec;
    }
    
    action do_qos() {
        ig_intr_md_for_tm.qid = 5w3;
    }
    
    action timesync_flag_cp_learn() {
        ig_intr_md_for_dprsr.digest_type = DPTP_FOLLOWUP_DIGEST_TYPE;
    }
    
    action timesyncs2s_flag_cp() {
        timesyncs2s_flag_set.execute(0);
        _drop();
    }

    action do_timesyncs2s_capture_tx_set() {
        timesyncs2s_capture_tx_set.execute(meta.mdata.switch_id);
    }
    
    action timesyncs2s_capture_egTs_lo() {
        timesyncs2s_egts_lo_set.execute(meta.mdata.switch_id);
    }
    
    action timesyncs2s_capture_elapsed_lo() {
        timesyncs2s_elapsed_lo_set.execute(meta.mdata.switch_id);
    }
    
    action timesyncs2s_capture_igTs_hi(bit<32> switch_id) {
        meta.mdata.ingress_timestamp_clipped_hi = (bit<32>)timesyncs2s_igts_hi_set.execute(switch_id);
    }
    
    action timesyncs2s_capture_igTs_lo(bit<32> switch_id) {
        meta.mdata.ingress_timestamp_clipped = timesyncs2s_igts_lo_set.execute(switch_id);
    }
    
    action timesyncs2s_capture_macTs_lo() {
        timesyncs2s_macts_lo_set.execute(meta.mdata.switch_id);
    }
    
    action timesyncs2s_capture_now_macTs_lo() {
        meta.mdata.mac_timestamp_clipped = timesyncs2s_now_macts_lo_set.execute(meta.mdata.switch_id);
    }
    
    action timesyncs2s_capture_reference_hi() {
        timesyncs2s_reference_hi_set.execute(meta.mdata.switch_id);
    }
    
    action timesyncs2s_capture_reference_lo() {
        timesyncs2s_reference_lo_set.execute(meta.mdata.switch_id);
    }
    
    action timesyncs2s_capture_updTs_lo() {
        timesyncs2s_updts_lo_set.execute(meta.mdata.switch_id);
    }
    
    table acl {
        actions = {
            _drop();
            nop();
        }
        key = {
            ig_intr_md.ingress_port: exact;
            hdr.ethernet.dstAddr   : exact;
            hdr.ethernet.etherType : exact;
        }
        default_action = nop();
    }
    
    table classify_logical_switch {
        actions = {
            classify_switch();
            nop();
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        default_action = nop();
    }
    
    table classify_src_logical_switch {
        actions = {
            classify_src_switch();
            nop();
        }
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        default_action = nop();
    }
    
    table copy_dptp_packet {
        actions = {
            dptp_packet();
            nop();
        }
        key = {
            meta.mdata.command: exact;
        }
        default_action = nop();
    }
    
    table dptp_add_elapsed_hi {
        actions = {
            do_dptp_add_elapsed_hi();
        }
        default_action = do_dptp_add_elapsed_hi();
    }
    
    table dptp_add_elapsed_lo {
        actions = {
            do_dptp_add_elapsed_lo();
        }
        default_action = do_dptp_add_elapsed_lo();
    }
    
    table dptp_calc_residue {
        actions = {
            do_dptp_calc_residue();
        }
        default_action = do_dptp_calc_residue();
    }
    
    table dptp_compare_igts {
        actions = {
            do_dptp_compare_igts();
        }
        default_action = do_dptp_compare_igts();
    }
    
    table dptp_compare_residue {
        actions = {
            do_dptp_compare_residue();
        }
        default_action = do_dptp_compare_residue();
    }
    
    table dptp_handle_overflow {
        actions = {
            do_dptp_handle_overflow();
            nop();
        }
        key = {
            meta.mdata.dptp_compare_residue: exact;
        }
        default_action = nop();
    }
    
    table dptp_store_now_hi {
        actions = {
            do_dptp_store_now_hi();
        }
        default_action = do_dptp_store_now_hi();
    }
    
    table dptp_store_now_lo {
        actions = {
            do_dptp_store_now_lo();
        }
        default_action = do_dptp_store_now_lo();
    }
    
    table dropit {
        actions = {
            _drop();
        }
        default_action = _drop();
    }
    
    table flip_address {
        actions = {
            reverse_packet();
            nop();
        }
        key = {
            meta.mdata.command: exact;
        }
        default_action = nop();
    }
    table mac_forward {
        actions = {
            set_egr();
            nop();
        }
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        size = 20;
        default_action = nop();
    }
    table qos {
        actions = {
            do_qos();
            nop();
        }
        key = {
            meta.mdata.command: exact;
        }
        default_action = nop();
    }
    
    table timesync_inform_cp {
        actions = {
            timesync_flag_cp_learn();
            nop();
        }
        key = {
            meta.mdata.command: exact;
        }
        default_action = nop();
    }
    
    table timesyncs2s_inform_cp {
        actions = {
            timesyncs2s_flag_cp();
        }
        default_action = timesyncs2s_flag_cp();
    }
    
    table timesyncs2s_store_capture_tx {
        actions = {
            do_timesyncs2s_capture_tx_set();
            nop();
        }
        key = {
            meta.mdata.switch_id: exact;
        }
        default_action = nop();
    }
    
    table timesyncs2s_store_egTs_lo {
        actions = {
            timesyncs2s_capture_egTs_lo();
        }
        default_action = timesyncs2s_capture_egTs_lo();
    }
    
    table timesyncs2s_store_elapsed_lo {
        actions = {
            timesyncs2s_capture_elapsed_lo();
        }
        default_action = timesyncs2s_capture_elapsed_lo();
    }
    
    table timesyncs2s_store_igTs_hi {
        actions = {
            timesyncs2s_capture_igTs_hi();
            nop();
        }
        key = {
            meta.mdata.command  : exact;
            meta.mdata.switch_id: exact;
        }
        default_action = nop();//timesyncs2s_capture_igTs_hi(20);
    }
    
    table timesyncs2s_store_igTs_lo {
        actions = {
            timesyncs2s_capture_igTs_lo();
            nop();
        }
        key = {
            meta.mdata.command  : exact;
            meta.mdata.switch_id: exact;
        }
        default_action = nop();//timesyncs2s_store_igTs_lo(20);
    }
    
    table timesyncs2s_store_macTs_lo {
        actions = {
            timesyncs2s_capture_macTs_lo();
        }
        default_action = timesyncs2s_capture_macTs_lo();
    }
    
    table timesyncs2s_store_now_macTs_lo {
        actions = {
            timesyncs2s_capture_now_macTs_lo();
        }
        default_action = timesyncs2s_capture_now_macTs_lo();
    }
    
    table timesyncs2s_store_reference_hi {
        actions = {
            timesyncs2s_capture_reference_hi();
        }
        default_action = timesyncs2s_capture_reference_hi();
    }
    
    table timesyncs2s_store_reference_lo {
        actions = {
            timesyncs2s_capture_reference_lo();
        }
        default_action = timesyncs2s_capture_reference_lo();
    }
    
    table timesyncs2s_store_updTs_lo {
        actions = {
            timesyncs2s_capture_updTs_lo();
        }
        default_action = timesyncs2s_capture_updTs_lo();
    }
    
    dptp_reference() dptp_get_ref;

    apply {
        acl.apply();
        if (hdr.timesync.isValid()) {
            classify_logical_switch.apply();
            classify_src_logical_switch.apply();
            flip_address.apply();
        }
        timesyncs2s_store_igTs_hi.apply();
        timesyncs2s_store_igTs_lo.apply();
        dptp_get_ref.apply(hdr, meta);
        dptp_add_elapsed_hi.apply();
        dptp_calc_residue.apply();
        dptp_compare_residue.apply();
        dptp_compare_igts.apply();
        dptp_add_elapsed_lo.apply();
        dptp_handle_overflow.apply();
        dptp_store_now_hi.apply();
        dptp_store_now_lo.apply();
        if (meta.mdata.command == COMMAND_TIMESYNCS2S_RESPONSE) {
            test1_set.execute(0);
            timesyncs2s_store_reference_hi.apply();
            timesyncs2s_store_reference_lo.apply();
            timesyncs2s_store_elapsed_lo.apply();
            timesyncs2s_store_now_macTs_lo.apply();
            timesyncs2s_store_macTs_lo.apply();
            timesyncs2s_store_egTs_lo.apply();
            timesyncs2s_store_updTs_lo.apply();
            ig_intr_md_for_dprsr.digest_type = DPTP_REPLY_DIGEST_TYPE;
            dropit.apply();
        } else {
            if (meta.mdata.command == COMMAND_TIMESYNC_CAPTURE_TX) {
                test2_set.execute(0);
                if (ig_intr_md.ingress_port != SWITCH_CPU) {
                    timesyncs2s_store_capture_tx.apply();
                    timesyncs2s_inform_cp.apply();
                    ig_intr_md_for_dprsr.digest_type = DPTP_REPLY_FOLLOWUP_DIGEST_TYPE;
                }
            }
        }
        mac_forward.apply();
        copy_dptp_packet.apply();
        timesync_inform_cp.apply();
        qos.apply();
        meta.bridged_header.setValid();
        meta.bridged_header.switch_id = meta.mdata.switch_id;
        meta.bridged_header.ingress_port = (bit<16>)ig_intr_md.ingress_port;
    }
}



Register<bit<32>, bit<32>>(MAX_LINKS) current_utilization;

Register<bit<32>, bit<32>>(1) egress_timestamp_clipped;

Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_reqts_lo;

control DptpEgress(
    inout header_t hdr, 
    inout metadata_t meta, 
    in egress_intrinsic_metadata_t eg_intr_md, 
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_parser_aux,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    RegisterAction<bit<32>, bit<32>, bit<32>>(egress_timestamp_clipped) clip_egress_timestamp = {
        void apply (inout bit<32> value, out bit<32> rv) {
            rv = 32w0;
            bit<32> in_value;
            in_value = value;
            value = (bit<32>)eg_intr_md_from_parser_aux.global_tstamp;
            rv = value;
        }
    };

    Lpf<bit<16>, bit<32>>(MAX_LINKS) current_utilization_bps;

    RegisterAction<bit<32>, bit<32>, bit<32>>(current_utilization) set_current_utilization = {
        void apply(inout bit<32> value) {
            bit<32> in_value;
            in_value = value;
            value = meta.mdata.current_utilization;
        }
    };
    
    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_reqts_lo) timesyncs2s_reqts_lo_set = {
        void apply(inout bit<32> value) {
            bit<32> in_value;
            in_value = value;
            value = (bit<32>)eg_intr_md_from_parser_aux.global_tstamp;
        }
    };
    
    /*** Actions ***/
    action do_calc_current_utilization (bit<32> link) {
        meta.mdata.current_utilization = (bit<32>)current_utilization_bps.execute(eg_intr_md.pkt_length, link);
        meta.mdata.link = link;
    }

    action nop () {}

    action do_store_current_utilization () {
        set_current_utilization.execute(meta.mdata.link);
    }

    action timesync_capture_tx () {
        // hdr.transparent_clock.setValid();
        // hdr.transparent_clock.udp_chksum_offset = 0;
        // hdr.transparent_clock.elapsed_time_offset = 51;
        // hdr.transparent_clock.captureTs = 0;
        //eg_intr_md_for_oport.update_delay_on_tx = 1;
        eg_intr_md_for_oport.capture_tstamp_on_tx = 1;
    }

    action timesync_do_clip_egts () {
        meta.mdata.egress_timestamp_clipped = clip_egress_timestamp.execute(32w0);
    }

    action do_timesync_current_rate () {
        hdr.timesync.current_rate = meta.mdata.current_utilization;
    }

    action timesync_calculate_egdelta () {
        hdr.timesync.egts = eg_intr_md_from_parser_aux.global_tstamp;
    }
    action timesync_response () {
        hdr.timesync.command = COMMAND_TIMESYNC_RESPONSE;
    }
    action timesyncs2s_request () {
        timesyncs2s_reqts_lo_set.execute(meta.mdata.src_switch_id);
        hdr.timesync.command = COMMAND_TIMESYNCS2S_REQUEST;
    }
    action timesyncs2s_response () {
        hdr.timesync.command = COMMAND_TIMESYNCS2S_RESPONSE;
        timesync_calculate_egdelta();
    }
    /*** Tables ***/
    table calc_current_utilization {
        actions = {
            do_calc_current_utilization();
            nop();
        }
        key = {
            meta.bridged_header.ingress_port: exact;
        }
        default_action = nop();
    }

    table store_current_utilization {
        actions = {
            do_store_current_utilization();
        }
        default_action = do_store_current_utilization();
    }

    table timesync_capture_ts {
        actions = {
            timesync_capture_tx();
            nop();
        }
        key = {
            meta.mdata.command: exact;
        }
        default_action = nop();
    }

    table timesync_clip_egts {
        actions = {
            timesync_do_clip_egts();
        }
        default_action = timesync_do_clip_egts();
    }

    table timesync_current_rate {
        actions = {
            do_timesync_current_rate();
        }
        default_action = do_timesync_current_rate();
    }

    table timesync_delta {
        actions = {
            timesync_calculate_egdelta();
        }
        default_action = timesync_calculate_egdelta();
    }

    table timesync_gen_response {
        actions = {
            timesync_response();
        }
        default_action = timesync_response();
    }

    table timesyncs2s_gen_request {
        actions = {
            timesyncs2s_request();
            nop();
        }
        key = {
            meta.mdata.switch_id: exact;
        }
        default_action = nop();
    }

    table timesyncs2s_gen_response {
        actions = {
            timesyncs2s_response();
            nop();
        }
        key = {
            meta.mdata.switch_id: exact;
        }
        default_action = nop();
    }

    apply {
        if (eg_intr_md.pkt_length != 0) {
            calc_current_utilization.apply();
        }
        if (hdr.timesync.isValid()) {
            timesync_clip_egts.apply();
            timesync_capture_ts.apply();
            if (meta.mdata.command == COMMAND_TIMESYNCS2S_REQUEST) {
                timesyncs2s_gen_response.apply();
            } else {
                if (meta.mdata.command == COMMAND_TIMESYNC_REQUEST) {
                    timesync_gen_response.apply();
                    timesync_delta.apply();
                    timesync_current_rate.apply();
                } else {
                    if (meta.mdata.command == COMMAND_TIMESYNCS2S_GENREQUEST) {
                        timesyncs2s_gen_request.apply();
                    }
                }
            }
        }
        store_current_utilization.apply();
    }
}


Pipeline(
    DptpIngressParser(), 
    DptpIngress(), 
    DptpIngressDeparser(), 
    DptpEgressParser(), 
    DptpEgress(), 
    DptpEgressDeparser()) pipe;

Switch(pipe) main;

