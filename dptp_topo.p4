/*
 * DPTP : Data-Plane Time-synchronization Protocol
 */
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/lpf_blackbox.p4"


#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_TIMESYNC 0x88F7
#define COMMAND_TIMESYNC_RESET 0x1
#define COMMAND_TIMESYNC_REQUEST 0x2
#define COMMAND_TIMESYNC_RESPONSE 0x3
#define COMMAND_TIMESYNC_TRANSDELAY 0x4
#define COMMAND_TIMESYNC_CAPTURE_TX 0x6

#define COMMAND_TIMESYNCS2S_GENTRANSDELAY 0x10
#define COMMAND_TIMESYNCS2S_GENREQUEST 0x11
#define COMMAND_TIMESYNCS2S_REQUEST 0x12
#define COMMAND_TIMESYNCS2S_RESPONSE 0x13
#define COMMAND_TIMESYNCS2S_TRANSDELAY 0x14

#define MAX_32BIT 4294967295
#define MAX_CLIENTS 65536
#define MAX_LINKS 512
#define MAX_SWITCHES 20
#define YES 1
#define NO 0
#define MAX_NS 1000000000
/* Declare Header */
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header ipv4_t ipv4;


field_list ipv4_field_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_chksum_calc {
    input {
        ipv4_field_list;
    }
    algorithm : csum16;
    output_width: 16;
}

calculated_field ipv4.hdrChecksum {
    update ipv4_chksum_calc;
}

header_type udp_t { // 8 bytes
    fields {
        srcPort : 16;
        dstPort : 16;
        hdr_length : 16;
        checksum : 16;
    }
}

header udp_t udp;

header_type timesync_t {
    fields {
        magic : 16;
        command : 8;
        reference_ts_hi : 32;
        reference_ts_lo : 32;
        era_ts_hi : 32;
        current_rate : 32;
        igmacts : 48;
        igts : 48;
        egts : 48;
        capturets : 48;
    }
}

header timesync_t timesync;

header_type metadata_t {
    fields {
        command : 8;
        reference_ts_hi : 32;
        reference_ts_lo : 32;
        era_ts_hi : 32;
        era_ts_lo : 32;
        global_ts_hi : 32;
        global_ts_lo : 32;
        result_ts_hi : 32;
        result_ts_lo : 32;
        global_ts : 48;
        mac_timestamp_clipped : 32;
        ingress_timestamp_clipped_hi : 32;
        ingress_timestamp_clipped : 32;
        egress_timestamp_clipped : 32;
        reqdelay : 32;
        capture_tx : 32;
        switch_id : 32;
        src_switch_id : 32;
        current_utilization : 32;
        link : 32;
        lpf_test : 32;
        port_switch_id : 32;
        pipe : 32;
        dptp_now_hi : 32;
        dptp_now_lo : 32;
        dptp_overflow_hi : 32;
        dptp_overflow_lo : 32;
        dptp_residue : 32;
        dptp_compare_residue : 32;
        dptp_overflow : 1;
        dptp_overflow_compare : 32;
    }
}

metadata metadata_t mdata;

/* Declare Parser */
parser start {
	return select(current(96,16)){
		0x88f7: parse_ethernet;
		0x0800: parse_ethernet;
		0x1234: parse_ethernet;
		default: ingress;
	}
}
parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        /** Fill Whatever ***/
	    ETHERTYPE_TIMESYNC : parse_timesync;
        ETHERTYPE_IPV4     : parse_ipv4;
        default: ingress;
    }
}
parser parse_timesync {
    extract(timesync);
    set_metadata(mdata.command, latest.command);
    set_metadata(mdata.reference_ts_hi, latest.reference_ts_hi);
    set_metadata(mdata.reference_ts_lo, latest.reference_ts_lo);
    set_metadata(mdata.result_ts_hi, 0);
    set_metadata(mdata.result_ts_lo, 0);
    return ingress;
}
parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

/** Registers ***/

field_list timesync_inform_cp_digest {
    ig_intr_md_for_tm.ucast_egress_port;
    ethernet.dstAddr;
    ig_intr_md_from_parser_aux.ingress_global_tstamp;
}

register reference_ts_hi {
    width: 32;
    instance_count: MAX_SWITCHES;
}
blackbox stateful_alu reference_ts_hi_set {
    reg: reference_ts_hi;
    update_lo_1_value: mdata.reference_ts_hi;
}
blackbox stateful_alu reference_ts_hi_get {
    reg: reference_ts_hi;
    output_value: register_lo;
    output_dst: mdata.reference_ts_hi;
}

register reference_ts_lo {
    width: 32;
    instance_count: MAX_SWITCHES;
}
blackbox stateful_alu reference_ts_lo_set {
    reg: reference_ts_lo;
    update_lo_1_value: mdata.reference_ts_lo;
}
blackbox stateful_alu reference_ts_lo_get {
    reg: reference_ts_lo;
    output_value: register_lo;
    output_dst: mdata.reference_ts_lo;
}

register timesyncs2s_capture_tx {
    width: 32;
    instance_count : MAX_SWITCHES;
}
blackbox stateful_alu timesyncs2s_capture_tx_set {
    reg: timesyncs2s_capture_tx;
    update_lo_1_value: timesync.reference_ts_hi;
}

register era_ts_hi {
    width: 32;
    instance_count: 1;
}
blackbox stateful_alu era_ts_hi_set {
    reg: era_ts_hi;
    update_lo_1_value: 0; // Zero
}
blackbox stateful_alu era_ts_hi_get {
    reg: era_ts_hi;
    output_value: register_lo;
    output_dst: mdata.era_ts_hi;
}

register era_ts_lo {
    width: 32;
    instance_count:1;
}
blackbox stateful_alu era_ts_lo_set {
    reg: era_ts_lo;
    update_lo_1_value: 0; // Zero
}
blackbox stateful_alu era_ts_lo_get {
    reg: era_ts_lo;
    output_value: register_lo;
    output_dst: mdata.era_ts_lo;
}

register ingress_timestamp_clipped {
    width:32;
    instance_count : 1;
}
@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 31 0
blackbox stateful_alu clip_ingress_timestamp {
    reg: ingress_timestamp_clipped;
    condition_lo: ig_intr_md_from_parser_aux.ingress_global_tstamp != 0;
    update_lo_1_value: ig_intr_md_from_parser_aux.ingress_global_tstamp;
    output_value:alu_lo;
    output_dst:mdata.ingress_timestamp_clipped;
}

register egress_timestamp_clipped {
    width:32;
    instance_count : 1;
}
@pragma stateful_field_slice eg_intr_md_from_parser_aux.egress_global_tstamp 31 0
blackbox stateful_alu clip_egress_timestamp {
    reg: egress_timestamp_clipped;
    condition_lo: eg_intr_md_from_parser_aux.egress_global_tstamp != 0;
    update_lo_1_value: eg_intr_md_from_parser_aux.egress_global_tstamp;
    output_value:alu_lo;
    output_dst:mdata.egress_timestamp_clipped;
}

register timesyncs2s_reference_hi {
    width:32;
    instance_count:MAX_SWITCHES;
}
blackbox stateful_alu timesyncs2s_reference_hi_set {
    reg:timesyncs2s_reference_hi;
    update_lo_1_value: timesync.reference_ts_hi;
}

register timesyncs2s_reference_lo {
    width:32;
    instance_count:MAX_SWITCHES;
}
blackbox stateful_alu timesyncs2s_reference_lo_set {
    reg:timesyncs2s_reference_lo;
    update_lo_1_value: timesync.reference_ts_lo;
}

register timesyncs2s_elapsed_hi {
    width:16;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice timesync.igts 47 32
blackbox stateful_alu timesyncs2s_elapsed_hi_set {
    reg:timesyncs2s_elapsed_hi;
    update_lo_1_value: timesync.igts;
}

register timesyncs2s_elapsed_lo {
    width:32;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice timesync.igts 31 0
blackbox stateful_alu timesyncs2s_elapsed_lo_set {
    reg:timesyncs2s_elapsed_lo;
    update_lo_1_value: timesync.igts;
}

register timesyncs2s_igts_hi {
    width:16;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 47 32
blackbox stateful_alu timesyncs2s_igts_hi_set {
    reg:timesyncs2s_igts_hi;
    update_lo_1_value: ig_intr_md_from_parser_aux.ingress_global_tstamp;
    output_value:alu_lo;
    output_dst:mdata.ingress_timestamp_clipped_hi;
}

register timesyncs2s_igts_lo {
    width:32;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 31 0
blackbox stateful_alu timesyncs2s_igts_lo_set {
    reg:timesyncs2s_igts_lo;
    update_lo_1_value: ig_intr_md_from_parser_aux.ingress_global_tstamp;
    output_value:alu_lo;
    output_dst:mdata.ingress_timestamp_clipped;
}

register timesyncs2s_reqigts_hi {
    width:16;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 47 32
blackbox stateful_alu timesyncs2s_reqigts_hi_set {
    reg:timesyncs2s_reqigts_hi;
    update_lo_1_value:ig_intr_md_from_parser_aux.ingress_global_tstamp;
}

register timesyncs2s_reqigts_lo {
    width:32;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 31 0
blackbox stateful_alu timesyncs2s_reqigts_lo_set {
    reg:timesyncs2s_reqigts_lo;
    update_lo_1_value:ig_intr_md_from_parser_aux.ingress_global_tstamp;
    output_value:alu_lo;
    output_dst:mdata.ingress_timestamp_clipped;
}

register timesyncs2s_macts_hi {
    width:16;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice timesync.igmacts 47 32
blackbox stateful_alu timesyncs2s_macts_hi_set {
    reg:timesyncs2s_macts_hi;
    update_lo_1_value: timesync.igmacts;
}

register timesyncs2s_macts_lo {
    width:32;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice timesync.igmacts 31 0
blackbox stateful_alu timesyncs2s_macts_lo_set {
    reg:timesyncs2s_macts_lo;
    update_lo_1_value: timesync.igmacts;
}

register timesyncs2s_now_macts_hi {
    width:16;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md.ingress_mac_tstamp 47 32
blackbox stateful_alu timesyncs2s_now_macts_hi_set {
    reg:timesyncs2s_now_macts_hi;
    update_lo_1_value: ig_intr_md.ingress_mac_tstamp ;
}

register timesyncs2s_now_macts_lo {
    width:32;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md.ingress_mac_tstamp 31 0
blackbox stateful_alu timesyncs2s_now_macts_lo_set {
    reg:timesyncs2s_now_macts_lo;
    update_lo_1_value: ig_intr_md.ingress_mac_tstamp;
}

register timesyncs2s_egts_lo {
    width:32;
    instance_count:MAX_SWITCHES;
}
@pragma stateful_field_slice timesync.egts 31 0
blackbox stateful_alu timesyncs2s_egts_lo_set {
    reg:timesyncs2s_egts_lo;
    update_lo_1_value: timesync.egts;
}

register timesyncs2s_cp_flag {
    width:32;
    instance_count:1;
}
blackbox stateful_alu timesyncs2s_flag_set {
    reg:timesyncs2s_cp_flag;
    update_lo_1_value: mdata.switch_id;
}

register timesync_cp_flag {
    width:32;
    instance_count:1;
}
blackbox stateful_alu timesync_flag_set {
    reg:timesync_cp_flag;
    update_lo_1_value: ig_intr_md_for_tm.ucast_egress_port;
}

register dptp_now_hi {
    width : 32;
    instance_count : 1;
}
blackbox stateful_alu dptp_now_hi_set {
    reg : dptp_now_hi;
    update_lo_1_value : mdata.dptp_now_hi;
}

register dptp_now_lo {
    width : 32;
    instance_count : 1;
}
blackbox stateful_alu dptp_now_lo_set {
    reg : dptp_now_lo;
    update_lo_1_value : mdata.dptp_now_lo;
}

register timesyncs2s_reqts_lo {
    width: 32;
    instance_count: MAX_SWITCHES;
}
@pragma stateful_field_slice eg_intr_md_from_parser_aux.egress_global_tstamp 31 0
blackbox stateful_alu timesyncs2s_reqts_lo_set {
    reg: timesyncs2s_reqts_lo;
    update_lo_1_value: eg_intr_md_from_parser_aux.egress_global_tstamp;
}

blackbox lpf current_utilization_bps {
    filter_input: eg_intr_md.pkt_length; //mdata.lpf_test;
    instance_count: MAX_LINKS;
}
register current_utilization {
    width : 32;
    instance_count : MAX_LINKS;
}
blackbox stateful_alu get_current_utilization {
    reg : current_utilization;
    update_lo_1_value : 0;//eg_intr_md.pkt_length;
    update_hi_1_value : register_hi + eg_intr_md.pkt_length;
    output_value : alu_hi;
    output_dst : mdata.current_utilization;
}
blackbox stateful_alu set_current_utilization {
    reg : current_utilization;
    update_lo_1_value : mdata.current_utilization;
}

action timesync_calculate_egdelta() {
    //modify_field(timesync.egdelta, eg_intr_md.deq_timedelta);
    //modify_field(timesync.egts, mdata.egress_timestamp_clipped);
    modify_field(timesync.egts, eg_intr_md_from_parser_aux.egress_global_tstamp);
}

action timesyncs2s_request() {
    timesyncs2s_reqts_lo_set.execute_stateful_alu(mdata.src_switch_id);
    modify_field(timesync.command, COMMAND_TIMESYNCS2S_REQUEST);
}

action timesyncs2s_response() {
    //timesyncs2s_respts_lo_set.execute_stateful_alu(mdata.switch_id);
    modify_field(timesync.command, COMMAND_TIMESYNCS2S_RESPONSE);
    timesync_calculate_egdelta();
}

action timesync_response() {
    modify_field(timesync.command, COMMAND_TIMESYNC_RESPONSE);
}

action timesync_capture_tx() {
    modify_field(eg_intr_md_for_oport.capture_tstamp_on_tx, 1);
}

action timesync_flag_cp_learn() {
    generate_digest(FLOW_LRN_DIGEST_RCVR, timesync_inform_cp_digest);
}

action timesync_flag_cp() {
    timesync_flag_set.execute_stateful_alu(0);
}

action do_timesync_current_rate () {
    modify_field(timesync.current_rate, mdata.current_utilization);
}


action do_calc_current_utilization (link) {
    current_utilization_bps.execute(mdata.current_utilization, link);
    modify_field(mdata.link, link);

}

action do_store_current_utilization () {
    set_current_utilization.execute_stateful_alu(mdata.link);
}


action timesync_hi_request() {
   reference_ts_hi_get.execute_stateful_alu(mdata.switch_id);
   //modify_field(timesync.command, COMMAND_TIMESYNC_RESPONSE);
   // modify_field(ethernet.dstAddr, ethernet.srcAddr);
   // modify_field(ethernet.srcAddr, 0x0000000011);
}

action dptp_now_hi_request() {
   reference_ts_hi_get.execute_stateful_alu(mdata.switch_id);
}

action timesync_request() {
    reference_ts_lo_get.execute_stateful_alu(mdata.switch_id);
}

action dptp_now_request() {
    reference_ts_lo_get.execute_stateful_alu(mdata.switch_id);
}
action reverse_packet() {
    /* Flip the src and dst mac */
    modify_field(ethernet.dstAddr, ethernet.srcAddr);
    modify_field(ethernet.srcAddr, 0x0000000011);

}

action timesync_get_era_lo() {
    era_ts_lo_get.execute_stateful_alu(0);
}

action timesync_get_era_hi() {
    era_ts_hi_get.execute_stateful_alu(0);
}

action timesync_do_clip_ts() {
    clip_ingress_timestamp.execute_stateful_alu(0);
}

action timesync_do_clip_egts() {
    clip_egress_timestamp.execute_stateful_alu(0);
}


action timesync_add_era() {
    //modify_field(mdata.result_ts_hi, mdata.reference_ts_hi);
    //modify_field(mdata.result_ts_lo, mdata.reference_ts_lo);
    add(mdata.result_ts_hi, mdata.reference_ts_hi, mdata.era_ts_hi);
}


action forward(newSrcMAC, newDstMAC, egress_spec) {
    // 1. Set the egress port of the next hop
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
    // 2. Update the ethernet destination address with the address of the next hop.
    modify_field(ethernet.dstAddr, newDstMAC);
    // 3. Update the ethernet source address with the address of the switch.
    modify_field(ethernet.srcAddr, newSrcMAC);
    // 4. Decrement the TTL
    add_to_field(ipv4.ttl, -1);
}

action do_timesyncs2s_capture_tx_set () {
    timesyncs2s_capture_tx_set.execute_stateful_alu(mdata.switch_id);
}
action timesyncs2s_capture_reference_hi() {
    timesyncs2s_reference_hi_set.execute_stateful_alu(mdata.switch_id);
}


action timesyncs2s_capture_reference_lo() {
    timesyncs2s_reference_lo_set.execute_stateful_alu(mdata.switch_id);
}

action timesyncs2s_capture_elapsed_lo() {
    timesyncs2s_elapsed_lo_set.execute_stateful_alu(mdata.switch_id);
}


action timesyncs2s_capture_igTs_hi(switch_id) {
    timesyncs2s_igts_hi_set.execute_stateful_alu(switch_id);
}

action timesyncs2s_capture_igTs_lo(switch_id) {
    timesyncs2s_igts_lo_set.execute_stateful_alu(switch_id);
}

action timesyncs2s_capture_macTs_lo() {
    timesyncs2s_macts_lo_set.execute_stateful_alu(mdata.switch_id);
}

action timesyncs2s_capture_now_macTs_lo() {
    timesyncs2s_now_macts_lo_set.execute_stateful_alu(mdata.switch_id);
}

action timesyncs2s_capture_egTs_lo() {
    timesyncs2s_egts_lo_set.execute_stateful_alu(mdata.switch_id);
}

action timesyncs2s_flag_cp() {
    timesyncs2s_flag_set.execute_stateful_alu(0);
    //Drop the packet
    drop();
}

action do_qos() {
    modify_field(ig_intr_md_for_tm.qid, 3);
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action copy_metadata () {
    //modify_field(mdata.reference_ts_hi, timesync.reference_ts_hi);
    modify_field(mdata.global_ts, ig_intr_md_from_parser_aux.ingress_global_tstamp);
}

action dptp_packet() {
    modify_field(timesync.reference_ts_lo, mdata.dptp_now_lo);
    modify_field(timesync.reference_ts_hi, mdata.dptp_now_hi);
    modify_field(timesync.era_ts_hi, mdata.era_ts_hi);
    modify_field(timesync.igmacts, ig_intr_md.ingress_mac_tstamp);
    modify_field(timesync.igts, ig_intr_md_from_parser_aux.ingress_global_tstamp);
}

action classify_switch(switch_id) {
    modify_field(mdata.switch_id, switch_id);
}

action classify_src_switch(switch_id) {
    modify_field(mdata.src_switch_id, switch_id);
}

action do_dptp_store_now_hi () {
    dptp_now_hi_set.execute_stateful_alu(0);
}

action do_dptp_store_now_lo () {
    dptp_now_lo_set.execute_stateful_alu(0);
}

action do_dptp_add_elapsed_hi () {
    add(mdata.dptp_now_hi, mdata.reference_ts_hi, mdata.ingress_timestamp_clipped_hi);
}

action do_dptp_add_elapsed_lo () {
    add(mdata.dptp_now_lo, mdata.reference_ts_lo, mdata.ingress_timestamp_clipped);
}

action do_dptp_overflow () {
    add(mdata.dptp_overflow_hi, mdata.dptp_now_hi, 1);
}

action do_dptp_handle_overflow () {
    add_to_field(mdata.dptp_now_hi, 1);
}

action do_dptp_calc_residue () {
    subtract(mdata.dptp_residue, MAX_32BIT, mdata.reference_ts_lo);
}

action do_dptp_compare_residue () {
    min(mdata.dptp_overflow_compare, mdata.dptp_residue, mdata.ingress_timestamp_clipped);
}

action do_dptp_compare_igts () {
    subtract(mdata.dptp_compare_residue, mdata.ingress_timestamp_clipped, mdata.dptp_overflow_compare);
}

action nop() {}

/**** Ingress Tables ****/
table store_current_utilization {
    actions {
        do_store_current_utilization;
    }
}

table timesync_delta {
    actions {
        timesync_calculate_egdelta;
    }
    size:1;
}


table timesyncs2s_gen_request {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        timesyncs2s_request;
    }
}

table timesyncs2s_gen_response {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        timesyncs2s_response;
    }
}

table timesync_gen_response {
    actions {
        timesync_response;
    }
}

table timesync_capture_ts {
    reads {
        mdata.command : exact;
    }
    actions {
        timesync_capture_tx;
        nop;
    }
}

table timesync_inform_cp {
    reads {
        mdata.command : exact;
    }
    actions {
        timesync_flag_cp_learn;
        nop;
    }
}

table timesync_current_rate {
    actions {
        do_timesync_current_rate;
    }
}

table calc_current_utilization {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        do_calc_current_utilization;
    }
}

table copy_meta {
    actions {
        copy_metadata;
    }
}
table timesync_hi_now {
    actions {
        timesync_hi_request;
    }
}

table timesync_now {
    actions {
        timesync_request;
    }
}
table copy_dptp_packet {
    reads {
        mdata.command : exact;
    }
    actions {
        dptp_packet;
        nop;
    }
}


table timesync_era_lo_get {
    actions {
        timesync_get_era_lo;
    }
}

table timesync_era_hi_get {
    actions {
        timesync_get_era_hi;
    }
}

table timesync_clip_ts {
    actions {
        timesync_do_clip_ts;
    }
}

table timesync_clip_egts {
    actions {
        timesync_do_clip_egts;
    }
}
table timesync_add_era_ts {
    actions {
        timesync_add_era;
    }
}

table timesyncs2s_store_reference_hi {
    actions {
        timesyncs2s_capture_reference_hi;
    }
}

table timesyncs2s_store_reference_lo {
    actions {
        timesyncs2s_capture_reference_lo;
    }
}
table timesyncs2s_store_capture_tx {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        do_timesyncs2s_capture_tx_set;
        nop;
    }
}

table timesyncs2s_store_elapsed_lo {
    actions {
        timesyncs2s_capture_elapsed_lo;
    }
}

table timesyncs2s_store_igTs_hi {
    reads {
        mdata.command : exact;
        mdata.switch_id : exact;
    }
    actions {
        timesyncs2s_capture_igTs_hi;
    }
}

table timesyncs2s_store_igTs_lo {
    reads {
        mdata.command : exact;
        mdata.switch_id : exact;
    }
    actions {
        timesyncs2s_capture_igTs_lo;
    }
}


table timesyncs2s_store_now_macTs_lo {
    actions {
        timesyncs2s_capture_now_macTs_lo;
    }
}

table timesyncs2s_store_macTs_lo {
    actions {
        timesyncs2s_capture_macTs_lo;
    }
}


table timesyncs2s_store_egTs_lo {
    actions {
        timesyncs2s_capture_egTs_lo;
    }
}

@pragma stage 10
table timesyncs2s_inform_cp {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        timesyncs2s_flag_cp;
        nop;
    }
}
@pragma stage 10
table timesyncs2s_inform_cp_diff {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        timesyncs2s_flag_cp;
        nop;
    }
}

table qos {
    reads {
        mdata.command : exact;
    }
    actions {
        do_qos;
        nop;
    }
}

table flip_address {
    reads {
        mdata.command : exact;
    }
    actions {
        reverse_packet;
        nop;
    }
}
action _drop() {
    drop();
}


table dropit {
    actions {
        _drop;
    }
}

table acl {
    reads {
        ig_intr_md.ingress_port : exact;
        ethernet.dstAddr : exact;
        ethernet.etherType : exact;
    }
    actions {
        _drop;
        nop;
    }
}

table classify_logical_switch {
    reads {
        //ig_intr_md.ingress_port : exact;
        ethernet.dstAddr : exact;
    }
    actions {
        classify_switch;
        nop;
    }
}

table classify_src_logical_switch {
    reads {
        //ig_intr_md.ingress_port : exact;
        ethernet.srcAddr : exact;
    }
    actions {
        classify_src_switch;
        nop;
    }
}

table dptp_add_elapsed_hi {
    actions {
        do_dptp_add_elapsed_hi;
    }
}

table dptp_add_elapsed_lo {
    actions {
        do_dptp_add_elapsed_lo;
    }
}

table dptp_store_now_hi {
    actions {
        do_dptp_store_now_hi;
    }
}

table dptp_store_now_lo {
    actions {
        do_dptp_store_now_lo;
    }
}

table dptp_overflow {
    actions {
        do_dptp_overflow;
    }
}

table dptp_handle_overflow {
    reads {
        mdata.dptp_compare_residue : exact;
    }
    actions {
        do_dptp_handle_overflow;
        nop;
    }
}

table dptp_calc_residue {
    actions {
        do_dptp_calc_residue;
    }
}

table dptp_compare_residue {
    actions {
        do_dptp_compare_residue;
    }
}

table dptp_compare_igts {
    actions {
        do_dptp_compare_igts;
    }
}
control dptp_get_ref {
    //1. Get Reference
    apply(timesync_now);
    apply(timesync_hi_now);
}

table mac_forward {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        set_egr;
        nop;
    }
    size:20;
}

control ingress {
    // Virtualization using Loop-backs (BNV)
    apply(acl);
    if (valid(timesync)) {
        apply(classify_logical_switch);
        apply(classify_src_logical_switch);
        apply(flip_address);
    }
    // Store current ingress time for DPTP Request.
    apply(timesyncs2s_store_igTs_hi);
    apply(timesyncs2s_store_igTs_lo);
    // Calculate current DPTP Global Time
    dptp_get_ref();
    apply(dptp_add_elapsed_hi);
    apply(dptp_calc_residue);
    apply(dptp_compare_residue);
    apply(dptp_compare_igts);
    apply(dptp_add_elapsed_lo);
    apply(dptp_handle_overflow);
    // (dptp_now_hi,dptp_now_lo) is the current global time
    apply(dptp_store_now_hi);
    apply(dptp_store_now_lo);
    // Handling DPTP request/response
    if (mdata.command == COMMAND_TIMESYNCS2S_RESPONSE) {
        // Got response from Another switch.
        apply(timesyncs2s_store_reference_hi);
        apply(timesyncs2s_store_reference_lo);
        apply(timesyncs2s_store_elapsed_lo);
        apply(timesyncs2s_store_now_macTs_lo);
        apply(timesyncs2s_store_macTs_lo);
        apply(timesyncs2s_store_egTs_lo);
        apply(timesyncs2s_inform_cp);
        //apply(dropit);
    } else if (mdata.command == COMMAND_TIMESYNC_CAPTURE_TX) {
    	if (ig_intr_md.ingress_port != 192) {
            apply(timesyncs2s_store_capture_tx);
            apply(timesyncs2s_inform_cp_diff);
     	}
    }
    // Forwarding for all packets based on MAC/IP
    apply(mac_forward);
    // Copy everything to DPTP packet header
    apply(copy_dptp_packet);
    apply(timesync_inform_cp);
    // Separate queuing for DPTP packets
    apply(qos);
}

control egress {
    if (eg_intr_md.pkt_length != 0) {
        apply(calc_current_utilization);
    }
    if (valid(timesync)) {
        apply(timesync_clip_egts);
        apply(timesync_capture_ts);
        if (mdata.command == COMMAND_TIMESYNCS2S_REQUEST) {
            // Response packet for Switch to Switch Timesync
            apply(timesyncs2s_gen_response);
        } else if (mdata.command == COMMAND_TIMESYNC_REQUEST) {
            // Response Packet for Switch to Host Timesync
            apply(timesync_gen_response);
            apply(timesync_delta);
            apply(timesync_current_rate);
        } else if (mdata.command == COMMAND_TIMESYNCS2S_GENREQUEST) {
            apply(timesyncs2s_gen_request);
        }
    }
    apply(store_current_utilization);
}
