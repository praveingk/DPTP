/*******************************************************************************
 * DPTP : Headers Declaration
 *
 *
 *
 *
 ******************************************************************************/
#ifndef _DPTP_HEADERS
#define _DPTP_HEADERS

// TODO : Below DPTP header is not entirely compatible with IEEE 1588
header dptp_t {
    bit<16> magic;           // For backward-compatibility with PTP (IEEE 1588)
    bit<8>  command;         // For backward-compatibility with PTP (IEEE 1588)
    bit<32> reference_ts_hi; // Current Time Hi
    bit<32> reference_ts_lo; // Current Time Lo
    bit<32> current_rate;    // Traffic rate used for NIC profiling
    bit<48> igmacts;         // Mac     Timestamp
    bit<48> igts;            // Ingress Timestamp 
    bit<48> egts;            // Egress  Timestamp
}

header dptp_bridge_t {
#ifdef LOGICAL_SWITCHES
    bit<8> switch_id;
#endif // LOGICAL_SWITCHES
    PortId_t ingress_port;
    bit<7> _pad0;
}

header transparent_clock_t {
    bit<8>  udp_chksum_offset;
    bit<8>  elapsed_time_offset;
    bit<48> captureTs;
}

struct dptp_metadata_t {
    bit<32> reference_ts_hi;
    bit<32> reference_ts_lo;
    bit<32> mac_timestamp_clipped;
    bit<32> ingress_timestamp_clipped_hi;
    bit<32> ingress_timestamp_clipped;
    bit<32> ingress_timestamp_hi;
    bit<32> ingress_timestamp_lo;
    bit<32> reqdelay;
    bit<8>  switch_id;
    bit<8>  src_switch_id;
    bit<32> current_utilization;
    bit<32> dptp_now_hi;
    bit<32> dptp_now_lo;
    bit<64> dptp_now;
    bit<64> dptp_ref;
    bit<64> ingress_timestamp;
    PortId_t egress_port;
    bit<32> dptp_residue;
    bit<32> dptp_compare_residue;
    bit<1>  dptp_overflow;
    bit<32> dptp_overflow_compare;
}


#endif