/*******************************************************************************
 * DPTP : Headers Declaration
 *
 *
 *
 *
 ******************************************************************************/

struct dptp_metadata_t {
    bit<5>  command;
    bit<32> reference_ts_hi;
    bit<32> reference_ts_lo;
    bit<32> mac_timestamp_clipped;
    bit<32> ingress_timestamp_clipped_hi;
    bit<32> ingress_timestamp_clipped;
    bit<32> reqdelay;
    bit<32> capture_tx;
    bit<8>  switch_id;
    bit<8>  src_switch_id;
    bit<32> current_utilization;
    bit<32> dptp_now_hi;
    bit<32> dptp_now_lo;
    PortId_t egress_port;
    bit<32> dptp_residue;
    bit<32> dptp_compare_residue;
    bit<1>  dptp_overflow;
    bit<32> dptp_overflow_compare;
}

header bridged_header_t {
    bit<8> switch_id;
    PortId_t ingress_port;
    bit<7> _pad0;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header dptp_t {
    bit<16> magic;           // For backward-compatibility with PTP (IEEE 1588)
    bit<8>  command;         // For backward-compatibility with PTP (IEEE 1588)
    bit<32> reference_ts_hi;
    bit<32> reference_ts_lo;
    bit<32> current_rate;
    bit<48> igmacts;
    bit<48> igts;
    bit<48> egts;
    //bit<48> capturets;
    //bit<5>  _pad0;
}

header transparent_clock_t {
    bit<8>  udp_chksum_offset;
    bit<8>  elapsed_time_offset;
    bit<48> captureTs;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> hdr_length;
    bit<16> checksum;
}

struct metadata_t {
    dptp_metadata_t    mdata;
    bridged_header_t bridged_header;
}

struct header_t {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    dptp_t          dptp;
}
