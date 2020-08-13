/*******************************************************************************
 * DPTP : Parser Declaration
 *
 *
 *
 *
 ******************************************************************************/
#ifndef _DPTP_PARSER
#define _DPTP_PARSER

#define DPTP_FOLLOWUP_DIGEST_TYPE       2
#define DPTP_REPLY_DIGEST_TYPE          3
#define DPTP_REPLY_FOLLOWUP_DIGEST_TYPE 4


enum bit<16> ether_type_t {
    IPV4  = 0x0800,
    DPTP  = 0x88F7
}

struct followup_digest_t {
    bit<16> egress_port;
    bit<48> mac_addr;
    bit<32> timestamp;
}


struct reply_digest_t {
    bit<8>  switch_id;
    bit<32> reference_ts_hi;
    bit<32> reference_ts_lo;
    //bit<16> elapsed_hi;
    bit<32> elapsed_lo;
    bit<32> macts_lo;
    bit<32> egts_lo;
    bit<16> now_igts_hi;
    bit<32> now_igts_lo;
    bit<32> now_macts_lo; 
}

struct reply_followup_digest_t {
    bit<8> switch_id;
    bit<32> tx_capturets_lo;
}


parser DptpIngressParser (
    packet_in pkt, 
    out dptp_t dptp, 
    in bit<16> ethernet_type) {

    state start {
        transition select(ethernet_type) {
            (bit<16>) ether_type_t.DPTP : parse_dptp;
            default                     : accept;
        }
    }

    state parse_dptp {
        pkt.extract(dptp);
        transition accept;
    }
}

control DptpIngressDeparser (in bit<48> ethernet_dstAddr, 
    inout dptp_t dptp, 
    in dptp_metadata_t dptp_meta, 
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    Digest<followup_digest_t>()          dptp_followup_digest;
    Digest<reply_digest_t>()             dptp_reply_digest;
    Digest<reply_followup_digest_t>()    dptp_reply_followup_digest;

    apply {
        if (ig_intr_md_for_dprsr.digest_type == DPTP_FOLLOWUP_DIGEST_TYPE) {
            dptp_followup_digest.pack({(bit<16>)dptp_meta.egress_port, ethernet_dstAddr, dptp_meta.ingress_timestamp_clipped});
        }
        if (ig_intr_md_for_dprsr.digest_type == DPTP_REPLY_DIGEST_TYPE) {
            dptp_reply_digest.pack({dptp_meta.switch_id,
                                        dptp.reference_ts_hi,
                                        dptp.reference_ts_lo,
                                        //hdr.dptp.igts[47:32],
                                        dptp.igts[31:0],
                                        dptp.igmacts[31:0],
                                        dptp.egts[31:0],
                                        dptp_meta.ingress_timestamp_hi[15:0],
                                        dptp_meta.ingress_timestamp_lo,
                                        dptp_meta.mac_timestamp_clipped});
        }
        if (ig_intr_md_for_dprsr.digest_type == DPTP_REPLY_FOLLOWUP_DIGEST_TYPE) {
            dptp_reply_followup_digest.pack({dptp_meta.switch_id,
                                                dptp.reference_ts_hi});
        }
        //pkt.emit(meta.bridged_header);

        // pkt.emit(meta.bridged_header);
        // pkt.emit(hdr.ethernet);
        // pkt.emit(hdr.ipv4);
        // pkt.emit(hdr.dptp);
    }
}

parser DptpBridgeParser (
    packet_in pkt, 
    out dptp_metadata_t dptp_meta,
    out dptp_bridge_t   bridge) {

    state start {
        pkt.extract(bridge);
#ifdef LOGICAL_SWITCHES
        dptp_meta.switch_id = bridge.switch_id;
#endif
        transition accept;
    }
}

parser DptpEgressParser (
    packet_in pkt, 
    out dptp_t dptp, 
    in bit<16> ethernet_type) {

    state start {
        transition select(ethernet_type) {
            (bit<16>) ether_type_t.DPTP : parse_dptp;
            default                     : accept;
        }
    }
    
    
    state parse_dptp {
        pkt.extract(dptp);
        transition accept;
    }
    
}


#endif