/*******************************************************************************
 * DPTP : Parser Declaration
 *
 *
 *
 *
 ******************************************************************************/


#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_DPTP  0x88F7

#define DPTP_DIGEST_TYPE 2

struct followup_digest_t {
    bit<16> egress_port;
    bit<48> macAddr;
}


parser DptpIngressParser (
    packet_in pkt, 
    out header_t hdr, 
    out metadata_t meta, 
    out ingress_intrinsic_metadata_t ig_intr_md, 
    out ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm, 
    out ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr) {

    state start {
        transition parse_ethernet;
    }

    // state start_transparent_clock {
    //     pkt.extract(ig_intr_md);
    //     transition select((pkt.lookahead<bit<112>>())[15:0]) {
    //         ETHERTYPE_DPTP: parse_ethernet;
    //         ETHERTYPE_IPV4: parse_ethernet;
    //         default: parse_transparent_clock;
    //     }
    // }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_DPTP: parse_dptp;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_transparent_clock {
        pkt.extract(hdr.transparent_clock);
        transition parse_ethernet;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_dptp {
        pkt.extract(hdr.timesync);
        meta.mdata.command = hdr.timesync.command;
        // meta.mdata.reference_ts_hi = hdr.timesync.reference_ts_hi;
        // meta.mdata.reference_ts_lo = hdr.timesync.reference_ts_lo;
        // meta.mdata.result_ts_hi = 0;
        // meta.mdata.result_ts_lo = 0;
        transition accept;
    }
}

control DptpIngressDeparser (
    packet_out pkt, 
    inout header_t hdr, 
    in metadata_t meta, 
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    Digest<followup_digest_t>() timesync_inform_cp_digest;
    apply {
        if (ig_intr_md_for_dprsr.digest_type == DPTP_DIGEST_TYPE) {
            timesync_inform_cp_digest.pack({meta.mdata.egress_port, hdr.ethernet.dstAddr});
        }
        pkt.emit(meta.bridged_header);
        //pkt.emit(hdr.transparent_clock);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.timesync);
    }
}


parser DptpEgressParser (
    packet_in pkt, 
    out header_t hdr, 
    out metadata_t meta, 
    out egress_intrinsic_metadata_t eg_intr_md) {
    
    state start {
        transition bridged_metadata;
    }

    state bridged_metadata {
        pkt.extract(meta.bridged_header);
        meta.mdata.switch_id = meta.bridged_header.switch_id;
        transition parse_ethernet;
    }

    // state start_transparent_clock {
    //     transition select((pkt.lookahead<bit<112>>())[15:0]) {
    //         ETHERTYPE_IPV4: parse_ethernet;
    //         ETHERTYPE_DPTP: parse_ethernet;
    //         default: parse_transparent_clock;
    //     }
    // }    

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_DPTP: parse_dptp;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_dptp {
        pkt.extract(hdr.timesync);
        meta.mdata.command = hdr.timesync.command;
        // meta.mdata.reference_ts_hi = hdr.timesync.reference_ts_hi;
        // meta.mdata.reference_ts_lo = hdr.timesync.reference_ts_lo;
        // meta.mdata.result_ts_hi = 0;
        // meta.mdata.result_ts_lo = 0;
        transition accept;
    }
    
    state parse_transparent_clock {
        pkt.extract(hdr.transparent_clock);
        transition parse_ethernet;
    }
}

control DptpEgressDeparser(
    packet_out pkt,
    inout header_t hdr,
    in metadata_t meta,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md){

    Checksum() ipv4_checksum;
    apply {
        hdr.ipv4.hdrChecksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.totalLen,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.fragOffset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr});
        //pkt.emit(hdr.transparent_clock);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.timesync);
    }
}