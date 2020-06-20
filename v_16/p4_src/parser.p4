/*******************************************************************************
 * DPTP : Parser Declaration
 *
 *
 *
 *
 ******************************************************************************/

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
    bit<32> now_igts_hi;
    bit<32> now_igts_lo;
    bit<32> now_macts_lo; 
}

struct reply_followup_digest_t {
    bit<8> switch_id;
    bit<32> tx_capturets_lo;
}


parser DptpIngressParser (
    packet_in pkt, 
    out header_t hdr, 
    out metadata_t meta, 
    out ingress_intrinsic_metadata_t ig_intr_md, 
    out ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm, 
    out ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE); // macro defined in tofino.p4
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
            (bit<16>) ether_type_t.IPV4 : parse_ipv4;
            (bit<16>) ether_type_t.DPTP : parse_dptp;
            default                     : accept;
        }
    }

    state parse_transparent_clock {
        //pkt.extract(hdr.transparent_clock);
        transition parse_ethernet;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_dptp {
        pkt.extract(hdr.dptp);
        meta.mdata.command = (bit<5>)hdr.dptp.command;
        transition accept;
    }
}

control DptpIngressDeparser (
    packet_out pkt, 
    inout header_t hdr, 
    in metadata_t meta, 
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {
    // in ingress_intrinsic_metadata_t ig_intr_md, 
    // in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_parser_aux, 
    // inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr, 
    // inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_t) {
    Digest<followup_digest_t>()          dptp_followup_digest;
    Digest<reply_digest_t>()             dptp_reply_digest;
    Digest<reply_followup_digest_t>()    dptp_reply_followup_digest;

    apply {
        if (ig_intr_md_for_dprsr.digest_type == DPTP_FOLLOWUP_DIGEST_TYPE) {
            dptp_followup_digest.pack({(bit<16>)meta.mdata.egress_port, hdr.ethernet.dstAddr, meta.mdata.ingress_timestamp_clipped});
        }
        if (ig_intr_md_for_dprsr.digest_type == DPTP_REPLY_DIGEST_TYPE) {
            dptp_reply_digest.pack({meta.mdata.switch_id[7:0],
                                        hdr.dptp.reference_ts_hi,
                                        hdr.dptp.reference_ts_lo,
                                        //hdr.dptp.igts[47:32],
                                        hdr.dptp.igts[31:0],
                                        hdr.dptp.igmacts[31:0],
                                        hdr.dptp.egts[31:0],
                                        meta.mdata.ingress_timestamp_clipped_hi,
                                        meta.mdata.ingress_timestamp_clipped,
                                        meta.mdata.mac_timestamp_clipped});
        }
        if (ig_intr_md_for_dprsr.digest_type == DPTP_REPLY_FOLLOWUP_DIGEST_TYPE) {
            dptp_reply_followup_digest.pack({meta.mdata.switch_id[7:0],
                                                hdr.dptp.reference_ts_hi});
        }
        pkt.emit(meta.bridged_header);
        //pkt.emit(hdr.transparent_clock);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.dptp);
    }
}


parser DptpEgressParser (
    packet_in pkt, 
    out header_t hdr, 
    out metadata_t meta, 
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
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
            (bit<16>) ether_type_t.IPV4 : parse_ipv4;
            (bit<16>) ether_type_t.DPTP : parse_dptp;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_dptp {
        pkt.extract(hdr.dptp);
        meta.mdata.command = (bit<5>)hdr.dptp.command;
        // meta.mdata.reference_ts_hi = hdr.dptp.reference_ts_hi;
        // meta.mdata.reference_ts_lo = hdr.dptp.reference_ts_lo;
        // meta.mdata.result_ts_hi = 0;
        // meta.mdata.result_ts_lo = 0;
        transition accept;
    }
    
    state parse_transparent_clock {
        //pkt.extract(hdr.transparent_clock);
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
        pkt.emit(hdr);
    }
}