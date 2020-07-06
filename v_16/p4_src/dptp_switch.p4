/* -*- P4_16 -*- */
/*******************************************************************************
 * Switch with DPTP enabled
 * This code demonstrates how to integrate DPTP control inside any p4_16 code 
 *
 ******************************************************************************/

#include "dptp.p4"
#include "dptp_parser.p4"
#include "dptp_headers.p4"


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


struct header_t {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    dptp_t          dptp;
}

struct metadata_t {
    dptp_metadata_t    mdata;
    dptp_bridge_t      bridged_header;
}


parser DptpSwitchIngressParser (
    packet_in pkt, 
    out header_t hdr, 
    out metadata_t meta, 
    out ingress_intrinsic_metadata_t ig_intr_md, 
    out ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm, 
    out ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr) {

    DptpIngressParser() dptp_ingress_parser;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE); // macro defined in tofino.p4
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        dptp_ingress_parser.apply(pkt, hdr.dptp, hdr.ethernet.etherType);
        transition select(hdr.ethernet.etherType) {
            (bit<16>) ether_type_t.IPV4 : parse_ipv4;
            default                     : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }    
}

// control DptpSwitchIngressDeparser (
//     packet_out pkt, 
//     inout header_t hdr, 
//     in metadata_t meta, 
//     in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

//     DptpIngressDeparser() dptp_ingress_deparser;

//     apply {
//         dptp_ingress_deparser.apply(pkt, hdr, meta, ig_intr_md_for_dprsr);
//         pkt.emit(hdr.ethernet);
//     }
// }

control DptpSwitchIngressDeparser (
    packet_out pkt, 
    inout header_t hdr, 
    in metadata_t meta, 
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {


    DptpIngressDeparser() dptp_ingress_deparser;

    apply {
        dptp_ingress_deparser.apply(hdr.ethernet.dstAddr, hdr.dptp, meta.mdata, ig_intr_md_for_dprsr);
        pkt.emit(meta.bridged_header);  
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.dptp);
    }
}

parser DptpSwitchEgressParser (
    packet_in pkt, 
    out header_t hdr, 
    out metadata_t meta, 
    out egress_intrinsic_metadata_t eg_intr_md) {

    DptpBridgeParser() dptp_bridge_parser;    
    DptpEgressParser() dptp_egress_parser;


    state start {
        pkt.extract(eg_intr_md);
        dptp_bridge_parser.apply(pkt, meta.mdata, meta.bridged_header);
        transition parse_ethernet;
    }


    state parse_ethernet {        
        pkt.extract(hdr.ethernet);
        dptp_egress_parser.apply(pkt, hdr.dptp, hdr.ethernet.etherType);
        transition select(hdr.ethernet.etherType) {
            (bit<16>) ether_type_t.IPV4 : parse_ipv4;
            default                     : accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
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



control virtSwitch(
    inout header_t hdr, 
    inout metadata_t meta,     
    in ingress_intrinsic_metadata_t ig_intr_md, 
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    action _drop() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
    }

    action nop() {}

    action classify_switch (bit<8> switch_id) {
        meta.mdata.switch_id = switch_id;
    }
    
    action classify_src_switch (bit<8> switch_id) {
        meta.mdata.src_switch_id = switch_id;
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
    
    apply {
        acl.apply();
        if (hdr.dptp.isValid()) {
            classify_logical_switch.apply();
            classify_src_logical_switch.apply();
        }
    }

}


control DptpSwitchIngress(
    inout header_t hdr, 
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md, 
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_parser_aux, 
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr, 
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    action nop () {}

    action set_egr(PortId_t egress_spec) {
        ig_intr_md_for_tm.ucast_egress_port = (bit<9>)egress_spec;
        meta.mdata.egress_port = egress_spec;
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

#ifdef LOGICAL_SWITCHES
    virtSwitch() virt_switch;
#endif // LOGICAL_SWITCHES

    DptpNow() dptp_now;
    DptpIngress() dptp_ingress;


    apply {
#ifdef LOGICAL_SWITCHES    
        virt_switch.apply(hdr, meta, ig_intr_md, ig_intr_md_for_dprsr);
#endif // LOGICAL SWITCHES        
        dptp_now.apply(meta.mdata, ig_intr_md_from_parser_aux);
        // Current Global time is now available here.
        dptp_ingress.apply(hdr.dptp, hdr.ethernet.srcAddr, hdr.ethernet.dstAddr, 
            meta.mdata,meta.bridged_header, ig_intr_md, ig_intr_md_from_parser_aux, ig_intr_md_for_dprsr, ig_intr_md_for_tm);
        mac_forward.apply();
    }
}

control DptpSwitchEgress(
    inout header_t hdr, 
    inout metadata_t meta, 
    in egress_intrinsic_metadata_t eg_intr_md, 
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_parser_aux,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    DptpEgress() dptp_egress;

    apply {
        dptp_egress.apply(hdr.dptp, meta.mdata, meta.bridged_header, 
            eg_intr_md, eg_intr_md_from_parser_aux, eg_intr_md_for_dprsr, eg_intr_md_for_oport);
    }
}

Pipeline(
    DptpSwitchIngressParser(), 
    DptpSwitchIngress(), 
    DptpSwitchIngressDeparser(), 
    DptpSwitchEgressParser(), 
    DptpSwitchEgress(), 
    DptpEgressDeparser()) pipe;

Switch(pipe) main;

