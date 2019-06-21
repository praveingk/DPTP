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
