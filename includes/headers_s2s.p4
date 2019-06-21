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
        trans_delay : 32;
        igmacts : 48;
        igts : 48;
        egts : 48;
        capturets : 48;
    }
}

header timesync_t timesync;

header_type transparent_clock_t {
	fields {
        udp_chksum_offset   : 8;
        elapsed_time_offset : 8;
		captureTs           : 48;
	}
}

header transparent_clock_t transparent_clock;

header_type cpu_ctrl_t {
    fields {
        command : 8;
        global_ts : 48;
    }
}
header cpu_ctrl_t cpu_ctrl;

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
        offset_global_ts_hi : 32;
        offset_global_ts_lo : 32;
        adjust : 48;
        trans_delay_offset : 32;
        mac_timestamp_clipped : 32;
        ingress_timestamp_clipped : 32;
        egress_timestamp_clipped : 32;
        switch_id : 32;
    }
}

metadata metadata_t mdata;


field_list hash_fields {
    ethernet.srcAddr;
}

field_list_calculation src_hash {
    input { hash_fields; }
    algorithm: random;
    output_width: 16;
}
