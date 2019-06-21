
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_TIMESYNC 0x88F7

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
