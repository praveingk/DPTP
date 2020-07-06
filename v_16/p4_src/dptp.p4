/* -*- P4_16 -*- */
/*******************************************************************************
 * DPTP : Data-Plane Time-synchronization Protocol
 *
 *
 ******************************************************************************/
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "dptp_headers.p4"
#include "dptp_parser.p4"

#define COMMAND_DPTP_REQUEST 0x2
#define COMMAND_DPTP_RESPONSE 0x3

#define COMMAND_DPTP_FOLLOWUP 0x6
#define COMMAND_DPTPS2S_GENREQUEST 0x11
#define COMMAND_DPTPS2S_REQUEST 0x12
#define COMMAND_DPTPS2S_RESPONSE 0x13

#define MAX_32BIT 4294967295
#define MAX_LINKS 512

#define SWITCH_CPU 192

#ifdef LOGICAL_SWITCHES
#define MAX_SWITCHES 16
#else
#define MAX_SWITCHES 1
#endif



Register<bit<32>, bit<32>>(MAX_SWITCHES) ts_hi;

Register<bit<32>, bit<32>>(MAX_SWITCHES) ts_lo;

Register<bit<32>, bit<32>>(1) dptp_now_hi;

Register<bit<32>, bit<32>>(1) dptp_now_lo;

Register<bit<16>, bit<16>>(MAX_SWITCHES) timesyncs2s_igts_hi;

control DptpNow (inout header_t hdr, inout dptp_metadata_t dptp_meta, in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_parser_aux) {
    RegisterAction<bit<32>, bit<8>, bit<32>>(ts_hi) ts_hi_get = {
        void apply (inout bit<32> value, out bit<32> result) {  
            result = value;
        }
    };

    RegisterAction<bit<32>, bit<8>, bit<32>>(ts_lo) ts_lo_get = {
        void apply (inout bit<32> value, out bit<32> result) {
            result = value;
        }
    };

    RegisterAction<bit<16>, bit<8>, bit<16>>(timesyncs2s_igts_hi) timesyncs2s_igts_hi_set = {
        void apply(inout bit<16> value, out bit<16> result) {
            value = (bit<16>)ig_intr_md_from_parser_aux.global_tstamp[47:32];
            result = value;
        }
    }; 

    action timesyncs2s_capture_igTs_hi() {
        dptp_meta.ingress_timestamp_clipped_hi = (bit<16>)timesyncs2s_igts_hi_set.execute(0);
    }
    action timesync_hi_request() {
        dptp_meta.reference_ts_hi = ts_hi_get.execute(dptp_meta.switch_id);
    }

    action timesync_request() {
        dptp_meta.reference_ts_lo = ts_lo_get.execute(dptp_meta.switch_id);
    }

    action do_dptp_compare_residue() {
        dptp_meta.dptp_overflow_compare = (dptp_meta.dptp_residue <= dptp_meta.ingress_timestamp_clipped ? dptp_meta.dptp_residue : dptp_meta.ingress_timestamp_clipped);
    }

    action do_dptp_handle_overflow () {
        dptp_meta.dptp_now_hi = dptp_meta.dptp_now_hi + 1;
    }
    
    action nop () {

    }
    
    table dptp_handle_overflow {
        actions = {
            do_dptp_handle_overflow();
            nop();
        }
        key = {
            dptp_meta.dptp_compare_residue: exact;
        }
        size = 1;
        default_action = do_dptp_handle_overflow();
    }

    apply {
        /*
            DPTP Current Time Calculation Logic : 
            1) Slice the ingress timestamp to hi (16-bit) and lo (32-bit)
            2) Get the reference_hi and lo from ts_hi and ts_lo registers.
            3) Add reference_hi + ingress_hi, reference_lo + ingress_lo
            4) Now, we need to check if reference_lo + ingress_lo had overflown and handle it.
            5) To check overflow the logic is as follows:
                a) residue = MAX_32BIT - reference_lo
                b) overflow_compare = residue <= ingress_lo?: Overflow : no Overflow
                c) Since, tofino1 does not support the above operation, we do the below :
                    1) overflow_compare = residue <= ingress_lo?: residue : ingress_lo
                    2) compare_residue = ingress_lo - overflow_compare
                    3) if compare_residue == 0, then no overlow, else overflow
        */            
        timesyncs2s_capture_igTs_hi();
        dptp_meta.ingress_timestamp_clipped = (bit<32>)ig_intr_md_from_parser_aux.global_tstamp[31:0];
        timesync_hi_request();
        timesync_request();        
        dptp_meta.dptp_now_lo = dptp_meta.reference_ts_lo + dptp_meta.ingress_timestamp_clipped;
        dptp_meta.dptp_now_hi = dptp_meta.reference_ts_hi + (bit<32>)dptp_meta.ingress_timestamp_clipped_hi;
        dptp_meta.dptp_residue = MAX_32BIT - dptp_meta.reference_ts_lo;
        do_dptp_compare_residue();
        dptp_meta.dptp_compare_residue = dptp_meta.ingress_timestamp_clipped - dptp_meta.dptp_overflow_compare;
        dptp_handle_overflow.apply();
    }
}


#ifdef DPTP_CALC_DP // Used to perform DPTP time correction/calculation in the Data-plane

Register<bit<32>, bit<32>>(MAX_SWITCHES) dptp_reqmacdelay;

Register<bit<32>, bit<32>>(MAX_SWITCHES) dptp_respigts;

Register<bit<32>, bit<32>>(MAX_SWITCHES) dptp_respnow_hi;

Register<bit<32>, bit<32>>(MAX_SWITCHES) dptp_respnow_lo;

control DptpRespStore (inout header_t hdr, inout dptp_metadata_t dptp_meta) {
    
    RegisterAction<bit<32>, bit<8>, bit<32>>(dptp_reqmacdelay) dptp_reqmacdelay_set = {
        void apply(inout bit<32> value) {
            value = (bit<32>)hdr.dptp.igmacts;
        }
    };

    RegisterAction<bit<32>, bit<8>, bit<32>>(dptp_respigts) dptp_respigts_set = {
        void apply(inout bit<32> value, out bit<32> result) {
            value = (bit<32>)hdr.dptp.igts;
        }
    };    

    RegisterAction<bit<32>, bit<8>, bit<32>>(dptp_respnow_hi) dptp_respnow_hi_set = {
        void apply(inout bit<32> value) {
            value = hdr.dptp.reference_ts_hi;
        }
    };

    RegisterAction<bit<32>, bit<8>, bit<32>>(dptp_respnow_lo) dptp_respnow_lo_set = {
        void apply(inout bit<32> value) {
            value = hdr.dptp.reference_ts_lo;
        }
    };
    
    action dptp_store_reqmacdelay (bit<8> switch_id) {
        dptp_reqmacdelay_set.execute(switch_id);
    }
    
    action dptp_store_respigts () {
        dptp_respigts_set.execute(dptp_meta.switch_id);
    }

    action dptp_store_reference_hi () {
        dptp_respnow_hi_set.execute(dptp_meta.switch_id);
    }
    
    action dptp_store_reference_lo () {
        dptp_respnow_lo_set.execute(dptp_meta.switch_id);
    }LOGICAL_SWITCHES
    
    apply {
        /*
        This control processes the reply packet, and stores the necessary information
        needed while the followup message comes. What all we need to store?
        1) Reference_hi, Reference_lo
        2) ReqMacDelay
        3) ElapsedIngress TS
        */
        dptp_store_reference_hi();
        dptp_store_reference_lo();
        dptp_store_reqmacdelay();
        dptp_store_respigts();
    }
}

control DptpCorrect (inout header_t hdr, inout metadata_t meta) {

    apply {
        /*
        What info we need for time calculation/offset at data-plane?
        1) ReqCaptureTx
        2) ReqMacDelay (igress - mac from server)
        3) ReferenceTs
        4) ElapsedTs (IgTs)
        4) RespCaptureTx 
        5) NowMacDelay (nowIgTs - nowMacTs )
        6) Now (nowIgTs)

        Upon receiving the followup packet.
            latency_tx = nowMacTs - ReqCaptureTx           => Stage 1
            respDelay  = RespCaptureTx - ElapsedTs         => Stage 1
            
            A = ReqMacDelay - respDelay                    => Stage 2       
            Resp = respDelay + NowMacDelay                 => Stage 2
            Wire = (latency_tx - A) >> 1                   => Stage 3

            RespDelay = Wire + Resp                        => Stage 4

            Reference_lo = Reference_lo + RespDelay_lo     => Stage 5
            Reference_hi = Reference_hi - nowIgTs       
            if (Reference_lo > nowIgTs_lo)                 => Stage 6
                Reference_lo = Reference_lo - nowIgTs_lo   => Stage 7
                Reference_hi = Reference_hi - nowIgTs_hi   => Stage 7
            else                    
                Reference_lo = (Reference_lo + MAX_32BIT) - nowIgTs_lo -> Need to figure how to do this.
                Reference_hi = Reference_hi - 1

        Embed the  recalculated reference in followup packet, and update the actual Reference Register so that 
        */

    }
}
#endif

control DptpIngress(
    inout header_t hdr, 
    inout dptp_metadata_t dptp_meta, 
    inout dptp_bridge_t bridge, 
    in ingress_intrinsic_metadata_t ig_intr_md, 
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_parser_aux, 
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr, 
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm) {

    RegisterAction<bit<32>, bit<1>, bit<32>>(dptp_now_hi) dptp_now_hi_set = {
        void apply(inout bit<32> value) {
            value = dptp_meta.dptp_now_hi;
        }
    };
    
    RegisterAction<bit<32>, bit<1>, bit<32>>(dptp_now_lo) dptp_now_lo_set = {
        void apply(inout bit<32> value) {
            value = dptp_meta.dptp_now_lo;
        }
    };

    action _drop() {
        ig_intr_md_for_dprsr.drop_ctl = 1;
    }

    action nop() {}
    
    action fill_dptp_packet() {
        hdr.dptp.reference_ts_lo = dptp_meta.dptp_now_lo;
        hdr.dptp.reference_ts_hi = dptp_meta.dptp_now_hi;
        hdr.dptp.igmacts = ig_intr_md.ingress_mac_tstamp;
        hdr.dptp.igts = ig_intr_md_from_parser_aux.global_tstamp;
    }
    
    action do_dptp_store_now_hi() {
        dptp_now_hi_set.execute(0);
    }

    action do_dptp_store_now_lo() {
        dptp_now_lo_set.execute(0);
    }
    
    action reverse_packet() {
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = 48w0x11;
    }

    action set_egr(PortId_t egress_spec) {
        ig_intr_md_for_tm.ucast_egress_port = (bit<9>)egress_spec;
        dptp_meta.egress_port = egress_spec;
    }
    
    action do_qos() {
        ig_intr_md_for_tm.qid = 5w3;
    }
    
    action timesync_flag_cp_learn() {
        ig_intr_md_for_dprsr.digest_type = DPTP_FOLLOWUP_DIGEST_TYPE;
    }    
    
    table dptp_store_now_hi {
        actions = {
            do_dptp_store_now_hi();
        }
        default_action = do_dptp_store_now_hi();
    }
    
    table dptp_store_now_lo {
        actions = {
            do_dptp_store_now_lo();
        }
        default_action = do_dptp_store_now_lo();
    }
    
    table dropit {
        actions = {
            _drop();
        }
        default_action = _drop();
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


    apply {
        if (hdr.dptp.command == COMMAND_DPTPS2S_RESPONSE) {
#ifdef DPTP_CALC_DP
            // DPTP Reference Adjustment in the data-plane.
            DptpRespStore.apply();
#else
            // Send a Digest to control-plane for DPTP Reference Adjustment
            dptp_meta.mac_timestamp_clipped = (bit<32>)ig_intr_md.ingress_mac_tstamp[31:0];
            ig_intr_md_for_dprsr.digest_type = DPTP_REPLY_DIGEST_TYPE;
            _drop();
#endif
            // Send Digest to Control-plane along with reply details
        } else if (hdr.dptp.command == COMMAND_DPTP_FOLLOWUP) {
            if (ig_intr_md.ingress_port != SWITCH_CPU) {
#ifdef DPTP_CALC_DP
                //DPTP Reference Adjustment in the data-plane.
                DptpCorrect.apply();
#else
                // Send Digest to Control-plane along with reply details for Time calculation.
                ig_intr_md_for_dprsr.digest_type = DPTP_REPLY_FOLLOWUP_DIGEST_TYPE;
                _drop();
#endif
            }
        }

        if (hdr.dptp.command == COMMAND_DPTP_REQUEST || hdr.dptp.command == COMMAND_DPTPS2S_REQUEST) {
            reverse_packet();
            fill_dptp_packet();
            ig_intr_md_for_dprsr.digest_type = DPTP_FOLLOWUP_DIGEST_TYPE;
        }
#ifdef LOGICAL_SWITCHES        
        mac_forward.apply();
        bridge.switch_id = dptp_meta.switch_id;
#endif // LOGICAL_SWITCHES
        bridge.setValid();
        bridge.ingress_port = ig_intr_md.ingress_port;
        do_qos();
    }
}


#ifdef LOGICAL_SWITCHES
Register<bit<32>, bit<32>>(MAX_LINKS) current_utilization;
#endif // LOGICAL_SWITCHES
Register<bit<32>, bit<32>>(MAX_SWITCHES) timesyncs2s_reqts_lo;

control DptpEgress(
    inout header_t hdr, 
    inout dptp_metadata_t dptp_meta, 
    inout dptp_bridge_t bridge,
    in egress_intrinsic_metadata_t eg_intr_md, 
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_parser_aux,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    Lpf<bit<16>, bit<9>>(MAX_LINKS) current_utilization_bps;

#ifdef LOGICAL_SWITCHES
    RegisterAction<bit<32>, bit<9>, bit<32>>(current_utilization) set_current_utilization = {
        void apply(inout bit<32> value) {
            bit<32> in_value;
            in_value = value;
            value = dptp_meta.current_utilization;
        }
    };
#endif // LOGICAL_SWITCHES    

    RegisterAction<bit<32>, bit<32>, bit<32>>(timesyncs2s_reqts_lo) timesyncs2s_reqts_lo_set = {
        void apply(inout bit<32> value) {
            bit<32> in_value;
            in_value = value;
            value = (bit<32>)eg_intr_md_from_parser_aux.global_tstamp;
        }
    };
    
    /*** Actions ***/

    action do_calc_host_rate () {
        dptp_meta.current_utilization = (bit<32>)current_utilization_bps.execute(eg_intr_md.pkt_length, bridge.ingress_port);
    }

    action nop () {}

#ifdef LOGICAL_SWITCHES
    action do_store_current_utilization () {
        set_current_utilization.execute(bridge.ingress_port);
    }
#endif // LOGICAL_SWITCHES

    action do_dptp_capture_tx () {
        // hdr.transparent_clock.setValid();
        // hdr.transparent_clock.udp_chksum_offset = 0;
        // hdr.transparent_clock.elapsed_time_offset = 51;
        // hdr.transparent_clock.captureTs = 0;
        //eg_intr_md_for_oport.update_delay_on_tx = 1;
        eg_intr_md_for_oport.capture_tstamp_on_tx = 1;
    }
    action do_dptp_response () {
        hdr.dptp.command = COMMAND_DPTP_RESPONSE;
        hdr.dptp.egts = eg_intr_md_from_parser_aux.global_tstamp;
        hdr.dptp.current_rate = dptp_meta.current_utilization;
    }
    action do_dptps2s_request () {
        hdr.dptp.command = COMMAND_DPTPS2S_REQUEST;
    }
    action do_dptps2s_response () {
        hdr.dptp.command = COMMAND_DPTPS2S_RESPONSE;
        hdr.dptp.egts = eg_intr_md_from_parser_aux.global_tstamp;
    }

    apply {
        do_calc_host_rate();
        if (hdr.dptp.command != COMMAND_DPTP_FOLLOWUP) {
            do_dptp_capture_tx();
        }
        if (hdr.dptp.command == COMMAND_DPTPS2S_REQUEST) {
            do_dptps2s_response();
        } else if (hdr.dptp.command == COMMAND_DPTP_REQUEST) {
            do_dptp_response();
        } else if (hdr.dptp.command == COMMAND_DPTPS2S_GENREQUEST) {
            do_dptps2s_request();
        }       
    }
}

