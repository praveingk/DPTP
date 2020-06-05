/*
 * Control Plane program for Tofino-based Timesync program.
 * Compile using following command : make ARCH=Target[tofino|tofinobm]
 * To Execute, Run: ./dptp_topo_cp
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <sched.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <bfsys/bf_sal/bf_sys_intf.h>
#include <dvm/bf_drv_intf.h>
#include <lld/lld_reg_if.h>
#include <lld/lld_err.h>
#include <lld/bf_ts_if.h>
#include <knet_mgr/bf_knet_if.h>
#include <knet_mgr/bf_knet_ioctl.h>
#include <bf_switchd/bf_switchd.h>
#include <pkt_mgr/pkt_mgr_intf.h>
#include <tofino/pdfixed/pd_common.h>
#include <tofino/pdfixed/pd_conn_mgr.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <tofinopd/dptp_topo/pd/pd.h>
#include <tofino/pdfixed/pd_common.h>
#include <tofino/pdfixed/pd_conn_mgr.h>
#include <port_mgr/bf_port_if.h>

#define THRIFT_PORT_NUM 7777
#define DPTP_GEN_REQ 0x11
#define DPTP_CAPTURE_COMMAND 0x6

p4_pd_sess_hdl_t sess_hdl;
typedef struct __attribute__((__packed__)) dptp_t {
  uint8_t dstAddr[6];
  uint8_t srcAddr[6];
  uint16_t type;
	uint16_t magic;
	uint8_t command;
	uint32_t reference_ts_hi;
	uint32_t reference_ts_lo;
	uint32_t eraTs;
	uint32_t delta;
	uint8_t igMacTs[6];
	uint8_t igTs[6];
	uint8_t egTs[6];
} dptp;

pcap_t *ppcap;
dptp dptp_pkt;
uint8_t *pkt;

// DPTP Followup
dptp dptp_followup_pkt;
uint8_t *upkt;
size_t sz = sizeof(dptp);
bf_pkt *bfpkt = NULL;
// DPTP Request
dptp dptp_request_pkt;
uint8_t *dreqpkt;
size_t dptp_sz = sizeof(dptp);
bf_pkt *bfdptppkt = NULL;

bf_pkt_tx_ring_t tx_ring = BF_PKT_TX_RING_0;
int switchid = 0;

/* Increment the era_hi register, upon timestamp wrap */
void increment_era() {
	int dev_id = 0;
	int count =2;
	uint32_t era_hi[count];
	p4_pd_dev_target_t p4_dev_tgt = {dev_id, (uint16_t)PD_DEV_PIPE_ALL};
	p4_pd_status_t status = 0;

	printf("****** Incrementing Era ******\n");
	status = p4_pd_begin_txn(sess_hdl, true);
	if (status != 0) {
		printf("Failed to begin transaction err=%d\n", status);
		return;
	}
	printf("era_hi[0] = %X (%d)", era_hi[0], count);
	era_hi[0] = era_hi[0] + 65536;
	printf("Incrementing era_hi to %X\n", era_hi[0]);
	status = p4_pd_complete_operations(sess_hdl);
	(void)p4_pd_commit_txn(sess_hdl, true);
	printf("***** Done ****\n");
}

/* Monitor global_ts, and check for wrap over */
void *monitor_global_ts(void *args) {
	bf_status_t status;
	uint64_t global_ts_ns_old;
	uint64_t global_ts_ns_new;
	uint64_t baresync_ts_ns;

	while (1) {
	 	status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_old, &baresync_ts_ns);
	 	sleep(2);
	 	status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_new, &baresync_ts_ns);

	 	if (global_ts_ns_new < global_ts_ns_old) {
	 		// Wrap Detected.
	 		increment_era();
	 	}
	 	sleep(2);
 	}
}

uint32_t max_ns = 1000000000;

void *monitor_timesynctopo_64(void *args) {

  // Logic go check logs dir. If absent, create one
  struct stat st = {0};

  if (stat("./logs", &st) == -1) {
          mkdir("./logs", 0755);
  }

  FILE *fc_s1m = fopen("logs/dptp_s1m.log", "w");
  FILE *fd = fopen("logs/dptp_measurement.log", "w");
  fprintf(fd, "reqMacDelay, replyQueing, respTxDelay, dpTxDelay, undpTxDelay, respWireDelay, respMacDelay, latency\n");
  // struct timespec tsp;
  // tsp.tv_sec = 0;
  // tsp.tv_nsec = 500000;

	int count = 2;
	uint32_t cp_flag[count];
	uint32_t s2s_reference_hi[count], s2s_reference_lo[count];
	uint32_t reference_hi_master[count], reference_lo_master[count];
	uint32_t reference_hi_s3[count], reference_lo_s3[count];
	uint32_t reference_hi_s4[count], reference_lo_s4[count];
  uint32_t reference_hi_s6[count], reference_lo_s6[count];
	uint32_t reference_hi_s1[count], reference_lo_s1[count];
	uint32_t reference_hi_s2[count], reference_lo_s2[count];
	uint16_t s2s_elapsed_hi[count];
	uint32_t s2s_elapsed_lo[count];
	uint32_t s2s_upreqdelay[count];
	uint32_t s2s_reqegts_lo[count], s2s_reqigts_lo[count];
	uint16_t s2s_reqegts_hi[count], s2s_reqigts_hi[count];
	uint16_t s2s_macts_hi[count];
	uint32_t s2s_macts_lo[count];
	uint16_t s2s_egts_hi[count];
	uint32_t s2s_egts_lo[count];
  uint16_t s2s_updts_hi[count];
  uint32_t s2s_updts_lo[count];
	uint32_t reference_hi[count], reference_lo[count];
	uint16_t now_igts_hi[count];
	uint32_t now_igts_lo[count];
	uint16_t now_macts_hi[count];
	uint32_t now_macts_lo[count];
	uint32_t offset_hi[count], offset_lo[count];
	uint32_t resp_qdepth[count], resp_qdelta[count];
  uint32_t capture_resp_tx[count];
  uint32_t reqDelayV[count];
	bf_dev_port_t reqport = 160;
	uint64_t capture_req_ts;
	uint64_t capture_resp_ts;
	bool ts_valid1, ts_valid2;
	int ts_id1, ts_id2;
  uint32_t test1[count], test2[count];
	p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
	cp_flag[0] = 0;
	int i=1; // pipe
	int e=0;
	int s1log = 1;
	while(1) {

		p4_pd_dptp_topo_register_read_timesyncs2s_cp_flag(sess_hdl, p4_dev_tgt, 0, REGISTER_READ_HW_SYNC, cp_flag, &count);
		if (cp_flag[i] == 0) {

			continue;
		}
    uint64_t global_ts_ns_bef, global_ts_ns_aft, baresync_ts_ns;
    bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_bef, &baresync_ts_ns);

		switch(cp_flag[i]) {
			case 1: // Switch 1
				reqport = 160; // Tofino1
				break;
      default:
        printf("Unexpected Case!\n");
        return NULL;
		}
		int switch_id = cp_flag[i];
		bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, reqport, &capture_req_ts, &ts_valid1, &ts_id1);
    //nanosleep(&tsp, NULL); // Hack to address the bug

		printf("======================Reply Received on Switch(%d)=========================\n", switch_id);
		// Below are for calculated timestamp
    // T_Now from master
		p4_pd_dptp_topo_register_read_timesyncs2s_reference_hi(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_reference_hi, &count);
		p4_pd_dptp_topo_register_read_timesyncs2s_reference_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_reference_lo, &count);
    // Request Received Mac Timestamp from master
    p4_pd_dptp_topo_register_read_timesyncs2s_macts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_macts_lo, &count);
    // Ingress Timestamp from master
		p4_pd_dptp_topo_register_read_timesyncs2s_elapsed_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_elapsed_lo, &count);
    // Egress Timestamp from master
		p4_pd_dptp_topo_register_read_timesyncs2s_egts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_egts_lo, &count);
    // Update Delay Tx from Master (Data plane)
    p4_pd_dptp_topo_register_read_timesyncs2s_updts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_updts_lo, &count);
    // Port Tx Timestamp from Master via Follow up
    p4_pd_dptp_topo_register_read_timesyncs2s_capture_tx(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, capture_resp_tx, &count);
    // Response Received Mac Timestamp at Switch1
		p4_pd_dptp_topo_register_read_timesyncs2s_now_macts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, now_macts_lo, &count);
    // Ingress Timestamp at Switch1
		p4_pd_dptp_topo_register_read_timesyncs2s_igts_hi(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, now_igts_hi, &count);
		p4_pd_dptp_topo_register_read_timesyncs2s_igts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, now_igts_lo, &count);

		uint64_t s2s_elapsed = 0;

		uint64_t now_igts = 0;
		now_igts = ((now_igts | now_igts_hi[i]) << 32) | now_igts_lo[i];
    uint64_t reference_ts = 0;
    reference_ts = ((reference_ts | s2s_reference_hi[i]) << 32) | s2s_reference_lo[i];
    uint32_t s2s_reference_hi_r = reference_ts / max_ns;
    uint32_t s2s_reference_lo_r = reference_ts % max_ns;
    uint32_t test_ref_elapsed_hi = s2s_reference_hi[i] + s2s_elapsed_hi[i];
    uint32_t test_ref_elapsed_lo = s2s_reference_lo[i] + s2s_elapsed_lo[i];

    capture_req_ts = capture_req_ts & 0xFFFFFFFF;
    capture_resp_ts = capture_resp_tx[i];

		int ReqMacDelay = s2s_elapsed_lo[i] - s2s_macts_lo[i];
		int replyQueing = s2s_egts_lo[i] - s2s_elapsed_lo[i];
		int respmacdelay = now_igts_lo[i] - now_macts_lo[i];
		int reqDelay =  capture_req_ts - s2s_reqigts_lo[i];
    printf("capture_req_ts = %u\n", capture_req_ts);
    printf("capture_resp_ts = %u\n", capture_resp_ts);
		int respDelay = capture_resp_ts - s2s_elapsed_lo[i];
    int respTxDelay = capture_resp_ts - s2s_egts_lo[i];
    int dpTxDelay = s2s_updts_lo[i] - s2s_egts_lo[i];
    int undpTxDelay = respTxDelay - dpTxDelay;
		int latency_ig = now_igts_lo[i] - s2s_reqigts_lo[i];
    int latency_tx = now_macts_lo[i] - capture_req_ts;
    int reqWireDelay = s2s_macts_lo[i] - capture_req_ts;
    int respWireDelay = now_macts_lo[i] - capture_resp_ts;
    //int respD = (latency_ig - ReqMacDelay - reqDelay - respDelay - respmacdelay)/2 + respDelay + respmacdelay;
    int respD_opt = (latency_tx - ReqMacDelay - respDelay)/2 + respDelay + respmacdelay;
    printf("respD_opt=%d\n", respD_opt);
    uint32_t calc_time_hi_dptp = s2s_reference_hi_r  + (respD_opt / max_ns);
		uint32_t calc_time_lo_dptp = s2s_reference_lo_r  + (respD_opt % max_ns);

    if (calc_time_lo_dptp >= max_ns) {
      //printf("calc_time_lo Wrapup!\n");
      calc_time_lo_dptp -= max_ns;
      calc_time_hi_dptp += 1;
    }
		// Below are for ground-truth timestamp
		p4_pd_dptp_topo_register_read_ts_hi(sess_hdl, p4_dev_tgt, 0, REGISTER_READ_HW_SYNC, reference_hi_master, &count);
		p4_pd_dptp_topo_register_read_ts_lo(sess_hdl, p4_dev_tgt, 0, REGISTER_READ_HW_SYNC, reference_lo_master, &count);

    uint64_t reference_ts_master = 0;
    reference_ts_master = ((reference_ts_master | reference_hi_master[i]) << 32) | reference_lo_master[i];
    uint32_t reference_hi_master_r = reference_ts_master / max_ns;
    uint32_t reference_lo_master_r = reference_ts_master % max_ns;
    printf("Reference_hi = %u, Reference_lo=%u\n", s2s_reference_hi[i], s2s_reference_lo[i]);
    printf("now_macts_lo=%u\n", now_macts_lo);
    printf("now_igts_hi=%u, now_igts_lo=%u\n", now_igts_hi[1], now_igts_lo[1]);
    printf("reference_ts_master = %lu\n", reference_ts_master);
    printf("reference_ts = %lu\n", reference_ts);
    uint32_t my_elp_hi = now_igts / max_ns;
		uint32_t my_elp_lo = now_igts % max_ns;
    printf("my_elp_hi=%u, my_elp_lo=%u\n",my_elp_hi, my_elp_lo);
    printf("global_ts_ns= %lu\n", global_ts_ns_bef);
		uint32_t orig_time_hi = reference_hi_master_r + my_elp_hi;
		uint32_t orig_time_lo = reference_lo_master_r + my_elp_lo;
    if (orig_time_lo >= max_ns) {
      //printf("orig_time_lo Wrapup!\n");
      orig_time_lo -= max_ns;
      orig_time_hi += 1;
    }

		cp_flag[0] = 0;
		cp_flag[1] = 0;

		uint32_t ref_calc_time_hi  = calc_time_hi_dptp - my_elp_hi;
    uint32_t ref_calc_time_lo;
    if (calc_time_lo_dptp < my_elp_lo) {
      //printf("ref_calc_time_lo wrapup!\n");
      ref_calc_time_lo = (calc_time_lo_dptp + max_ns) - my_elp_lo;
      ref_calc_time_hi -= 1;
    } else {
      ref_calc_time_lo  = calc_time_lo_dptp - my_elp_lo;
    }

    reference_ts = ((uint64_t)ref_calc_time_hi * (uint64_t)max_ns) + ref_calc_time_lo;
    ref_calc_time_hi = (reference_ts >> 32) & 0xFFFFFFFF;
    ref_calc_time_lo = reference_ts & 0xFFFFFFFF;

    p4_pd_dptp_topo_register_write_ts_hi(sess_hdl, p4_dev_tgt, switch_id, &ref_calc_time_hi);
		p4_pd_dptp_topo_register_write_ts_lo(sess_hdl, p4_dev_tgt, switch_id, &ref_calc_time_lo);
		p4_pd_dptp_topo_register_write_timesyncs2s_cp_flag(sess_hdl, p4_dev_tgt, 0, cp_flag);
		p4_pd_complete_operations(sess_hdl);
		(void)p4_pd_commit_txn(sess_hdl, true);
    printf("-------------------------------------------------\n");
    printf("                     Switch %d             \n", switch_id);
    printf("-------------------------------------------------\n");
    printf("Request Wire Delay                = %d ns\n", reqWireDelay);
    printf("Reply Mac Delay                   = %d ns\n", ReqMacDelay);
    printf("Reply Queing                      = %d ns\n", replyQueing);
    printf("Reply Egress Tx Delay             = %d ns\n", respTxDelay);
    printf("Reply Dataplane Tx Delay          = %d ns\n", dpTxDelay);
    printf("Unaccounted Dataplane Tx Delay    = %d ns\n", undpTxDelay);
    printf("Response Wire Delay               = %d ns\n", respWireDelay);
    printf("Response Mac Delay                = %d ns\n", respmacdelay);
    printf("Total RTT (RespRx - ReqTx)        = %d ns\n", latency_tx);
    printf("-------------------------------------------------\n");

		//printf("Switchid=%d\n", switch_id);
		if (switch_id == 1) {
      printf("calc_time_hi(Ground Truth) = %u s, calc_time_lo(Ground Truth) = %u ns\n", orig_time_hi, orig_time_lo);
      printf("calc_time_hi(DPTP)         = %u s, calc_time_lo(DPTP)         = %u ns\n", calc_time_hi_dptp, calc_time_lo_dptp);
      printf("-------------------------------------------------\n");
      printf("Error in Synchronization   = %d ns\n", calc_time_lo_dptp - orig_time_lo);
      printf("-------------------------------------------------\n");
      fprintf(fc_s1m,"%d, %d\n", s1log, calc_time_lo_dptp - orig_time_lo);
      fprintf(fd, "%d, %d, %d, %d, %d, %d, %d, %d, %d\n", reqWireDelay,
       ReqMacDelay, replyQueing, respTxDelay, dpTxDelay,undpTxDelay, respWireDelay, respmacdelay, latency_tx);
			fflush(fc_s1m);
      fflush(fd);
      s1log++;
		}
	}
	fclose(fc_s1m);
  fclose(fd);
}

FILE *fp;
void send_bf_followup_packet(uint8_t *dstAddr, uint32_t capture_tx) {
	memcpy(dptp_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
	dptp_pkt.reference_ts_hi = htonl(capture_tx);
  memcpy(upkt, &dptp_pkt, sz);
  if (bf_pkt_data_copy(bfpkt, upkt, sz) != 0) {
    printf("Failed data copy\n");
  }
  bf_status_t stat = bf_pkt_tx(0, bfpkt, tx_ring, (void *)bfpkt);
  if (stat  != BF_SUCCESS) {
    printf("Failed to send packet status=%s\n", bf_err_str(stat));
  } else {
    printf("Packet sent successfully capture_tx=%x\n", htonl(capture_tx));
  }
}

void* send_dptp_requests(void *args) {
  int i=0;
  sleep(3); // Initial packets are lost somehow.
  while (1) {
    printf("Sending DPTP Packets Out..\n");
    bf_status_t stat = bf_pkt_tx(0, bfdptppkt, tx_ring, (void *)bfdptppkt);
    if (stat  != BF_SUCCESS) {
      printf("Failed to send packet status=%s\n", bf_err_str(stat));
    }
    usleep(1000000);
    i++;
  }
}


/* Handle digests for DPTP requests and sends a follow-up
   packet after reading the Tx timestamp from port.*/
p4_pd_dptp_topo_timesync_inform_cp_digest_digest_notify_cb
  handle_timesync_inform_digest(p4_pd_sess_hdl_t sess_hdl,
        p4_pd_dptp_topo_timesync_inform_cp_digest_digest_msg_t *msg,
        void *callback_fn_cookie) {
  int i=0;
  int j=0;
	uint64_t capture_ts;
  uint32_t capture_ts_32;
	bool ts_valid;
	int ts_id;
  uint16_t num_entries = msg->num_entries;
  p4_pd_dptp_topo_timesync_inform_cp_digest_digest_entry_t digest;

	for (i=0;i< num_entries;i++) {
		uint16_t clientport = msg->entries[i].mdata_egress_port;
    printf("Got Digest to read for port %d\n", clientport);
		ts_valid = 0;
		int j = 1;
		while (ts_valid == 0) {
			bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, clientport, &capture_ts, &ts_valid, &ts_id);
			capture_ts_32 = capture_ts & 0xFFFFFFFF;
			j++;
 		}
    printf("Sending followup packet\n");
		send_bf_followup_packet(msg->entries[i].ethernet_dstAddr, capture_ts_32);
	}
	p4_pd_dptp_topo_timesync_inform_cp_digest_notify_ack(sess_hdl, msg);
}

/* Sets the global 64-bit Reference Time of master.
   The reference is stored in reference_ts_lo[0] and reference_ts_hi[0]
   Currently uses the CPU clock time as global Time */
void store_snapshot_64(uint32_t ts_sec, uint32_t ts_nsec, uint64_t global_ts_ns_bef) {
	p4_pd_status_t status;
	uint64_t global_ts_ns_aft, baresync_ts_ns;
	p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
  int max_ns = 1000000000;
	uint64_t max_ns_32 = 4294967296;
  uint64_t reference_ts = 0;
	uint64_t global_ts_ns;
  uint64_t time_r = 0;
  uint32_t ts_sec_r;
  reference_ts = ((uint64_t)ts_sec * (uint64_t)max_ns) + ts_nsec;
  uint32_t ts_nsec_r;
	printf("****** Reset Global Offset ******\n");
	status = p4_pd_begin_txn(sess_hdl, true);
	if (status != 0) {
		printf("Failed to begin transaction err=%d\n", status);
		return;
	}
	bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_aft, &baresync_ts_ns);
	printf("Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);
  ts_sec = (reference_ts >> 32) & 0xFFFFFFFF;
  ts_nsec = reference_ts & 0xFFFFFFFF;

  printf("Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);
	uint32_t offset_t_lo = (uint32_t)global_ts_ns_aft & (uint32_t)0xFFFFFFFF;
	uint32_t offset_t_hi = (global_ts_ns_aft >> 32) & (uint32_t)0xFFFFFFFF;
  ts_sec  -= offset_t_hi;
  if (ts_nsec < offset_t_lo) {
    uint64_t ts_nsec_big = (uint64_t)ts_nsec + (uint64_t)max_ns_32;
    ts_nsec = (uint32_t)(ts_nsec_big - (uint64_t)offset_t_lo);
    ts_sec -= 1;
  } else {
    ts_nsec  = ts_nsec - offset_t_lo;
  }
  p4_pd_dptp_topo_register_write_ts_hi(sess_hdl, p4_dev_tgt, 0, &ts_sec);
  p4_pd_dptp_topo_register_write_ts_lo(sess_hdl, p4_dev_tgt, 0, &ts_nsec);

	status = p4_pd_complete_operations(sess_hdl);
	(void)p4_pd_commit_txn(sess_hdl, true);
  printf("Setting Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);
  time_r = ((time_r | ts_sec) << 32) | ts_nsec;
	printf("***** Done ****\n");
}

void snapshot_reference() {
	struct timespec tsp;
	bf_status_t status;
	uint64_t global_ts_ns_bef, baresync_ts_ns;
	status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_bef, &baresync_ts_ns);
	if (status != 0) {
		printf("Failed to get global ts.\n");
		return;
	}
	clock_gettime(CLOCK_REALTIME, &tsp);   //Call clock_gettime to fill tsp
	store_snapshot_64((uint32_t)tsp.tv_sec, (uint32_t)tsp.tv_nsec, global_ts_ns_bef);
}

void init_bf_switchd() {
  bf_switchd_context_t *switchd_main_ctx = NULL;
  char *install_dir;
  char target_conf_file[100];
  int ret;
	p4_pd_status_t status;
  install_dir = getenv("SDE_INSTALL");
  sprintf(target_conf_file, "%s/share/p4/targets/tofino/dptp_topo.conf", install_dir);

  /* Allocate memory to hold switchd configuration and state */
  if ((switchd_main_ctx = malloc(sizeof(bf_switchd_context_t))) == NULL) {
    printf("ERROR: Failed to allocate memory for switchd context\n");
    return;
  }

  memset(switchd_main_ctx, 0, sizeof(bf_switchd_context_t));
  switchd_main_ctx->install_dir = install_dir;
  switchd_main_ctx->conf_file = target_conf_file;
  switchd_main_ctx->skip_p4 = false;
  switchd_main_ctx->skip_port_add = false;
  switchd_main_ctx->running_in_background = true;
  switchd_main_ctx->dev_sts_port = THRIFT_PORT_NUM;
  switchd_main_ctx->dev_sts_thread = true;

  ret = bf_switchd_lib_init(switchd_main_ctx);
  printf("Initialized bf_switchd, ret = %d\n", ret);

	status = p4_pd_client_init(&sess_hdl);
	if (status == 0) {
		printf("Successfully performed client initialization.\n");
	} else {
		printf("Failed in Client init\n");
	}
}

void init_tables() {
  if (switchid == 1) {
    system("bfshell -f commands-newtopo-tofino1.txt");
    printf("DONE adding commands!\n");
  } else if (switchid == 2) {
    system("bfshell -f commands-newtopo-tofino2.txt");
  }
}


static bf_status_t switch_pktdriver_tx_complete(bf_dev_id_t device,
                                                bf_pkt_tx_ring_t tx_ring,
                                                uint64_t tx_cookie,
                                                uint32_t status) {

  //bf_pkt *pkt = (bf_pkt *)(uintptr_t)tx_cookie;
  //bf_pkt_free(device, pkt);
  return 0;
}

void switch_pktdriver_callback_register(bf_dev_id_t device) {

  bf_pkt_tx_ring_t tx_ring;
  bf_pkt_rx_ring_t rx_ring;

  /* register callback for TX complete */
  for (tx_ring = BF_PKT_TX_RING_0; tx_ring < BF_PKT_TX_RING_MAX; tx_ring++) {
    bf_pkt_tx_done_notif_register(
        device, switch_pktdriver_tx_complete, tx_ring);
  }
}

// Custom MAC address defined for switches
uint8_t switch1[] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x01};
uint8_t  master[] = {0xa0, 0x00, 0x00, 0x10, 0x00, 0x0a};

void dptp_requestpkt_init() {
  int i=0;
  int cookie;
  if (bf_pkt_alloc(0, &bfdptppkt, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }

  memcpy(dptp_request_pkt.dstAddr, master, 6);
  memcpy(dptp_request_pkt.srcAddr, switch1, 6);
  dptp_request_pkt.type = htons(0x88f7);
  dptp_request_pkt.magic = htons(0x0002);
  dptp_request_pkt.command = DPTP_GEN_REQ;
  dreqpkt = (uint8_t *) malloc(dptp_sz);
  memcpy(dreqpkt, &dptp_request_pkt, dptp_sz);
  if (bf_pkt_is_inited(0)) {
    printf("DPTP Request Packet is initialized\n");
  }
  if (bf_pkt_data_copy(bfdptppkt, dreqpkt, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
}

void dptp_followuppkt_init() {
  int i=0;
  int cookie;
  if (bf_pkt_alloc(0, &bfpkt, sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }

  uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
  uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
  memcpy(dptp_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  memcpy(dptp_pkt.srcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  dptp_pkt.type = htons(0x88f7);
  dptp_pkt.magic = htons(0x0002);
  dptp_pkt.command = DPTP_CAPTURE_COMMAND;

  upkt = (uint8_t *) malloc(sz);
  memcpy(upkt, &dptp_pkt, sz);

  if (bf_pkt_is_inited(0)) {
    printf("bf_pkt is initialized\n");
  }

  if (bf_pkt_data_copy(bfpkt, upkt, sz) != 0) {
    printf("Failed data copy\n");
  }
  //bf_pkt_set_pkt_data(bfpkt, upkt);
  printf("Packet init");
  for (i=0;i<sz;i++) {
    printf("%X ",bfpkt[i]);
  }
  printf("\n");
}

#define MAX_LINKS 512
void lpf_init () {
  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
  p4_pd_lpf_spec_t lpf_spec;

  p4_pd_status_t status ;
  int i=0;
  lpf_spec.gain_decay_separate_time_constant = false;
  lpf_spec.time_constant = 1000000000; //1 s
  lpf_spec.output_scale_down_factor = 0;
  lpf_spec.lpf_type = PD_LPF_TYPE_RATE;// This calculates the aggreagate

  for (i=0;i<MAX_LINKS;i++) {
    status = p4_pd_dptp_topo_lpf_set_current_utilization_bps(sess_hdl, p4_dev_tgt, i, &lpf_spec);
  }
  printf ("Set lpf status = %d\n", status);
}

void register_learn () {
	p4_pd_status_t status = 0;
	void *cb_fun_cookie = NULL;
  status = p4_pd_dptp_topo_timesync_inform_cp_digest_register(sess_hdl, (uint8_t)0,
         (p4_pd_dptp_topo_timesync_inform_cp_digest_digest_notify_cb)handle_timesync_inform_digest,
         cb_fun_cookie);
  if (status != 0) {
    printf("Error registering learning module, err =%d\n", status);
  }

  fp = fopen("timesync-learn.log","w");
  p4_pd_dptp_topo_set_learning_timeout(sess_hdl, (uint8_t)0, 0);
}

void getSwitchName () {
  char switchName[25];
  FILE *f = fopen("/etc/hostname","r");
  fscanf(f, "%s", switchName);
  if (strcmp(switchName, "tofino1") == 0) {
    switchid = 1;
  } else if (strcmp(switchName, "tofino2") == 0) {
    switchid = 2;
  }
  printf("Detected running on Tofino%d\n", switchid);
}


int main (int argc, char **argv) {
	init_bf_switchd();
  getSwitchName();
	init_tables();
	pthread_t era_thread;
	pthread_t timesyncs2s_thread;
  pthread_t dptp_thread;

	printf("Starting dptp_topo Control Plane Unit ..\n");

	// Thread to monitor the Global Timestamp for wrap over, and increment Era
	pthread_create(&era_thread, NULL, monitor_global_ts, NULL);
  // Thread to report the current time and report accuracy
	pthread_create(&timesyncs2s_thread, NULL, monitor_timesynctopo_64, NULL);

	switch_pktdriver_callback_register(0);
  dptp_requestpkt_init();
  dptp_followuppkt_init();
  lpf_init();

	register_learn();
	snapshot_reference();
  // Thread to send out regular DPTP requests from SWITCH1 to MASTER
  pthread_create(&dptp_thread, NULL, send_dptp_requests, NULL);

	// Hope this never hits. Wait indefinitely for threads to finish.
	pthread_join(era_thread, NULL);
	return 0;
}
