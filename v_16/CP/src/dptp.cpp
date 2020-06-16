#include "dptp.hpp"

using namespace dptp;

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
  } dptp_p;

  dptp_p dptp_pkt;
  uint8_t *pkt;

  // DPTP Followup
  dptp_p dptp_followup_pkt;
  uint8_t *upkt;
  size_t sz = sizeof(dptp_p);
  bf_pkt *bfpkt;

  // DPTP Request
  dptp_p dptp_request_pkt;
  uint8_t *dreqpkt;
  size_t dptp_sz = sizeof(dptp_p);
  bf_pkt *bfDptpPkt = NULL;

  bf_pkt_tx_ring_t tx_ring = BF_PKT_TX_RING_0;

  const bfrt::BfRtInfo *bfrtInfo   = nullptr;
  const bfrt::BfRtLearn *bfrtLearnFollowup = nullptr;
  const bfrt::BfRtLearn *bfrtLearnReply    = nullptr;
  const bfrt::BfRtLearn *bfrtLearnReplyFop = nullptr;

  std::shared_ptr<bfrt::BfRtSession> session;
  bf_status_t bf_status;

  bf_rt_target_t dev_tgt;

  auto hwflag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW;

  // Threads
  pthread_t era_thread;
	pthread_t timesyncs2s_thread;
  pthread_t dptp_thread;

  // Learn Followup Digest fields
  bf_rt_id_t learn_egress_port = 0; 
  bf_rt_id_t learn_mac_addr = 0;
  bf_rt_id_t learn_timestamp = 0;

  // Learn Reply Digest fields
  bf_rt_id_t learn_rswitch_id = 0;
  bf_rt_id_t learn_reference_ts_hi = 0; 
  bf_rt_id_t learn_reference_ts_lo = 0;
  bf_rt_id_t learn_elapsed_hi = 0;
  bf_rt_id_t learn_elapsed_lo = 0;
  bf_rt_id_t learn_macts_lo = 0;
  bf_rt_id_t learn_egts_lo = 0;
  bf_rt_id_t learn_tx_updts_lo = 0;
  bf_rt_id_t learn_now_macts_lo = 0;
  bf_rt_id_t learn_now_igts_hi = 0;
  bf_rt_id_t learn_now_igts_lo = 0;

  // Learn Reply Followup Digest fields
  bf_rt_id_t learn_rfswitch_id = 0; 
  bf_rt_id_t learn_tx_capturets_lo = 0; 


  // Registers
  // ts_hi
  const bfrt::BfRtTable *reg_ts_hi;
  bf_rt_id_t reg_ts_hi_index;
  bf_rt_id_t reg_ts_hi_f1;
  std::unique_ptr<bfrt::BfRtTableKey> reg_ts_hi_key;
  std::unique_ptr<bfrt::BfRtTableData> reg_ts_hi_data;
  // ts_lo
  const bfrt::BfRtTable *reg_ts_lo;
  bf_rt_id_t reg_ts_lo_index;
  bf_rt_id_t reg_ts_lo_f1;
  std::unique_ptr<bfrt::BfRtTableKey> reg_ts_lo_key;
  std::unique_ptr<bfrt::BfRtTableData> reg_ts_lo_data;

  // Custom MAC address defined for switches
  uint8_t switch1[] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x01};
  uint8_t  master[] = {0xa0, 0x00, 0x00, 0x10, 0x00, 0x0a};

  uint64_t s2s_reference_hi[MAX_SWITCHES];
  uint64_t s2s_reference_lo[MAX_SWITCHES];
  uint64_t s2s_macts_lo[MAX_SWITCHES];
  uint64_t s2s_elapsed_hi[MAX_SWITCHES];
  uint64_t s2s_elapsed_lo[MAX_SWITCHES];
  uint64_t s2s_egts_lo[MAX_SWITCHES];
  uint64_t now_macts_lo[MAX_SWITCHES];
  uint64_t now_igts_hi[MAX_SWITCHES];
  uint64_t now_igts_lo[MAX_SWITCHES];
  uint64_t capture_req_tx[MAX_SWITCHES];
  uint64_t capture_resp_tx[MAX_SWITCHES];

  uint32_t s2s_reference_hi_d[MAX_SWITCHES];
  uint32_t s2s_reference_lo_d[MAX_SWITCHES];
  uint32_t now_igts_hi_d[MAX_SWITCHES];
  uint32_t now_igts_lo_d[MAX_SWITCHES];
  
  uint32_t max_ns = 1000000000;

  bf_status_t dptp::setUp(void) {
    dev_tgt.dev_id = 0;
    dev_tgt.pipe_id = ALL_PIPES;
    // Get devMgr singleton instance
    auto &devMgr = bfrt::BfRtDevMgr::getInstance();
    // Get bfrtInfo object from dev_id and p4 program name
    auto bf_status = devMgr.bfRtInfoGet(dev_tgt.dev_id, "dptp_v16", &bfrtInfo);
    // Create a session object
    session = bfrt::BfRtSession::sessionCreate();
    printf("DPTP bfrt Setup!\n");
    return bf_status;
  }

  bf_status_t dptp::initRegisterAPI(void) {
    // ts_hi register
    bf_status = bfrtInfo->bfrtTableFromNameGet("ts_hi", &reg_ts_hi);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_hi->keyFieldIdGet("$REGISTER_INDEX", &reg_ts_hi_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_hi->dataFieldIdGet("ts_hi.f1", &reg_ts_hi_f1);
    assert(bf_status == BF_SUCCESS);

    bf_status = reg_ts_hi->keyAllocate(&reg_ts_hi_key);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_hi->dataAllocate(&reg_ts_hi_data);
    assert(bf_status == BF_SUCCESS);

    bf_status = reg_ts_hi_key->setValue(reg_ts_hi_index, 0);
    assert(bf_status == BF_SUCCESS);

    // ts_lo register
    bf_status = bfrtInfo->bfrtTableFromNameGet("ts_lo", &reg_ts_lo);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_lo->keyFieldIdGet("$REGISTER_INDEX", &reg_ts_lo_index);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_lo->dataFieldIdGet("ts_lo.f1", &reg_ts_lo_f1);
    assert(bf_status == BF_SUCCESS);

    bf_status = reg_ts_lo->keyAllocate(&reg_ts_lo_key);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_lo->dataAllocate(&reg_ts_lo_data);
    assert(bf_status == BF_SUCCESS);

    bf_status = reg_ts_lo_key->setValue(reg_ts_lo_index, 0);
    assert(bf_status == BF_SUCCESS);
    printf("Initialized register APIs\n");
    return BF_SUCCESS;
  }

  bf_status_t dptp::writeReferenceTs (const uint64_t ts_hi, const uint64_t ts_lo, uint64_t switch_id) {
    bf_status = reg_ts_hi_key->setValue(reg_ts_hi_index, switch_id);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_hi_data->setValue(reg_ts_hi_f1, ts_hi);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_lo_key->setValue(reg_ts_lo_index, switch_id);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_lo_data->setValue(reg_ts_lo_f1, ts_lo);
    assert(bf_status == BF_SUCCESS);

    bf_status = session->beginTransaction(false);

    bf_status = reg_ts_hi->tableEntryMod(*session, dev_tgt, *reg_ts_hi_key, *reg_ts_hi_data);
    assert(bf_status == BF_SUCCESS);
    bf_status = reg_ts_lo->tableEntryMod(*session, dev_tgt, *reg_ts_lo_key, *reg_ts_lo_data);
    assert(bf_status == BF_SUCCESS);

    bf_status = session->verifyTransaction();
    bf_status = session->sessionCompleteOperations();
    bf_status = session->commitTransaction(true);
    return BF_SUCCESS;
  }


  /* Sets the global 64-bit Reference Time of master.
     The reference is stored in reference_ts_lo[0] and reference_ts_hi[0]
     Currently uses the CPU clock time as global Time 
   */ 
  bf_status_t dptp::initReferenceTs (void) {
    struct timespec tsp;
    int max_ns = 1000000000;
    uint64_t max_ns_32 = 4294967296;
    uint64_t reference_ts = 0;
    uint64_t time_r = 0;
    uint64_t global_ts_ns, baresync_ts_ns;
    uint32_t ts_sec, ts_nsec;

    // External Clock Reference from CPU
    clock_gettime(CLOCK_REALTIME, &tsp);
    
    reference_ts = ((uint64_t)tsp.tv_sec * (uint64_t)max_ns) + tsp.tv_nsec;
    
    bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns, &baresync_ts_ns);
    printf("Time tv_sec = %u, tv_nsec = %u\n", tsp.tv_sec, tsp.tv_nsec);
    ts_sec = (reference_ts >> 32) & 0xFFFFFFFF;
    ts_nsec = reference_ts & 0xFFFFFFFF;

    // Correct the offset
    printf("Time ts_sec = %u, ts_nsec = %u\n", ts_sec, ts_nsec);
    uint32_t offset_t_lo = (uint32_t)global_ts_ns & (uint32_t)0xFFFFFFFF;
    uint32_t offset_t_hi = (global_ts_ns >> 32) & (uint32_t)0xFFFFFFFF;
    ts_sec  -= offset_t_hi;
    if (ts_nsec < offset_t_lo) {
      uint64_t ts_nsec_big = (uint64_t)ts_nsec + (uint64_t)max_ns_32;
      ts_nsec = (uint32_t)(ts_nsec_big - (uint64_t)offset_t_lo);
      ts_sec -= 1;
    } else {
      ts_nsec  = ts_nsec - offset_t_lo;
    }
    // Write the Registers
    writeReferenceTs((const uint64_t)ts_sec, (const uint64_t)ts_nsec, 0);

    // printf("Setting Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);
    // time_r = ((time_r | ts_sec) << 32) | ts_nsec;
    // printf("***** Done ****\n");
    return BF_SUCCESS;
  }

  bf_status_t dptp::incrementEra () {
    // ts_hi needs to incremented by 0x10000 (65536)
    return BF_SUCCESS;
  }
  /* Monitor global_ts, and check for wrap over for era maintenance */
  void* dptp::eraMaintenance (void *args) {
    bf_status_t status;
    uint64_t global_ts_ns_old;
    uint64_t global_ts_ns_new;
    uint64_t baresync_ts_ns;

    while (1) {
      status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_old, &baresync_ts_ns);
      status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_new, &baresync_ts_ns);
      //printf("%lu,%lu\n", global_ts_ns_old, global_ts_ns_new);
      if (global_ts_ns_new < global_ts_ns_old) {
        // Wrap Detected.
        incrementEra();
      }
      sleep(2);
    }
  }
  
  bf_status_t dptp::createEraThread (void) {
    // Thread to monitor the Global Timestamp for wrap over, and increment Era
    pthread_create(&era_thread, NULL, eraMaintenance, NULL);
    return BF_SUCCESS;
  }

  bf_status_t dptp::initReferenceTsAPI () {
    bf_status = reg_ts_hi->keyAllocate(&reg_ts_hi_key);
    bf_status = reg_ts_hi->dataAllocate(&reg_ts_hi_data);
    bf_status = reg_ts_lo->keyAllocate(&reg_ts_lo_key);
    bf_status = reg_ts_lo->dataAllocate(&reg_ts_lo_data);    
    assert(bf_status == BF_SUCCESS);
    return BF_SUCCESS;
  }

  bf_status_t dptp::readReferenceTs(uint32_t *ts_hi, uint32_t *ts_lo, uint8_t switch_id) {
    bf_status = reg_ts_hi_key->setValue(reg_ts_hi_index, (uint64_t)switch_id);
    bf_status = reg_ts_lo_key->setValue(reg_ts_lo_index, (uint64_t)switch_id);

    bf_status = reg_ts_hi->tableEntryGet(*session, dev_tgt, *(reg_ts_hi_key.get()), hwflag, reg_ts_hi_data.get());
    assert(bf_status == BF_SUCCESS);

    std::vector<uint64_t> ts_hi_val;
    bf_status = reg_ts_hi_data->getValue(reg_ts_hi_f1, &ts_hi_val);
    assert(bf_status == BF_SUCCESS);

    bf_status = reg_ts_lo->tableEntryGet(*session, dev_tgt, *(reg_ts_lo_key.get()), hwflag, reg_ts_lo_data.get());
    assert(bf_status == BF_SUCCESS);
    std::vector<uint64_t> ts_lo_val;
    bf_status = reg_ts_lo_data->getValue(reg_ts_lo_f1, &ts_lo_val);
    assert(bf_status == BF_SUCCESS);

    *ts_hi = (uint32_t)ts_hi_val[0];
    *ts_lo = (uint32_t)ts_lo_val[0];
    printf("ts_hi content: %u\n", *ts_hi);
    printf("ts_lo content: %u\n", *ts_lo);
    return BF_SUCCESS;
  }

  void* dptp::sendDptpRequests (void *args) {
    int i=0;
    sleep(3); // Initial packets are lost somehow.
    while (1) {
      printf("Sending DPTP Packets Out..\n");
      bf_status_t stat = bf_pkt_tx(0, bfDptpPkt, tx_ring, (void *)bfDptpPkt);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet status=%s\n", bf_err_str(stat));
      }
      usleep(1000000);
      i++;
    }
  }  


  void dptp::createDptpRequestThread (void) {
    pthread_create(&dptp_thread, NULL, sendDptpRequests, NULL);
  }

  void dptp::waitOnThreads (void) {
    pthread_join(era_thread, NULL);
  }

  bf_status_t dptp::initRequestPkt(void) {
    int i=0;
    int cookie;
    if (bf_pkt_alloc(0, &bfDptpPkt, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_1) != 0) {
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
    if (bf_pkt_data_copy(bfDptpPkt, dreqpkt, dptp_sz) != 0) {
      printf("Failed data copy\n");
    }
    // printf("Packet init");
    // for (i=0;i<sz;i++) {
    //   printf("%X ",bfDptpPkt[i]);
    // }
    // printf("\n");
  }

  bf_status_t dptp::initFollowupPkt(void) {
    int i=0;
    int cookie;
    if (bf_pkt_alloc(0, &bfpkt, sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
      printf("Failed bf_pkt_alloc\n");
    }

    uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
    uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
    memcpy(dptp_followup_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
    memcpy(dptp_followup_pkt.srcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
    dptp_followup_pkt.type = htons(0x88f7);
    dptp_followup_pkt.magic = htons(0x0002);
    dptp_followup_pkt.command = DPTP_CAPTURE_COMMAND;

    upkt = (uint8_t *) malloc(sz);
    memcpy(upkt, &dptp_followup_pkt, sz);

    if (bf_pkt_is_inited(0)) {
      printf("bf_pkt is initialized\n");
    }

    if (bf_pkt_data_copy(bfpkt, upkt, sz) != 0) {
      printf("Failed data copy\n");
    }
    //bf_pkt_set_pkt_data(bfpkt, upkt);

  }

  bf_status_t dptp::initPackets () {
    initRequestPkt();
    initFollowupPkt();
  }

  bf_status_t dptp::sendFollowupPacket(uint8_t *dstAddr, uint32_t tx_capture_tstamp_lo) {
    memcpy(dptp_followup_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
    dptp_followup_pkt.reference_ts_hi = htonl(tx_capture_tstamp_lo);
    memcpy(upkt, &dptp_followup_pkt, sz);
    if (bf_pkt_data_copy(bfpkt, upkt, sz) != 0) {
      printf("Failed data copy\n");
    }
    bf_status_t stat = bf_pkt_tx(0, bfpkt, tx_ring, (void *)bfpkt);
    if (stat  != BF_SUCCESS) {
      printf("Failed to send packet status=%s\n", bf_err_str(stat));
    } else {
      printf("Packet sent successfully capture_tx=%x\n", htonl(tx_capture_tstamp_lo));
    }
    return BF_SUCCESS;
  }

  bf_status_t followupDigestCallback(const bf_rt_target_t &bf_rt_tgt,
                            const std::shared_ptr<bfrt::BfRtSession> bfrtsession,
                            std::vector<std::unique_ptr<bfrt::BfRtLearnData>> vec,
                            bf_rt_learn_msg_hdl *const learn_msg_hdl,
                            const void *cookie) {

    uint64_t egress_port;
    uint64_t mac_addr;
    uint8_t dstAddr[6];
    int i= 0;
    int ts_id;
    bool ts_valid;
    uint64_t tx_capture_tstamp;
    uint32_t tx_capture_tstamp_lo;
    const size_t size = 6;

    for (;i<vec.size();i++) {
      vec[i].get()->getValue(learn_egress_port, &egress_port);          
      //vec[0].get()->getValue(learn_mac_addr, &mac_addr);
      vec[i].get()->getValue(learn_mac_addr, size, dstAddr);
      printf("Egress port = %u\n", egress_port);  
      printf("Mac Addr    = %X %X %X %X %X %X\n", dstAddr[0],dstAddr[1],dstAddr[2],dstAddr[3],dstAddr[4], dstAddr[5]);  
      ts_valid = 0;
		  int j = 1;
		  while (ts_valid == 0) {
			  bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, egress_port, &tx_capture_tstamp, &ts_valid, &ts_id);
			  tx_capture_tstamp_lo = tx_capture_tstamp & 0xFFFFFFFF;
			  j++;
 		  }
      sendFollowupPacket(dstAddr, tx_capture_tstamp_lo);
    }
    auto bf_status = bfrtLearnFollowup->bfRtLearnNotifyAck(bfrtsession, learn_msg_hdl);
    assert(bf_status == BF_SUCCESS);
    return BF_SUCCESS;
  }

  bf_status_t dptp::replyDigestCallback(const bf_rt_target_t &bf_rt_tgt,
                            const std::shared_ptr<bfrt::BfRtSession> bfrtsession,
                            std::vector<std::unique_ptr<bfrt::BfRtLearnData>> vec,
                            bf_rt_learn_msg_hdl *const learn_msg_hdl,
                            const void *cookie) {
    uint8_t switch_id = 0;
	bf_dev_port_t reqport = 160;
    int i= 0;
    int ts_id;
    bool ts_valid;

    for (;i<vec.size();i++) {
      vec[i].get()->getValue(learn_rswitch_id, 1, &switch_id);          
      printf("Reply received on switch %d\n", switch_id);
      if (switch_id > MAX_SWITCHES) {
        printf("Not expecting this switch-id, return!!\n");
        return BF_UNEXPECTED;
      }
      switch(switch_id) {
        case 1: // Switch 1
          reqport = 160; // Tofino1
          break;
        default:
          printf("Unexpected Case!\n");
          return BF_UNEXPECTED;
	  }
      bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, reqport, &capture_req_tx[switch_id], &ts_valid, &ts_id);
      vec[i].get()->getValue(learn_reference_ts_hi, &s2s_reference_hi[switch_id]);          
      vec[i].get()->getValue(learn_reference_ts_lo, &s2s_reference_lo[switch_id]);          
      vec[i].get()->getValue(learn_macts_lo, &s2s_macts_lo[switch_id]);   
      //vec[i].get()->getValue(learn_elapsed_hi, &s2s_elapsed_hi[switch_id]);  
      vec[i].get()->getValue(learn_elapsed_lo, &s2s_elapsed_lo[switch_id]);  
      vec[i].get()->getValue(learn_egts_lo, &s2s_egts_lo[switch_id]);   
      vec[i].get()->getValue(learn_now_macts_lo, &now_macts_lo[switch_id]);   
      vec[i].get()->getValue(learn_now_igts_hi, &now_igts_hi[switch_id]);   
      vec[i].get()->getValue(learn_now_igts_lo, &now_igts_lo[switch_id]);
      uint64_t reference_ts_c = 0;
      reference_ts_c = ((reference_ts_c | (uint32_t)s2s_reference_hi[switch_id]) << 32) | (uint32_t)s2s_reference_lo[switch_id];
      uint32_t a = reference_ts_c / max_ns;
      uint32_t b = reference_ts_c % max_ns;
      s2s_reference_hi_d[switch_id] = a;
      s2s_reference_lo_d[switch_id] = b;
  	  uint64_t now_igts_c = 0;
	  now_igts_c = ((now_igts_c | now_igts_hi[switch_id]) << 32) | now_igts_lo[switch_id];
      a = now_igts_c / max_ns;
      b = now_igts_c % max_ns;
      now_igts_hi_d[switch_id] = a;
      now_igts_lo_d[switch_id] = b;

      printf("Reference_hi   = %u, Reference_lo   =%u\n", s2s_reference_hi[switch_id], s2s_reference_lo[switch_id]);
      printf("Reference TS   = %lu\n", reference_ts_c);
      printf("Reference_hi_d = %u, Reference_lo_d =%u\n", s2s_reference_hi_d[switch_id], s2s_reference_lo_d[switch_id]);
      printf("capture_req_tx = %u\n", (capture_req_tx[switch_id] & 0xFFFFFFFF));
      printf("s2s_macts_lo   = %u\n", s2s_macts_lo[switch_id]);
      printf("s2s_elapsed_hi = %u, s2s_elapsed_lo = %u\n", s2s_elapsed_hi[switch_id], s2s_elapsed_lo[switch_id]);
      printf("s2s_egts_lo    = %u\n", s2s_egts_lo[switch_id]);
      printf("now_macts_lo   = %u\n", now_macts_lo[switch_id]); 
      printf("now_igts_lo    = %u\n", now_igts_lo[switch_id]); 
      printf("now_igts_hi_d  = %u, now_igts_lo_d = %u\n", now_igts_hi_d[switch_id], now_igts_lo_d[switch_id]); 

    }

    initReferenceTsAPI();

    auto bf_status = bfrtLearnReply->bfRtLearnNotifyAck(bfrtsession, learn_msg_hdl);
    assert(bf_status == BF_SUCCESS);
    return BF_SUCCESS;
  }



  bf_status_t dptp::writeCalcRefTs (uint32_t calc_time_hi_dptp, 
                       uint32_t calc_time_lo_dptp, 
                       uint32_t now_elapsed_hi, 
                       uint32_t now_elapsed_lo,
                       uint8_t switch_id) {
    uint64_t ref_calc_time_hi  = calc_time_hi_dptp - now_elapsed_hi;
    uint64_t ref_calc_time_lo;
    if (calc_time_lo_dptp < now_elapsed_lo) {
      ref_calc_time_lo = (calc_time_lo_dptp + max_ns) - now_elapsed_lo;
      ref_calc_time_hi -= 1;
    } else {
      ref_calc_time_lo  = calc_time_lo_dptp - now_elapsed_lo;
    }
    uint64_t reference_ts = ((uint64_t)ref_calc_time_hi * (uint64_t)max_ns) + ref_calc_time_lo;
    ref_calc_time_hi = (reference_ts >> 32) & 0xFFFFFFFF;
    ref_calc_time_lo = reference_ts & 0xFFFFFFFF;        
    writeReferenceTs(ref_calc_time_hi, ref_calc_time_lo, (uint64_t)switch_id);           
  }

  bf_status_t dptp::reportDptpError (uint32_t calc_time_hi, 
                        uint32_t calc_time_lo,                       
                        uint32_t now_elapsed_hi, 
                        uint32_t now_elapsed_lo, 
                        uint8_t master_switch) {

    uint32_t master_ts_hi, master_ts_lo;
    uint64_t reference_ts_master = 0;
    initReferenceTsAPI();
    readReferenceTs(&master_ts_hi, &master_ts_lo, master_switch);
    reference_ts_master = ((reference_ts_master | master_ts_hi) << 32) | master_ts_lo;
    uint32_t reference_hi_master_r = reference_ts_master / max_ns;
    uint32_t reference_lo_master_r = reference_ts_master % max_ns;

    printf("ref %u,%u\n", reference_hi_master_r, reference_lo_master_r);
  	uint32_t master_now_hi = reference_hi_master_r + now_elapsed_hi;
		uint32_t master_now_lo = reference_lo_master_r + now_elapsed_lo;
    if (master_now_lo >= max_ns) {
      //printf("orig_time_lo Wrapup!\n");
      master_now_lo -= max_ns;
      master_now_hi += 1;
    }
    printf("calc_time_hi(Ground Truth) = %u s, calc_time_lo(Ground Truth) = %u ns\n", master_now_hi, master_now_lo);
    printf("calc_time_hi(DPTP)         = %u s, calc_time_lo(DPTP)         = %u ns\n", calc_time_hi, calc_time_lo);
    printf("-------------------------------------------------\n");
    printf("Error in Synchronization   = %d ns\n", calc_time_lo - master_now_lo);
    printf("-------------------------------------------------\n");
  }

  bf_status_t dptp::replyFollowupDigestCallback(const bf_rt_target_t &bf_rt_tgt,
                            const std::shared_ptr<bfrt::BfRtSession> bfrtsession,
                            std::vector<std::unique_ptr<bfrt::BfRtLearnData>> vec,
                            bf_rt_learn_msg_hdl *const learn_msg_hdl,
                            const void *cookie) {
    uint8_t switch_id = 0;                          
    uint64_t egress_port;
    uint64_t mac_addr;
    uint8_t dstAddr[6];
    int i= 0;
    int ts_id;
    bool ts_valid;
    uint64_t tx_capture_tstamp;
    uint32_t tx_capture_tstamp_lo;
    const size_t size = 6;

    for (;i<vec.size();i++) {
      vec[i].get()->getValue(learn_rswitch_id, 1, &switch_id);          
      //printf("Reply Followup received on switch %d\n", switch_id);
      if (switch_id > MAX_SWITCHES) {
        printf("Not expecting this switch-id, return!!\n");
      }
      vec[i].get()->getValue(learn_tx_capturets_lo, &capture_resp_tx[switch_id]);      
      printf("capture_resp_tx= %u\n", capture_resp_tx[switch_id]);

      int reqWireDelay  = s2s_macts_lo[switch_id] - capture_req_tx[switch_id];
      int ReqMacDelay   = s2s_elapsed_lo[switch_id] - s2s_macts_lo[switch_id];
      int replyQueing   = s2s_egts_lo[switch_id] - s2s_elapsed_lo[switch_id];
      int respmacdelay  = now_igts_lo[switch_id] - now_macts_lo[switch_id];
      int respDelay     = capture_resp_tx[switch_id] - s2s_elapsed_lo[switch_id];
      int respTxDelay   = capture_resp_tx[switch_id] - s2s_egts_lo[switch_id];
      int latency_tx    = now_macts_lo[switch_id] - capture_req_tx[switch_id];
      int respWireDelay = now_macts_lo[switch_id] - capture_resp_tx[switch_id];
      int respTDelay = (latency_tx - ReqMacDelay - respDelay)/2 + respDelay + respmacdelay;

      uint32_t calc_time_hi_dptp = s2s_reference_hi_d[switch_id]  + (respTDelay / max_ns);
		  uint32_t calc_time_lo_dptp = s2s_reference_lo_d[switch_id]  + (respTDelay % max_ns);
      writeCalcRefTs(calc_time_hi_dptp, calc_time_lo_dptp, now_igts_hi_d[switch_id], now_igts_lo_d[switch_id], switch_id);
      printf("-------------------------------------------------\n");
      printf("                     Switch %d             \n", switch_id);
      printf("-------------------------------------------------\n");
      printf("Request Wire Delay                = %d ns\n", reqWireDelay);
      printf("Reply Mac Delay                   = %d ns\n", ReqMacDelay);
      printf("Reply Queing                      = %d ns\n", replyQueing);
      printf("Reply Egress Tx Delay             = %d ns\n", respTxDelay);
      // printf("Reply Dataplane Tx Delay          = %d ns\n", dpTxDelay);
      // printf("Unaccounted Dataplane Tx Delay    = %d ns\n", undpTxDelay);
      printf("Response Wire Delay               = %d ns\n", respWireDelay);
      printf("Response Mac Delay                = %d ns\n", respmacdelay);
      printf("Total RTT (RespRx - ReqTx)        = %d ns\n", latency_tx);
      printf("Total Response Delay              = %d ns\n", respTDelay);
      printf("-------------------------------------------------\n");
      reportDptpError(calc_time_hi_dptp, calc_time_lo_dptp, now_igts_hi_d[switch_id], now_igts_lo_d[switch_id], 0);
      // reportStats()
    }


    auto bf_status = bfrtLearnReplyFop->bfRtLearnNotifyAck(bfrtsession, learn_msg_hdl);
    assert(bf_status == BF_SUCCESS);
    return BF_SUCCESS;
  }

  bf_status_t dptp::registerDigest (void) {
    bf_status = bfrtInfo->bfrtLearnFromNameGet("DptpIngressDeparser.dptp_followup_digest", &bfrtLearnFollowup);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnFollowup->learnFieldIdGet("egress_port", &learn_egress_port);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnFollowup->learnFieldIdGet("mac_addr", &learn_mac_addr);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnFollowup->bfRtLearnCallbackRegister(session, dev_tgt, followupDigestCallback, nullptr);
    assert(bf_status == BF_SUCCESS);

    bf_status = bfrtInfo->bfrtLearnFromNameGet("DptpIngressDeparser.dptp_reply_digest", &bfrtLearnReply);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("switch_id", &learn_rswitch_id);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("reference_ts_hi", &learn_reference_ts_hi);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("reference_ts_lo", &learn_reference_ts_lo);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bfrtLearnReply->learnFieldIdGet("elapsed_hi", &learn_elapsed_hi);
    // assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("elapsed_lo", &learn_elapsed_lo);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("macts_lo", &learn_macts_lo);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("egts_lo", &learn_egts_lo);
    assert(bf_status == BF_SUCCESS);
    // bf_status = bfrtLearnReply->learnFieldIdGet("tx_updts_lo", &learn_tx_updts_lo);
    // assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("now_macts_lo", &learn_now_macts_lo);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("now_igts_hi", &learn_now_igts_hi);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->learnFieldIdGet("now_igts_lo", &learn_now_igts_lo);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReply->bfRtLearnCallbackRegister(session, dev_tgt, replyDigestCallback, nullptr);
    assert(bf_status == BF_SUCCESS);

    bf_status = bfrtInfo->bfrtLearnFromNameGet("DptpIngressDeparser.dptp_reply_followup_digest", &bfrtLearnReplyFop);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReplyFop->learnFieldIdGet("switch_id", &learn_rfswitch_id);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReplyFop->learnFieldIdGet("tx_capturets_lo", &learn_tx_capturets_lo);
    assert(bf_status == BF_SUCCESS);
    bf_status = bfrtLearnReplyFop->bfRtLearnCallbackRegister(session, dev_tgt, replyFollowupDigestCallback, nullptr);
    assert(bf_status == BF_SUCCESS);
  }
