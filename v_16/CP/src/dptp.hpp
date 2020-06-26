#ifndef _DPTP_HPP
#define _DPTP_HPP

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
#include <pcap.h>
#include <arpa/inet.h>

#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table.hpp>

#ifdef __cplusplus
extern "C"
{
#endif
#include <bf_switchd/bf_switchd.h>
#include <lld/bf_ts_if.h>
#include <pkt_mgr/pkt_mgr_intf.h>
#include <port_mgr/bf_port_if.h>
#ifdef __cplusplus
}
#endif

#define ALL_PIPES 0xffff
#define MAX_SWITCHES 20
#define DPTP_GEN_REQ 0x11
#define DPTP_CAPTURE_COMMAND 0x6

namespace dptp {
	// Utility Functions

	bf_status_t writeReferenceTs(const uint64_t ts_hi, const uint64_t ts_lo, uint64_t switch_id);

	bf_status_t incrementEra(void);

	void *eraMaintenance(void *args);

	void *sendDptpRequests(void *args);

	bf_status_t initReferenceTsAPI(void);

	bf_status_t readReferenceTs(uint32_t *ts_hi, uint32_t *ts_lo, uint8_t switch_id);

	bf_status_t reportDptpError(uint32_t calc_time_hi, uint32_t calc_time_lo, uint32_t now_elapsed_hi, uint32_t now_elapsed_lo, uint8_t master_switch);

	bf_status_t initRequestPkt(void);

	bf_status_t initFollowupPkt(void);

	bf_status_t replyDigestCallback(const bf_rt_target_t &bf_rt_tgt,
									const std::shared_ptr<bfrt::BfRtSession> bfrtsession,
									std::vector<std::unique_ptr<bfrt::BfRtLearnData>> vec,
									bf_rt_learn_msg_hdl *const learn_msg_hdl,
									const void *cookie);

	bf_status_t replyFollowupDigestCallback(const bf_rt_target_t &bf_rt_tgt,
											const std::shared_ptr<bfrt::BfRtSession> bfrtsession,
											std::vector<std::unique_ptr<bfrt::BfRtLearnData>> vec,
											bf_rt_learn_msg_hdl *const learn_msg_hdl,
											const void *cookie);

	bf_status_t writeCalcRefTs(uint32_t calc_time_hi_dptp,
							   uint32_t calc_time_lo_dptp,
							   uint32_t now_elapsed_hi,
							   uint32_t now_elapsed_lo,
							   uint8_t switch_id);

	bf_status_t sendFollowupPacket(uint8_t *dstAddr, uint32_t tx_capture_tstamp_lo);

	// Entry Functions
	bf_status_t setUp(void);

	bf_status_t initRegisterAPI(void);

	bf_status_t initReferenceTs(void);

	bf_status_t createEraThread(void);

	bf_status_t initPackets(void);

	void waitOnThreads(void);

	bf_status_t registerDigest(void);

	void createDptpRequestThread(void);
} // namespace dptp

#endif // _DPTP_HPP