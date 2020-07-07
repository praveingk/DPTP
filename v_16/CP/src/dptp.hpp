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
	// Entry Functions
	bf_status_t setUpBfrt(bf_rt_target_t target, const char *progname);

	bf_status_t initRegisterAPI(void);

	bf_status_t initReferenceTs(void);

	bf_status_t createEraThread(void);

	static bf_status_t txComplete(bf_dev_id_t device,
                  				 bf_pkt_tx_ring_t tx_ring,
                   				 uint64_t tx_cookie,
                  				 uint32_t status);

	void callbackRegister(void);

	bf_status_t initPackets(void);

	void waitOnThreads(void);

	bf_status_t registerDigest(const char *dptp_followup_digest, const char *dptp_reply_digest, const char *dptp_reply_followup_digest);

	void createDptpRequestThread(uint32_t interval);
} // namespace dptp

#endif // _DPTP_HPP