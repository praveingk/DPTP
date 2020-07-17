
/*
 * DPTP Client APIs
 */
#ifndef _DPTP_H
#define _DPTP_H
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

/* DPTP Message Types */
#define DPTP_REQ 0x2
#define DPTP_RESP 0x3
#define DPTP_FUP 0x6

#define NSEC_PER_SEC 1000000000L
#define KERNEL_TIME_ADJUST_LIMIT 20000
#define PTP_PROTOCOL 0x88F7

#define MBPS 1000000
#define MAX_PORTS 8

uint8_t kernel_time_set;

/* DPTP header */

struct dptp_header
{
  uint16_t magic;
  uint8_t type;
  uint32_t nowHi;
  uint32_t nowLo;
  uint32_t portRate;
  uint8_t igMacTs[6];
  uint8_t igTs[6];
  uint8_t egTs[6];
} __rte_packed;

struct dptp_data_ts
{
  uint16_t portid;
  struct rte_mbuf *pkt;
  struct timespec txReqTs;
  struct timespec rxRespTs;
  struct timespec rxFopTs;
  struct timespec rxFopCallTs;
  uint32_t latency;
  uint32_t nowHi;
  uint32_t nowLo;
  uint32_t portRate;
  uint64_t nowTs;
  uint64_t igMacTs;
  uint64_t igTs;
  uint64_t egTs;
  uint32_t txTs;
  uint32_t profileNicWireDelay;
  struct rte_eth_link portLinkRate;
  float portUtil;
  int64_t dptpDelta;
  uint32_t nicDelta;
  uint32_t clientDelta;
  uint64_t nicTimeTs;
  struct timeval kernel_adj;
};

void run_dptp(struct dptp_data_ts *dptp_data, struct rte_ether_addr tor_switch, struct rte_mempool *mbuf_pool);

__rte_noreturn void start_dptp(uint16_t ports, struct rte_ether_addr tor_switch, struct rte_mempool *mbuf_pool);
#endif