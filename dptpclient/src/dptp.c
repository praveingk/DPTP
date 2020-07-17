/*
 * DPTP Client APIs
 */

#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/time.h>
#include <getopt.h>
#include <unistd.h>
#include "dptp.h"

static inline uint64_t timespec64_to_ns(const struct timespec *ts)
{
  return ((uint64_t)ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

static uint64_t dptpts_to_ns(uint8_t *ts)
{
  uint64_t ts_ns = 0;
  int i = 0;
  for (i = 0; i < 5; i++)
  {
    ts_ns = (ts_ns | ts[i]) << 8;
  }
  ts_ns = ts_ns | ts[5];
  return ts_ns;
}

static struct timeval
ns_to_timeval(int64_t nsec)
{
  struct timespec t_spec = {0, 0};
  struct timeval t_eval = {0, 0};
  int32_t rem;

  if (nsec == 0)
    return t_eval;
  rem = nsec % NSEC_PER_SEC;
  t_spec.tv_sec = nsec / NSEC_PER_SEC;

  if (rem < 0)
  {
    t_spec.tv_sec--;
    rem += NSEC_PER_SEC;
  }

  t_spec.tv_nsec = rem;
  t_eval.tv_sec = t_spec.tv_sec;
  t_eval.tv_usec = t_spec.tv_nsec / 1000;

  return t_eval;
}

/*
 * Update the kernel time with the difference between it and the current NIC
 * time.
 */
static inline void
update_kernel_time(struct dptp_data_ts *dptp_data)
{
  int64_t nsec;
  struct timespec net_time, sys_time;
  clock_gettime(CLOCK_REALTIME, &sys_time);
  rte_eth_timesync_read_time(dptp_data->portid, &net_time);

  nsec = (int64_t)timespec64_to_ns(&net_time) -
         (int64_t)timespec64_to_ns(&sys_time);

  dptp_data->kernel_adj = ns_to_timeval(nsec);

  /*
	 * If difference between kernel time and system time in NIC is too big
	 * (more than +/- 20 microseconds), use clock_settime to set directly
	 * the kernel time, as adjtime is better for small adjustments (takes
	 * longer to adjust the time).
	 */

  if (nsec > KERNEL_TIME_ADJUST_LIMIT || nsec < -KERNEL_TIME_ADJUST_LIMIT)
    clock_settime(CLOCK_REALTIME, &net_time);
  else
    adjtime(&dptp_data->kernel_adj, 0);
}

static void print_dptp_packet(struct dptp_header *dptp_hdr)
{
  printf("DPTP : Type=%d, Reference Hi=%u, Reference Lo=%u, Port Rate=%u, Mac Ts=%lu, Ig Ts=%lu, Eg Ts=%lu \n",
         dptp_hdr->type, htonl(dptp_hdr->nowHi), htonl(dptp_hdr->nowLo),
         htonl(dptp_hdr->portRate), dptpts_to_ns(dptp_hdr->igMacTs), dptpts_to_ns(dptp_hdr->igTs), dptpts_to_ns(dptp_hdr->egTs));
}

static void print_dptp_data(struct dptp_data_ts *dptp_data)
{
  int switchReqDelay = dptp_data->igTs - dptp_data->igMacTs;
  int switchQueueDelay = dptp_data->egTs - dptp_data->igTs;
  int switchTxDelay = dptp_data->txTs - dptp_data->egTs;
  int nicWireDelay = dptp_data->latency - (dptp_data->txTs - dptp_data->igMacTs);
  int dptpRespDelay = nicWireDelay / 2;
  printf("----------------------------\n");
  printf("DPTP RTT                = %d ns\n", dptp_data->latency);
  printf("|_ Switch Request Delay = %d ns\n", switchReqDelay);
  printf("|_ Switch Queuing Delay = %d ns\n", switchQueueDelay);
  printf("|_ Switch Tx Delay      = %d ns\n", switchTxDelay);
  printf("|_ NicWireDelay         = %d ns\n", nicWireDelay);
  printf("ProfileNicWireDelay     = %d ns\n", dptp_data->profileNicWireDelay);
  printf("DPTP Response Delay     = %d ns\n", dptpRespDelay);
  printf("Link Util bytes         = %u bytes\n", dptp_data->portRate);
  printf("Link Utilization        = %f %%\n", dptp_data->portUtil);
  printf("DPTP Now                = %lu ns\n", dptp_data->nowTs);
  printf("Correcting Nic Time     = %lu by delta =  %ld ns\n", dptp_data->nicTimeTs, dptp_data->dptpDelta);
  printf("|_ DPTP Client Delay    = %u ns\n", dptp_data->clientDelta);
  printf("Correcting Kernel time  = %ld ns\n", dptp_data->kernel_adj.tv_usec);
  printf("----------------------------\n");
}

static void dptp_correct_time(struct dptp_data_ts *dptp_data)
{
  int nicWireDelay = dptp_data->latency - (dptp_data->txTs - dptp_data->igMacTs);

  int dptpRespDelay = 0;
  struct timespec nicTime;

  dptp_data->portUtil = 100 * ((float)(dptp_data->portRate * 8) / (float)(dptp_data->portLinkRate.link_speed * MBPS));
  if (dptp_data->portUtil > 1)
  {
    if (dptp_data->profileNicWireDelay != 0)
      dptpRespDelay = dptp_data->profileNicWireDelay / 2;
  }
  else
  {
    dptpRespDelay = nicWireDelay / 2;
  }

  dptp_data->nowTs = dptp_data->nowTs + dptpRespDelay;

  rte_eth_timesync_read_time(dptp_data->portid, &nicTime);
  dptp_data->nicTimeTs = timespec64_to_ns(&nicTime);
  dptp_data->dptpDelta = dptp_data->nowTs - dptp_data->nicTimeTs;
  dptp_data->clientDelta = nicTime.tv_nsec - dptp_data->rxFopCallTs.tv_nsec;

  rte_eth_timesync_adjust_time(dptp_data->portid, dptp_data->dptpDelta);
  update_kernel_time(dptp_data);

  if (dptp_data->portUtil < 1)
  {
    if (dptp_data->profileNicWireDelay != 0)
      dptp_data->profileNicWireDelay = (dptp_data->profileNicWireDelay + nicWireDelay) / 2;
    else
      dptp_data->profileNicWireDelay = nicWireDelay;
  }

  print_dptp_data(dptp_data);
}
/*
 * Parse the PTP SYNC message.
 */
static void
parse_dptp_resp(struct dptp_header *dptp_hdr, struct dptp_data_ts *dptp_data, uint16_t rx_tstamp_idx)
{
  uint64_t nowHiTemp = 0;
  rte_eth_timesync_read_rx_timestamp(dptp_data->portid, &dptp_data->rxRespTs, rx_tstamp_idx);
  dptp_data->nowHi = htonl(dptp_hdr->nowHi);
  dptp_data->nowLo = htonl(dptp_hdr->nowLo);
  dptp_data->portRate = htonl(dptp_hdr->portRate);
  dptp_data->igMacTs = dptpts_to_ns(dptp_hdr->igMacTs);
  dptp_data->igTs = dptpts_to_ns(dptp_hdr->igTs);
  dptp_data->egTs = dptpts_to_ns(dptp_hdr->egTs);
  dptp_data->latency = timespec64_to_ns(&dptp_data->rxRespTs) - timespec64_to_ns(&dptp_data->txReqTs);
  nowHiTemp = (nowHiTemp | dptp_data->nowHi) << 32;
  //printf("%lu\n", nowHiTemp);
  dptp_data->nowTs = nowHiTemp | dptp_data->nowLo;

  //printf("dptp now = %lu \n", )
  //printf("Received DPTP Response Packet at %ld, %ld\n", dptp_data->rxRespTs.tv_sec, dptp_data->rxRespTs.tv_nsec);
  //print_dptp_packet(dptp_hdr);
}

static void parse_dptp_fup(struct dptp_header *dptp_hdr, struct dptp_data_ts *dptp_data, uint16_t rx_tstamp_idx)
{
  rte_eth_timesync_read_rx_timestamp(dptp_data->portid, &dptp_data->rxFopTs, rx_tstamp_idx);
  rte_eth_timesync_read_time(dptp_data->portid, &dptp_data->rxFopCallTs);
  //printf("Received DPTP Followup Packet at %ld, %ld\n", dptp_data->rxFopTs.tv_sec, dptp_data->rxFopTs.tv_nsec);
  dptp_data->txTs = htonl(dptp_hdr->nowHi);
  //print_dptp_packet(dptp_hdr);
  dptp_correct_time(dptp_data);
}

static void send_dptp_request(struct dptp_data_ts *dptp_data, struct rte_ether_addr tor_switch, struct rte_mempool *mbuf_pool)
{
  struct rte_mbuf *dptp_req_pkt;
  size_t pkt_size;
  struct rte_ether_hdr *eth_hdr;
  struct rte_ether_addr eth_addr;
  struct dptp_header *dptp_hdr;
  struct rte_ether_addr tor_switchaddr = tor_switch;
  int wait_us, ret;

  ret = rte_eth_macaddr_get(dptp_data->portid, &eth_addr);
  if (ret != 0)
  {
    printf("\nCore %u: port %u failed to get MAC address: %s\n",
           rte_lcore_id(), dptp_data->portid,
           rte_strerror(-ret));
    return;
  }
  dptp_req_pkt = rte_pktmbuf_alloc(mbuf_pool);
  if (dptp_req_pkt == NULL)
  {
    printf("Failed to allocate mbuf\n");
    return;
  }
  pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct dptp_header);
  dptp_req_pkt->data_len = pkt_size;
  dptp_req_pkt->pkt_len = pkt_size;
  eth_hdr = rte_pktmbuf_mtod(dptp_req_pkt, struct rte_ether_hdr *);

  rte_ether_addr_copy(&eth_addr, &eth_hdr->s_addr);

  rte_ether_addr_copy(&tor_switchaddr, &eth_hdr->d_addr);

  eth_hdr->ether_type = htons(PTP_PROTOCOL);
  dptp_hdr = (struct dptp_header *)(rte_pktmbuf_mtod(dptp_req_pkt, char *) + sizeof(struct rte_ether_hdr));
  dptp_hdr->magic = 0x0200;
  dptp_hdr->type = DPTP_REQ;

  /* Enable flag for hardware timestamping. */
  dptp_req_pkt->ol_flags |= PKT_TX_IEEE1588_TMST;

  /* Read value from NIC to prevent latching with old value. */

  rte_eth_timesync_read_tx_timestamp(dptp_data->portid, &dptp_data->txReqTs);
  /* Transmit the packet. */
  rte_eth_tx_burst(dptp_data->portid, 0, &dptp_req_pkt, 1);
  wait_us = 0;
  dptp_data->txReqTs.tv_nsec = 0;
  dptp_data->txReqTs.tv_sec = 0;

  /* Wait at least 1 us to read TX timestamp. */
  while (((ret = rte_eth_timesync_read_tx_timestamp(dptp_data->portid, &dptp_data->txReqTs)) < 0) && (wait_us < 1000))
  {
    rte_delay_us(1);
    wait_us++;
  }

  printf("Sent DPTP request packet, port=%d, txReqTs=%lu, err = %s\n",
         dptp_data->portid, timespec64_to_ns(&dptp_data->txReqTs), rte_strerror(-ret));
}

/* This function processes DPTP packets
 *
 */
static bool
parse_dptp_frames(struct rte_mbuf *pkt, struct dptp_data_ts *dptp_data)
{
  struct dptp_header *dptp_hdr;
  struct rte_ether_hdr *eth_hdr;
  uint16_t eth_type;

  eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
  eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
  dptp_data->pkt = pkt;
  if (eth_type == PTP_PROTOCOL)
  {
    dptp_hdr = (struct dptp_header *)(rte_pktmbuf_mtod(pkt, char *) + sizeof(struct rte_ether_hdr));

    switch (dptp_hdr->type)
    {
    case DPTP_RESP:
      parse_dptp_resp(dptp_hdr, dptp_data, pkt->timesync);
      return false;
    case DPTP_FUP:
      parse_dptp_fup(dptp_hdr, dptp_data, pkt->timesync);
      return true;
    default:
      break;
    }
  }
  return false;
}

#define MAX_BURST 1000
void run_dptp(struct dptp_data_ts *dptp_data, struct rte_ether_addr tor_switch, struct rte_mempool *mbuf_pool)
{
  unsigned nb_rx;
  struct rte_mbuf *pkt;
  bool fop_received;

  printf("---------------------------------------\n");
  printf("DPTP - port %d\n", dptp_data->portid);
  printf("---------------------------------------\n");
  send_dptp_request(dptp_data, tor_switch, mbuf_pool);

  while (!fop_received)
  {
    do
    {
      nb_rx = rte_eth_rx_burst(dptp_data->portid, 0, &pkt, MAX_BURST);
    } while (nb_rx == 0);

    if (pkt->ol_flags & PKT_RX_IEEE1588_PTP)
      fop_received = parse_dptp_frames(pkt, dptp_data);

    rte_pktmbuf_free(pkt);
  }
}

static void dptp_eval(struct dptp_data_ts *dptp_data, uint16_t portid1, uint16_t portid2)
{
  int drift = 0;
  int nicDiff, switchDiff;
  long refNow1, refNow2;
  int dptp_error;
  printf("Port %d -> Now - %lu, tx -  %u, rx - %lu \n", portid1, dptp_data[portid1].nowTs,
         dptp_data[portid1].txTs, timespec64_to_ns(&dptp_data[portid1].rxRespTs));
  printf("Port %d -> Now - %lu, tx -  %u, rx - %lu \n", portid2, dptp_data[portid2].nowTs,
         dptp_data[portid2].txTs, timespec64_to_ns(&dptp_data[portid2].rxRespTs));

  switchDiff = dptp_data[portid2].txTs - dptp_data[portid1].txTs;
  nicDiff = timespec64_to_ns(&dptp_data[portid2].rxRespTs) - timespec64_to_ns(&dptp_data[portid1].rxRespTs);
  drift = switchDiff - nicDiff;
  refNow1 = dptp_data[portid1].nowTs - timespec64_to_ns(&dptp_data[portid1].rxRespTs);
  refNow2 = dptp_data[portid2].nowTs - timespec64_to_ns(&dptp_data[portid2].rxRespTs);
  dptp_error = (refNow2 - refNow1) - drift;
  // printf("%lu %lu\n", dptp_data[portid1].nowTs, dptp_data[portid2].nowTs);
  // printf("switchDiff = %d, nicDiff = %d, Drift = %d\n", switchDiff, nicDiff, drift);
  // printf("Reference Now 1 = %ld, Reference Now 2 = %ld\n", refNow1, refNow2);
  printf("DPTP error between ports(%d, %d) = %d\n", portid1, portid2, dptp_error);
}

__rte_noreturn void start_dptp(uint16_t ports, struct rte_ether_addr tor_switch, struct rte_mempool *mbuf_pool)
{
  uint16_t portid;
  struct dptp_data_ts dptp_data[MAX_PORTS];

  for (int i = 0; i < MAX_PORTS; i++)
  {
    memset(&dptp_data[i], '\0', sizeof(struct dptp_data_ts));
    dptp_data[i].portid = i;
    rte_eth_link_get(i, &dptp_data[i].portLinkRate);
  }
  while (1)
  {
    /* Read packet from RX queues. */
    for (portid = 0; portid < ports; portid++)
    {
      run_dptp(&dptp_data[portid], tor_switch, mbuf_pool);
      usleep(1000);
    }
    dptp_eval(dptp_data, 0, 1);
    //usleep(2000);
    sleep(1);
  }
}
