/*
 * This application is a simple DPTP Client.
 * It sends DPTP requests across the enabled ports, and synchronizes the nic clock.
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <limits.h>
#include <sys/time.h>
#include <getopt.h>
#include <unistd.h>
#include "dptp.h"
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS            8191
#define MBUF_CACHE_SIZE       250


struct rte_mempool *mbuf_pool;
uint32_t ptp_enabled_port_mask;
uint16_t ptp_enabled_port_nb;
static uint8_t ptp_enabled_ports[RTE_MAX_ETHPORTS];


static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1;
	const uint16_t tx_rings = 1;
	int retval;
	uint16_t q;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));

		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	/* Force full Tx path in the driver, required for IEEE1588 */
	port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MULTI_SEGS;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);

		if (retval < 0)

			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		struct rte_eth_txconf *txconf;

		txconf = &dev_info.default_txconf;
		txconf->offloads = port_conf.txmode.offloads;

		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Enable timesync timestamping for the Ethernet device */
	retval = rte_eth_timesync_enable(port);
	if (retval < 0) {
		printf("Timesync enable failed: %d\n", retval);
		return retval;
	} else {
		printf("Enabling Timestamp on port %d\n", port);
	}

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0) {
		printf("Promiscuous mode enable failed: %s\n",
			rte_strerror(-retval));
		return retval;
	}
	printf("Initialized port %d\n",port);
	return 0;
}


/*
 * The lcore main. This is the main thread that does the work, reading from an
 * input port and writing to an output port.
 */
static __rte_noreturn void
lcore_main(void)
{

	printf("\nStarting DPTP...\n");

	start_dptp(ptp_enabled_port_nb, mbuf_pool);

}

static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK -T VALUE\n"
		" -T VALUE: 0 - Disable, 1 - Enable Linux Clock"
		" Synchronization (0 default)\n"
		" -p PORTMASK: hexadecimal bitmask of ports to configure\n",
		prgname);
}

static int
ptp_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* Parse the hexadecimal string. */
	pm = strtoul(portmask, &end, 16);

	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static int
parse_ptp_kernel(const char *param)
{
	char *end = NULL;
	unsigned long pm;

	/* Parse the hexadecimal string. */
	pm = strtoul(param, &end, 16);

	if ((param[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (pm == 0)
		return 0;

	return 1;
}

/* Parse the commandline arguments. */
static int
ptp_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = { {NULL, 0, 0, 0} };

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:T:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {

		/* Portmask. */
		case 'p':
			ptp_enabled_port_mask = ptp_parse_portmask(optarg);
			if (ptp_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		/* Time synchronization. */
		case 'T':
			ret = parse_ptp_kernel(optarg);
			if (ret < 0) {
				print_usage(prgname);
				return -1;
			}

			//kernel_time_set = ret;
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	argv[optind-1] = prgname;

	optind = 1; /* Reset getopt lib. */

	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned nb_ports;

	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");



	argc -= ret;
	argv += ret;

	ret = ptp_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with PTP initialization\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		printf("%d %d\n", portid, ptp_enabled_port_mask);
		if ((ptp_enabled_port_mask & (1 << portid)) != 0) {
			if (port_init(portid, mbuf_pool) == 0) {
				ptp_enabled_ports[ptp_enabled_port_nb] = portid;
				ptp_enabled_port_nb++;
				printf("Enabled port %d\n", portid);
			} else {
				rte_exit(EXIT_FAILURE,
					 "Cannot init port %"PRIu8 "\n",
					 portid);
			}
		} else
			printf("Skipping disabled port %u\n", portid);
	}

	if (ptp_enabled_port_nb == 0) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled."
			" Please set portmask.\n");
	}

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
