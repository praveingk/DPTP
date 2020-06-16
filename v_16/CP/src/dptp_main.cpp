/*
 * Control Plane program for DPTP
 * Compile using following command : make 
 * To Execute, Run: ./run.sh
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
#include <pcap.h>
#include <arpa/inet.h>
#include "dptp.hpp"

using namespace std;
using namespace dptp;


#ifdef __cplusplus
extern "C"
{
#endif
#include <bf_switchd/bf_switchd.h>
#ifdef __cplusplus
}
#endif

#define THRIFT_PORT_NUM 7777
int switchid = 0;

void init_bf_switchd() {
	bf_switchd_context_t *switchd_main_ctx = NULL;
	char *install_dir;	
	char target_conf_file[100];
	bf_status_t bf_status;
	install_dir = getenv("SDE_INSTALL");
	sprintf(target_conf_file, "%s/share/p4/targets/tofino/dptp.conf", install_dir);

	/* Allocate memory to hold switchd configuration and state */
	if ((switchd_main_ctx = (bf_switchd_context_t *)calloc(1, sizeof(bf_switchd_context_t))) == NULL) {
		printf("ERROR: Failed to allocate memory for switchd context\n");
		return;
	}

	memset(switchd_main_ctx, 0, sizeof(bf_switchd_context_t));
	switchd_main_ctx->install_dir = install_dir;
	switchd_main_ctx->conf_file = target_conf_file;
	switchd_main_ctx->skip_p4 = false;
	switchd_main_ctx->skip_port_add = false;
	switchd_main_ctx->running_in_background = true;
	switchd_main_ctx->dev_sts_thread = true;
	switchd_main_ctx->dev_sts_port = THRIFT_PORT_NUM;

	bf_status = bf_switchd_lib_init(switchd_main_ctx);
	printf("Initialized bf_switchd, status = %d\n", bf_status);
}

void getSwitchName () {
	char switchName[25];
	FILE *f = fopen("/etc/hostname", "r");
	fscanf(f, "%s", switchName);
	if (strcmp(switchName, "tofino1") == 0) {
		switchid = 1;
	}
	else if (strcmp(switchName, "tofino2") == 0) {
		switchid = 2;
	}
	printf("Detected running on Tofino%d\n", switchid);
}

void init_tables() {
	char cwd[256];
	char bfrtcommand[256];
	if (getcwd(cwd, sizeof(cwd)) != NULL) {
		printf("Current working dir: %s\n", cwd);
	}
	//printf("Current WD:%s\n", cwd);
	sprintf(bfrtcommand, "bfshell -b %s/table-setup.py", cwd);
	//printf("%s\n", bfrtcommand);
	system(bfrtcommand);
}

void init_ports() {
	if (switchid == 1) {
		system("bfshell -f commands-ports-tofino1.txt");
	}
	else if (switchid == 2) {
		system("bfshell -f commands-ports-tofino2.txt");
	}
}

static bf_status_t txComplete(bf_dev_id_t device,
							  bf_pkt_tx_ring_t tx_ring,
							  uint64_t tx_cookie,
							  uint32_t status) {
	//bf_pkt *pkt = (bf_pkt *)(uintptr_t)tx_cookie;
	//bf_pkt_free(device, pkt);
	return BF_SUCCESS;
}
void callbackRegister(bf_dev_id_t device) {
	int tx_ring;
	/* register callback for TX complete */
	for (tx_ring = BF_PKT_TX_RING_0; tx_ring < BF_PKT_TX_RING_MAX; tx_ring++) {
		bf_pkt_tx_done_notif_register(
			device, txComplete, (bf_pkt_tx_ring_t)tx_ring);
	}
}

int main(int argc, char **argv) {
	// Start the BF Switchd
	init_bf_switchd();
	// Initialize the switch ports and data-plane MATs
	getSwitchName();
	init_ports();
	init_tables();
	printf("Starting dptp_topo Control Plane Unit ..\n");
	dptp::setUp();
	dptp::initRegisterAPI();

	dptp::initReferenceTs();
	dptp::createEraThread();

	callbackRegister(0);

	dptp::initPackets();
	dptp::registerDigest();
	dptp::createDptpRequestThread();
	dptp::waitOnThreads();
	return 0;
}
