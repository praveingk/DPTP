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

void init_bf_switchd(const char* progname) {
	bf_switchd_context_t *switchd_main_ctx = NULL;
	char *install_dir;	
	char target_conf_file[100];
	bf_status_t bf_status;
	install_dir = getenv("SDE_INSTALL");
	sprintf(target_conf_file, "%s/share/p4/targets/tofino/%s.conf", install_dir, progname);

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


int main(int argc, char **argv) {
	const char * p4progname = "dptp_simple_switch";
	const char * followup_digest = "SwitchIngressDeparser.dptp_ingress_deparser.dptp_followup_digest";
	const char * reply_digest = "SwitchIngressDeparser.dptp_ingress_deparser.dptp_reply_digest";
	const char * reply_followup_digest = "SwitchIngressDeparser.dptp_ingress_deparser.dptp_reply_followup_digest";
	uint32_t dptp_interval = 1000000; // Currently supports upto a request every 2ms, i.e. 500 DPTP requests/sec
	bf_rt_target_t dev_tgt;

	// Initialize the device id and pipelines to be used for DPTP
    dev_tgt.dev_id = 0;
    dev_tgt.pipe_id = ALL_PIPES;

	// Start the BF Switchd
	init_bf_switchd(p4progname);

	// Initialize the switch ports and data-plane MATs
	getSwitchName();
	init_ports();
	init_tables();

	printf("Starting DPTP Simple Switch..\n");

	// Setup bfrt runtime APIs and then the register APIs which will be used to read/write registers (reference)
	dptp::setUpBfrt(dev_tgt, p4progname);
	dptp::initRegisterAPI();

	// Initialize packets (request,followup) and register digest for followup generation, reply and reply followup packets.
	dptp::initPackets();
	dptp::registerDigest(followup_digest, reply_digest, reply_followup_digest);

	// Master Switch which has the Clock Reference
	dptp::initReferenceTs();
	dptp::createEraThread();

	// Other Switches which needs the Clock Reference
	sleep(2); // 
	dptp::createDptpRequestThread(dptp_interval);

	// Wait on the threads so that DPTP runs in the background
	dptp::waitOnThreads();
	return 0;
}
