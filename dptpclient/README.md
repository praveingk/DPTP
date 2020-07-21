# DPTP Client (DPDK-based)

DPTP Client is a DPDK-based application that synchronizes the nic/kernel time to the network time.
It sends requests to the ToR (Top-of-the-Rack) switch, that also runs DPTP.
This code is tested on DPDK version 20.08, and Intel X710 NICs.

## Pre-requisites

1) Build & Install DPDK with "CONFIG_RTE_LIBRTE_IEEE1588=y" and "CONFIG_RTE_EAL_IGB_UIO=y"

2) Bind the NIC ports to DPDK (IGB_UIO)
```shell
sudo $DPDK_PATH/usertools/dpdk-devbind.py --b igb_uio <NIC Ports>
```

## Steps to run Dptpclient

1) Build dptpclient 
```shell
export DPTP_PATH=<PATH TO DPTP FOLDER>
cd $DPTP_PATH/dptpclient/
./build.sh
```

2) Run dptpclient on the NIC ports that are enabled
```shell
 sudo ./build/dptpclient -- -p <PORT_MASK>
 ```
 For example, to run dptpclient on NIC port 0 and 1 the command is following :
 ```shell
 sudo ./build/dptpclient -- -p 0x3
 ```
