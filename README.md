# DPTP
Data-Plane Time synchronization Protocol
(https://www.comp.nus.edu.sg/~pravein/papers/DPTP_SOSR19.pdf)
This source code synchronizes two Barefoot Tofino switches to support a global timing (64-bit) in the data-plane. 

p4_14 : v_14/

p4_16 : v_16/
The current source code is p4_14 based, and will soon publish the p4_16 code.

# Topology 
The Topology used in as below : 

![DPTP Topology](Tofino-minibed-timesync.png)


A single tofino switch named "tofino1" is virtualized into two switches Master(M) and Switch1. To do this virtualization, you will need to add a loopback link between port3 (160-163) and port5 (176-179). Once done, it will be configured as 10G ports, and we will be using only one link (160-176) as the connection between Switch1 and Master. Additionally, you will need atleast one host connected to port 1(128-131) to send DPTP requests.
### Steps to run DPTP in Tofino:

1) Navigate to the SDE PATH :
```shell
     cd ~/bf-sde-8.x.x
```
2) Set the env variables : 
```shell
     . ./set_sde.bash
```
3) Build the p4 program using the command :
```shell
     ./p4_build ../<YOUR PATH>/DPTP/dptp.p4
```
4) Load the p4 program, and run the control plane API code using :
```shell
     "cd ../<YOUR PATH>/CP"
     "./run.sh"
```
5) This should automatically start the synchronization between Switch1 and master through packets from control-plane.

### Steps to run MoonGen for host synchronization:
Moongen script sends synchronization requests packets between switches
Pull from https://github.com/praveingk/moongen/, Make sure the submodule libmoon is also pulled. 
Follow the readme instructions in moongen to build it.
1) Enable the NIC to work with DPDK:
```shell
sudo ./libmoon/deps/dpdk/usertools/dpdk-devbind.py --b igb_uio <NIC Port>
```

2) To start DPTP in the network between switch 1 and master:
```shell
 sudo ./build/MoonGen examples/dptp_topo.lua <DPDK PORT id1> <DPDK Port id2>
```
Note that "DPDK Port id2" is redundant and is used only for switch-to-host DPTP accuracy measurement. 

### Steps to Create CrossTraffic in the Link(160-176) during DPTP

1) To create cross-traffic in the link being used for synchronization towards the SW1 (i.e. 160 --> 176),
we simply craft a packet to destination address of SW1 (0x100000000001) and send it from any host link.
```shell
 sudo ./build/MoonGen examples/dptp_topo.lua -d 1 <DPDK PORT id1> <DPDK Port id2>
```
Note that "DPDK Port id2" is redundant and is used only for switch-to-host DPTP accuracy measurement. 

2) To create oversubscribed traffic, run the above example from two 10G host-links.
