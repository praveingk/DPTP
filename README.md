# DPTP
Data-Plane Time synchronization Protocol

# Topology 


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

### Steps to run MoonGen:
Moongen script sends synchronization requests packets between switches

1) Enable the NIC to work with DPDK:
```shell
sudo ./libmoon/deps/dpdk/usertools/dpdk-devbind.py --b igb_uio <NIC Port>
```

2) To start DPTP in the network between switch 1 and master:
```shell
 sudo ./build/MoonGen examples/dptp_topo.lua <DPDK PORT id1> <DPDK Port id2>
```

Note that <DPDK Port id2> is redundant and is used only for switch-to-host DPTP. 
For just switch-to-switch DPTP, the command could be :
```shell
 sudo ./build/MoonGen examples/dptp_topo.lua 0 0
```
Now, you must be seeing prints on the Switches along with the synchronization accuracy.
