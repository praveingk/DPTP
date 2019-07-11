#!/bin/bash

if [ $# -eq 1 ];then
    use_old=true
else
    use_old=false
fi

if [ $use_old == "true" ];then
    makefile="Makefile.old"
    setbash="set_bash.old"
else
    makefile="Makefile"
    setbash="set_bash"
fi

source $setbash;
make -f $makefile clean ; make -f $makefile; ./dptp_topo_cp
