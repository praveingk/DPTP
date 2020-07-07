#!/bin/bash

if [ $# -eq 1 ];then
    profile=debug
else
    profile=prod
fi


makefile="Makefile"
setbash="set_bash"


source $setbash;
make -f $makefile clean ; make -f $makefile profile=$profile; ./dptp_simple_switch
