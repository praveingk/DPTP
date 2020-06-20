#!/bin/bash

if [ $# -eq 1 ];then
    profile=test
else
    profile=prod
fi


makefile="Makefile"
setbash="set_bash"


source $setbash;
make -f $makefile clean ; make -f $makefile profile=$profile; ./dptp_main
