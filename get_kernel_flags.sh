#!/bin/bash

Kernel_Flags=(CONFIG_BPF=y CONFIG_BPF_SYSCALL=y CONFIG_NET_CLS_BPF=m CONFIG_NET_ACT_BPF=m CONFIG_BPF_JIT=y CONFIG_HAVE_EBPF_JIT=y CONFIG_BPF_EVENTS=y CONFIG_IKHEADERS=y)

echo "Your Linux Version : "
cat /proc/version | awk 'BEGIN{FS=" " };{print $1 " " $2 " " $3}'
echo "----------------------------------------------------------"
echo "Checking for kernal flags"

version=`cat /proc/version | awk 'BEGIN{FS=" " };{print $3}'`

for flag in "${Kernel_Flags[@]}"    
do
    tmp=`cat /boot/config-"$version"|  grep -w "$flag" `
    if [[ $tmp != $flag ]]
    then
        flag1=`echo $flag | awk 'BEGIN{FS="="};{print $1}'` 
        tmp=`cat /boot/config-"$version"|  grep -w "$flag1" `
        echo "MISMATCH !! Required : $flag Found : $tmp"
    fi
done
