#!/bin/bash
for i in `seq 1 53`
do 
	taskset -c 1 ovs-vswitchd --pid --log-file --detach
	sleep 1
	pkill ovs-vswitchd
	sleep 1
done
