#!/bin/sh

ifconfig -a | awk '/igb/{sub(":", "", $1); print $1}' | xargs > igbX
ifconfig -a | awk '/ix[0-9]/{sub(":", "", $1); print $1}' | xargs > ixX
ifconfig -a | awk '/em[0-9]/{sub(":", "", $1); print $1}' | xargs > emX

for i in `cat igbX`
do
	ifconfig ${i} -rxcsum -txcsum -rxcsum6 -txcsum6 -tso -tso6 -tso4 -lro up
done

for i in `cat ixX`
do
	ifconfig ${i} -rxcsum -txcsum -rxcsum6 -txcsum6 -tso -tso6 -tso4 -lro up
done

for i in `cat emX`
do
	ifconfig ${i} -rxcsum -txcsum -rxcsum6 -txcsum6 -tso -tso6 -tso4 -lro up
done

#sysctl -w dev.netmap.if_size=2048
#sysctl -w dev.netmap.if_num=200
#sysctl -w dev.netmap.ring_size=73728
#sysctl -w dev.netmap.ring_num=400
#sysctl -w dev.netmap.buf_size=2048
#sysctl -w dev.netmap.buf_num=300000
