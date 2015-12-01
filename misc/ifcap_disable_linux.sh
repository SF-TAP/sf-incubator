#!/usr/bin/env sh

DEV=$1
ETHTOOL="ethtool"

for OPT in tx rx sg tso gso gro lro rxhash rxvlan txvlan
do
    echo ${ETHTOOL} -K ${DEV} ${OPT} off
    ${ETHTOOL} -K ${DEV} ${OPT} off
done
