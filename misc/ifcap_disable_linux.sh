#!/usr/bin/env sh

DEV=$1
ETHTOOL="/usr/sbin/ethtool"

for OPT in tx rx sg tso ufo gso gro lro rxlan txlan rxhash
do
    ${ETHTOOL} ${DEV} ${OPT} off
done
