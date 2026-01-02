#!/bin/bash

IFACE="enp2s0f0"
echo "Measuring TX rate on interface $IFACE over 30 seconds..."

# Get initial TX bytes
TX1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
T1=$(date +%s)

sleep 30

# Get TX bytes after 60 seconds
TX2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
T2=$(date +%s)

# Sanity check
if [[ -z "$TX1" || -z "$TX2" ]]; then
    echo "Failed to read TX bytes for $IFACE"
    exit 1
fi

# Compute delta and rate
TX_BYTES=$((TX2 - TX1))
TIME_DELTA=$((T2 - T1))
TX_BITS=$((TX_BYTES * 8))

# Compute Gbps using bc
TX_GBPS=$(echo "scale=6; $TX_BITS / ($TIME_DELTA * 1000000000)" | bc)

echo "TX over $TIME_DELTA seconds: $TX_BYTES bytes"
echo "TX Rate: $TX_GBPS Gbps"