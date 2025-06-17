#!/bin/bash

IFACE="enp2s0f0"
DURATION=60

echo "Monitoring interface: $IFACE for $DURATION seconds..."

# Initial readings
rx1=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
tx1=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
t1=$(date +%s)

# Show seconds counter while waiting
for ((i=1; i<=DURATION; i++)); do
    echo -ne "Elapsed time: ${i}s\r"
    sleep 1
done
echo ""

# Final readings
rx2=$(cat /sys/class/net/$IFACE/statistics/rx_bytes)
tx2=$(cat /sys/class/net/$IFACE/statistics/tx_bytes)
t2=$(date +%s)

# Calculate differences
rx_diff=$((rx2 - rx1))
tx_diff=$((tx2 - tx1))
time_diff=$((t2 - t1))

# Convert to Gbps
rx_gbps=$(echo "scale=3; $rx_diff * 8 / $time_diff / 1000000000" | bc)
tx_gbps=$(echo "scale=3; $tx_diff * 8 / $time_diff / 1000000000" | bc)

# Display results
echo "----------------------------"
echo "Interface: $IFACE"
echo "Duration: $time_diff seconds"
echo "RX: $rx_diff bytes  => $rx_gbps Gbps"
echo "TX: $tx_diff bytes  => $tx_gbps Gbps"
echo "----------------------------"
