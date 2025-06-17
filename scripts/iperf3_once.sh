
# SERVER_IP="10.31.1.157"
# BANDWIDTH="1G"
# DURATION=10

# # Bind the client to the eth0 IP as source (to force using eth0)
# SOURCE_IP="$SERVER_IP"

# echo "Starting iperf3 UDP test to $SERVER_IP for $DURATION seconds at $BANDWIDTH from $SOURCE_IP..."

# # Run iperf3 and capture output
# OUTPUT=$(iperf3 -c "$SERVER_IP" -u -B "$SOURCE_IP" -b "$BANDWIDTH" -t "$DURATION")

# # Print full output
# echo "$OUTPUT"

# # Extract packets sent from sender summary line
# PACKETS_SENT=$(echo "$OUTPUT" | grep -Eo '[0-9]+/[0-9]+.*sender' | head -n1 | awk -F'/' '{print $2}' | awk '{print $1}')

# echo "Packets sent: $PACKETS_SENT"
# echo "Test completed."

#!/bin/bash

SERVER_IP="100.99.37.253"
BANDWIDTH="1G"
DURATION=100
SOURCE_IP="$SERVER_IP"

echo "Starting iperf3 UDP test to $SERVER_IP for $DURATION seconds at $BANDWIDTH from $SOURCE_IP..."

# Run the iperf3 test and capture output
OUTPUT=$(iperf3 -c "$SERVER_IP" -u -B "$SOURCE_IP" -b "$BANDWIDTH" -t "$DURATION")

echo "$OUTPUT"

# Extract the sender summary line
SENDER_LINE=$(echo "$OUTPUT" | grep -E '\[ *[0-9]+\] +0\.00-.*sec.*sender')

# Extract transfer amount and unit from sender line
TRANSFER_VAL=$(echo "$SENDER_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="sec") {print $(i+1); exit}}')
TRANSFER_UNIT=$(echo "$SENDER_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="sec") {print $(i+2); exit}}')

# Convert to bytes
case "$TRANSFER_UNIT" in
  Bytes) BYTES_SENT=$(printf "%.0f" "$TRANSFER_VAL") ;;
  KBytes) BYTES_SENT=$(printf "%.0f" "$(echo "$TRANSFER_VAL * 1024" | bc)") ;;
  MBytes) BYTES_SENT=$(printf "%.0f" "$(echo "$TRANSFER_VAL * 1024 * 1024" | bc)") ;;
  GBytes) BYTES_SENT=$(printf "%.0f" "$(echo "$TRANSFER_VAL * 1024 * 1024 * 1024" | bc)") ;;
  *) BYTES_SENT="Unknown unit: $TRANSFER_UNIT" ;;
esac

# Extract packets sent
PACKETS_SENT=$(echo "$SENDER_LINE" | grep -oP '\d+/\K\d+')

echo "Packets sent: $PACKETS_SENT"
echo "Total bytes sent: $BYTES_SENT"
echo "Test completed."




