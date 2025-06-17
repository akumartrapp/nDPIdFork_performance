SERVER_IP="100.99.37.253"
BANDWIDTH="1G"
DURATION=10

echo "Starting iperf3 UDP test to $SERVER_IP for $DURATION seconds at $BANDWIDTH..."

# Run the iperf3 test and capture output (no -B binding)
OUTPUT=$(iperf3 -c "$SERVER_IP" -u -b "$BANDWIDTH" -t "$DURATION")

echo "$OUTPUT"

# Extract the sender summary line
SENDER_LINE=$(echo "$OUTPUT" | grep -E '\[ *[0-9]+\] +0\.00-.*sec.*sender')

if [ -z "$SENDER_LINE" ]; then
  echo "iperf3 failed or no sender summary found"
  exit 1
fi

# Extract transfer amount and unit
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

PACKETS_SENT=$(echo "$SENDER_LINE" | grep -oP '\d+/\K\d+')

echo "Packets sent: $PACKETS_SENT"
echo "Total bytes sent: $BYTES_SENT"
echo "Test completed."
