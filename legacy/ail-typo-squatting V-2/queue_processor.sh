#!/bin/bash

# Lock file for the queue processor
QUEUE_LOCKFILE="/tmp/queue_processor.lock"

# Check if the queue processor is already running
if [ -e "$QUEUE_LOCKFILE" ]; then
    echo "[*] Queue processor is already running. Exiting."
    exit 1
fi

# Create the lock file
touch "$QUEUE_LOCKFILE"

# Ensure the lock file is removed on exit
trap "rm -f $QUEUE_LOCKFILE" EXIT

# Process the queue
while IFS= read -r job; do
    echo "[*] Running job: $job"
    bash -c "$job"
    # Remove the processed command from the queue
    sed -i '1d' /tmp/cron_queue
done < /tmp/cron_queue
