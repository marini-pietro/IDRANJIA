#!/bin/bash

# List of program names to kill
PROGRAM_NAMES=("log_server.py" "auth_server.py" "api_server.py")

for PROGRAM_NAME in "${PROGRAM_NAMES[@]}"; do
    # Find and kill processes by name
    PIDS=$(pgrep -f "$PROGRAM_NAME")

    if [ -z "$PIDS" ]; then
        echo "No processes found with name: $PROGRAM_NAME"
        continue
    fi

    echo "Killing processes with name: $PROGRAM_NAME"
    for PID in $PIDS; do
        echo "Killing PID: $PID"
        kill -9 $PID
    done

    echo "All processes with name $PROGRAM_NAME have been terminated."
done
