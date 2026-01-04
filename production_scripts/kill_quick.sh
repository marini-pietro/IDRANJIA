#!/bin/bash

# Kill log_server.py as a normal Python process
LOG_PIDS=$(ps aux | grep python | grep "log_server.py" | grep -v grep | awk '{print $2}')
if [ -z "$LOG_PIDS" ]; then
    echo "No running process found for log_server.py"
else
    echo "Killing log_server.py processes"
    for PID in $LOG_PIDS; do
        echo "Killing PID: $PID"
        kill -9 $PID
    done
    echo "All log_server.py processes have been terminated."
fi

# Kill auth_server.py and api_server.py as Waitress processes
for SCRIPT_NAME in "auth_server.py" "api_server.py"; do
    PIDS=$(ps aux | grep waitress | grep "$SCRIPT_NAME" | grep -v grep | awk '{print $2}')
    if [ -z "$PIDS" ]; then
        echo "No Waitress processes found for: $SCRIPT_NAME"
        continue
    fi
    echo "Killing Waitress processes for: $SCRIPT_NAME"
    for PID in $PIDS; do
        echo "Killing PID: $PID"
        kill -9 $PID
    done
    echo "All Waitress processes for $SCRIPT_NAME have been terminated."
done
