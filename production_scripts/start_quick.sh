#!/bin/bash
cd .. # Move to the parent directory (project root) so waitress can find the scripts
python3 ../log_server.py &
python3 ../auth_server.py &
python3 ../api_server.py &
wait