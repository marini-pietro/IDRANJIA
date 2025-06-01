#!/bin/bash
python3 ../log_server.py &
python3 ../auth_server.py &
python3 ../api_server.py &
wait