Start-Process -FilePath "python" -ArgumentList "log_server.py" -NoNewWindow
Start-Process -FilePath "python" -ArgumentList "auth_server.py" -NoNewWindow
Start-Process -FilePath "python" -ArgumentList "api_server.py" -NoNewWindow