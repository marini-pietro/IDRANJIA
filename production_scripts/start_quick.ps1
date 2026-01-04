# Add this as the first line
Set-Location ..  # Move to the parent directory (project root) so waitress can find the scripts
Start-Process -FilePath "python" -ArgumentList "log_server.py" -NoNewWindow
Start-Process -FilePath "python" -ArgumentList "auth_server.py" -NoNewWindow
Start-Process -FilePath "python" -ArgumentList "api_server.py" -NoNewWindow