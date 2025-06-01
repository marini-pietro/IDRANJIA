# Define the process names to kill
$processesToKill = @("log_server", "auth_server", "api_server")

# Loop through each process name and attempt to stop it
foreach ($process in $processesToKill) {
    Get-Process -Name $process -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
            Write-Host "Successfully killed process: $process (PID: $($_.Id))" -ForegroundColor Green
        } catch {
            Write-Host "Failed to kill process: $process. It may not be running." -ForegroundColor Yellow
        }
    }
}