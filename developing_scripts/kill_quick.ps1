# Define the process names to kill
$processesToKill = @("log_server", "auth_server", "api_server")

Write-Host "Checking for processes: $($processesToKill -join ', ')" -ForegroundColor White
foreach ($process in $processesToKill) {
    $found = $false
    Get-Process -Name $process -ErrorAction SilentlyContinue | ForEach-Object {
        $found = $true
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
            Write-Host "Successfully killed process: $process (PID: $($_.Id))" -ForegroundColor Green
        } catch {
            Write-Host "Failed to kill process: $process (PID: $($_.Id))." -ForegroundColor Red
        }
    }
    if (-not $found) {
        Write-Host "No running process found with name: $process" -ForegroundColor Yellow
    }
}