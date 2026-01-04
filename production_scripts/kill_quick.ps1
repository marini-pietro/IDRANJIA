# Kill log_server.py as a normal Python process
$logProcs = Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.CommandLine -match "log_server.py" }
if ($logProcs) {
    foreach ($proc in $logProcs) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Host "Successfully killed log_server.py (PID: $($proc.Id))" -ForegroundColor Green
        } catch {
            Write-Host "Failed to kill log_server.py (PID: $($proc.Id))." -ForegroundColor Red
        }
    }
} else {
    Write-Host "No running process found for log_server.py" -ForegroundColor Yellow
}

# Kill auth_server and api_server as Waitress processes
$waitressScripts = @("auth_server.py", "api_server.py")
foreach ($script in $waitressScripts) {
    $found = $false
    $procs = Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -match "waitress" -and $_.CommandLine -match [regex]::Escape($script)
    }
    foreach ($proc in $procs) {
        $found = $true
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            Write-Host "Successfully killed Waitress process for: $script (PID: $($proc.ProcessId))" -ForegroundColor Green
        } catch {
            Write-Host "Failed to kill Waitress process for: $script (PID: $($proc.ProcessId))." -ForegroundColor Red
        }
    }
    if (-not $found) {
        Write-Host "No running Waitress process found for: $script" -ForegroundColor Yellow
    }
}