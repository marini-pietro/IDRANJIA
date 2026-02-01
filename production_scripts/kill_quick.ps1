# Microservices Process Killer - Improved Version
Write-Host "Stopping microservices..." -ForegroundColor Yellow

# Define all services
$services = @(
    @{ Name = "log_server"; Script = "log_server.py" },
    @{ Name = "auth_server"; Script = "auth_server.py" },
    @{ Name = "api_server"; Script = "api_server.py" }
)

foreach ($service in $services) {
    $scriptName = $service.Script
    $found = $false
    
    # Find processes by command line (more reliable than process name)
    $processes = Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%$scriptName%'"
    
    if ($processes) {
        foreach ($proc in $processes) {
            $found = $true
            $pid = $proc.ProcessId
            $cmdLine = $proc.CommandLine
            
            try {
                Stop-Process -Id $pid -Force -ErrorAction Stop
                Write-Host "Killed $scriptName (PID: $pid)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to kill $scriptName (PID: $pid): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    if (-not $found) {
        Write-Host "~ No process found for $scriptName" -ForegroundColor Gray
    }
}