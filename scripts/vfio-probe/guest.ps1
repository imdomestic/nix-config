param([int]$DelaySeconds = 60, [switch]$Graphics)
$ErrorActionPreference = 'Stop'
function Invoke-GraphicsProbe {
    $exe = 'C:\IntelDrivers\vfio-d3d-probe.exe'
    $p = New-Object System.Diagnostics.Process
    try {
        $p.StartInfo.FileName = $exe
        $p.StartInfo.UseShellExecute = $false
        $p.StartInfo.CreateNoWindow = $true
        $p.StartInfo.RedirectStandardOutput = $true
        $p.StartInfo.RedirectStandardError = $true
        $null = $p.Start()
        $stdout = $p.StandardOutput.ReadToEndAsync()
        $stderr = $p.StandardError.ReadToEndAsync()
        $finished = $p.WaitForExit(60000)
        if (-not $finished) { $p.Kill(); $p.WaitForExit() }
        [ordered]@{
            timedOut = -not $finished
            exitCode = $p.ExitCode
            stdout = $stdout.Result
            stderr = $stderr.Result
        }
    } catch { [ordered]@{ error = $_.Exception.Message } }
    finally { $p.Dispose() }
}
try {
    Start-Sleep -Seconds $DelaySeconds
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $intel = @(Get-PnpDevice -Class Display -PresentOnly | Where-Object InstanceId -like 'PCI\VEN_8086*')
    $report = [ordered]@{
        time = (Get-Date).ToString('o')
        operatingSystem = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime
        hypervisorPresent = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
        deviceGuard = $(try {
            Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
        } catch { $_.Exception.Message })
        display = @(Get-CimInstance Win32_VideoController | Select-Object Name, PNPDeviceID, DriverVersion, Status, ConfigManagerErrorCode, CurrentHorizontalResolution, CurrentVerticalResolution)
        problems = @(Get-CimInstance Win32_PnPEntity | Where-Object ConfigManagerErrorCode -ne 0 | Select-Object Name, PNPDeviceID, ConfigManagerErrorCode)
        drivers = (& pnputil.exe /enum-devices /class Display /drivers | Out-String)
        displayDriverStore = $(try {
            @(Get-WindowsDriver -Online -All | Where-Object ClassName -eq 'Display' | Select-Object Driver, OriginalFileName, ProviderName, Version)
        } catch { $_.Exception.Message })
        intelProperties = @($intel | ForEach-Object {
            Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_ProblemStatus,DEVPKEY_Device_ProblemCode,DEVPKEY_Device_DriverInfPath -ErrorAction SilentlyContinue | Select-Object InstanceId, KeyName, Type, Data
        })
        events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $boot; Level = @(1,2,3) } -MaxEvents 40 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message)
        graphicsEvents = @(foreach ($log in @('Microsoft-Windows-DxgKrnl-Admin', 'Microsoft-Windows-Kernel-PnP/Configuration')) {
            try {
                Get-WinEvent -LogName $log -MaxEvents 100 -ErrorAction Stop | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message
            } catch {
                [pscustomobject]@{ LogName = $log; QueryError = $_.Exception.Message }
            }
        })
        graphicsLogs = @(Get-WinEvent -ListLog '*Dxg*','*Kernel-PnP*' -ErrorAction SilentlyContinue | Select-Object LogName, IsEnabled, RecordCount)
        secureBoot = $(try { Confirm-SecureBootUEFI } catch { $_.Exception.Message })
    }
    if ($Graphics) { $report.d3d = Invoke-GraphicsProbe }
    $body = $report | ConvertTo-Json -Depth 5
    $body | Set-Content -Encoding UTF8 C:\IntelDrivers\vfio-report.json
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        try {
            Invoke-RestMethod -Uri http://192.168.178.1:8765/report -Method Post -ContentType 'application/json' -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 10 | Out-Null
            break
        } catch {
            Start-Sleep -Seconds 10
        }
    }
} finally {
    & schtasks.exe /Delete /TN VFIOProbe /F
}
