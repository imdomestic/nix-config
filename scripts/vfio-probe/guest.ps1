$ErrorActionPreference = 'Stop'
try {
    Start-Sleep -Seconds 60
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $intel = @(Get-PnpDevice -Class Display -PresentOnly | Where-Object InstanceId -like 'PCI\VEN_8086*')
    $report = [ordered]@{
        time = (Get-Date).ToString('o')
        display = @(Get-CimInstance Win32_VideoController | Select-Object Name, PNPDeviceID, DriverVersion, Status, ConfigManagerErrorCode, CurrentHorizontalResolution, CurrentVerticalResolution)
        problems = @(Get-CimInstance Win32_PnPEntity | Where-Object ConfigManagerErrorCode -ne 0 | Select-Object Name, PNPDeviceID, ConfigManagerErrorCode)
        drivers = (& pnputil.exe /enum-devices /class Display /drivers | Out-String)
        intelProperties = @($intel | ForEach-Object {
            Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_ProblemStatus,DEVPKEY_Device_ProblemCode,DEVPKEY_Device_DriverInfPath -ErrorAction SilentlyContinue | Select-Object InstanceId, KeyName, Type, Data
        })
        events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $boot; Level = @(1,2,3) } -MaxEvents 40 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message)
    }
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
