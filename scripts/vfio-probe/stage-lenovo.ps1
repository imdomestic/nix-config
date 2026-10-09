param([Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ArchiveSHA256)
$ErrorActionPreference = 'Stop'
$archive = 'C:\IntelDrivers\LenovoGraphics.zip'
$destination = 'C:\IntelDrivers\Lenovo7026'
Start-Transcript -Path C:\IntelDrivers\stage-lenovo.log -Force
try {
    if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $ArchiveSHA256) {
        throw 'Lenovo archive checksum mismatch'
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
    $graphics = Join-Path $destination 'Graphics'
    $inf = Join-Path $graphics 'iigd_dch.inf'
    $contents = Get-Content -LiteralPath $inf -Raw
    if (!$contents.Contains('32.0.101.7026') -or !$contents.Contains('PCI\VEN_8086&DEV_64A0&SUBSYS_383E17AA')) {
        throw 'Unexpected OEM version or hardware support'
    }
    foreach ($catalog in @('igdlh.cat', 'extinf_i.cat')) {
        $signature = Get-AuthenticodeSignature (Join-Path $graphics $catalog)
        $signature | Select-Object Path, Status, StatusMessage
        if ($signature.Status -ne 'Valid') { throw "Invalid signature: $catalog" }
    }
    $old = Get-WindowsDriver -Online -Driver oem9.inf
    if ($old.Version -ne '32.0.101.9033' -or (Split-Path $old.OriginalFileName -Leaf) -ne 'iigd_dch.inf') {
        throw 'oem9.inf is not the expected previous driver; leaving it installed'
    }
    New-Item -ItemType Directory -Path C:\IntelDrivers\Backup9033 -Force | Out-Null
    & pnputil.exe /export-driver oem9.inf C:\IntelDrivers\Backup9033
    if ($LASTEXITCODE -ne 0) { throw 'Previous driver backup failed' }
    foreach ($file in @('iigd_dch.inf', 'iigd_ext.inf')) {
        & pnputil.exe /add-driver (Join-Path $graphics $file)
        if ($LASTEXITCODE -ne 0) { throw "OEM driver staging failed: $file" }
    }
    # Remove the newer main driver only after both signed OEM packages are staged.
    & pnputil.exe /delete-driver oem9.inf /uninstall
    if ($LASTEXITCODE -notin @(0, 3010)) { throw 'Previous driver removal failed' }
    Get-WindowsDriver -Online -All | Where-Object ClassName -eq 'Display' | Format-Table Driver, ProviderName, Version
    Write-Output 'LENOVO_7026_STAGED'
} finally {
    Stop-Transcript
}
