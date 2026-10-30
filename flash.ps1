# Build and flash Presence Lock.
#
# Running firmware shows up as a keyboard + "USB Serial Device" (its own COM port).
# For flashing, the chip has to drop into its ROM bootloader, which appears as a
# different COM port (with a "USB JTAG/serial debug unit" next to it). This script
# does the switch: 1200-baud touch -> wait for the bootloader port -> upload -> reset.
# If it can't find the board, hold BOOT while plugging it in and run it again.

$ErrorActionPreference = 'Stop'
$py = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
Set-Location $PSScriptRoot

function Get-EspPort([string]$interface) {
    $dev = Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -match "VID_303A&PID_1001&$interface" } | Select-Object -First 1
    if ($dev -and $dev.FriendlyName -match '\((COM\d+)\)') { return $Matches[1] }
}

& $py -m platformio run
if ($LASTEXITCODE) { exit $LASTEXITCODE }

$boot = Get-EspPort 'MI_00'
$app = Get-EspPort 'MI_01'
if (-not $boot -or $app) {
    if (-not $app) { throw 'ESP32 not found. Hold BOOT while plugging it in, then run this again.' }
    Write-Host "Asking the firmware on $app to enter the bootloader..."
    $p = New-Object System.IO.Ports.SerialPort $app, 115200
    $p.DtrEnable = $true
    try { $p.Open() } catch { throw "Couldn't open $app - close the settings page or any serial monitor and try again." }
    Start-Sleep -Milliseconds 300; $p.WriteLine('bootloader'); Start-Sleep -Milliseconds 300
    try { $p.Close() } catch {}
    # older firmware only understands the 1200-baud touch
    $p = New-Object System.IO.Ports.SerialPort $app, 1200
    try { $p.Open(); Start-Sleep -Milliseconds 300; $p.Close() } catch {}
    $boot = $null
    for ($i = 0; $i -lt 60 -and -not $boot; $i++) {  # Windows can take 10-20 s to re-enumerate
        Start-Sleep -Milliseconds 500
        if (-not (Get-EspPort 'MI_01')) { $boot = Get-EspPort 'MI_00' }
    }
    if (-not $boot) { throw 'Bootloader port did not appear. Hold BOOT while plugging it in, then run this again.' }
}

Write-Host "Flashing via bootloader port $boot"
& $py -m platformio run -t upload --upload-port $boot
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $py -m esptool --port $boot --after hard-reset chip-id | Out-Null

Start-Sleep -Seconds 5
$app = Get-EspPort 'MI_01'
Write-Host "Done. Firmware is running on $app"
