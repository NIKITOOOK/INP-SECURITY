[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Linux', 'Windows11')]
    [string]$Guest,
    [switch]$Create
)

$ErrorActionPreference = 'Stop'
$vbox = 'D:\Virtual machine\VBoxManage.exe'
$vmBase = 'D:\AI-Agent-Security-Lab\vms'
$vmName = "AI-Policy-Lab-$Guest"
$vmDirectory = Join-Path $vmBase $vmName
$vmDisk = Join-Path $vmDirectory 'system.vdi'
$vmId = [guid]::NewGuid().ToString()
if (-not (Test-Path -LiteralPath $vbox -PathType Leaf)) { throw 'VirtualBox executable not found.' }
if (-not [IO.Path]::GetFullPath($vmDirectory).StartsWith($vmBase + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'VM target is outside the lab.'
}
if (Test-Path -LiteralPath $vmDirectory) { throw "VM directory already exists: $vmDirectory" }
$registered = & $vbox list vms
if ($LASTEXITCODE -ne 0) { throw 'Cannot query registered VMs.' }
if ($registered | Where-Object { $_.StartsWith('"' + $vmName + '" ') }) { throw 'VM name is already registered.' }

$osType = if ($Guest -eq 'Linux') { 'Debian_64' } else { 'Windows11_64' }
$diskSize = if ($Guest -eq 'Linux') { '49152' } else { '65536' }
$graphics = if ($Guest -eq 'Linux') { 'vmsvga' } else { 'vboxsvga' }
$steps = [System.Collections.Generic.List[object]]::new()
$steps.Add(@('createvm', '--name', $vmName, '--platform-architecture', 'x86', '--basefolder', $vmBase,
    '--ostype', $osType, '--uuid', $vmId, '--register'))
$steps.Add(@('modifyvm', $vmId, '--memory', '4096', '--cpus', '2', '--vram', '32',
    '--graphicscontroller', $graphics, '--ioapic', 'on', '--boot1', 'dvd', '--boot2', 'disk',
    '--boot3', 'none', '--boot4', 'none', '--clipboard-mode', 'disabled',
    '--clipboard-file-transfers', 'disabled', '--drag-and-drop', 'disabled',
    '--audio-enabled', 'off', '--usb-ohci', 'off', '--usb-ehci', 'off', '--usb-xhci', 'off',
    '--vrde', 'off', '--accelerate-3d', 'off', '--nested-hw-virt', 'off', '--autostart-enabled', 'off',
    '--nic1', 'none', '--nic2', 'none', '--nic3', 'none', '--nic4', 'none',
    '--nic5', 'none', '--nic6', 'none', '--nic7', 'none', '--nic8', 'none'))
if ($Guest -eq 'Windows11') {
    $steps.Add(@('modifyvm', $vmId, '--firmware', 'efi', '--tpm-type', '2.0'))
}
$steps.Add(@('createmedium', 'disk', '--filename', $vmDisk, '--size', $diskSize, '--format', 'VDI', '--variant', 'Standard'))
$steps.Add(@('storagectl', $vmId, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci', '--portcount', '2', '--bootable', 'on'))
$steps.Add(@('storageattach', $vmId, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', $vmDisk))
$steps.Add(@('storageattach', $vmId, '--storagectl', 'SATA', '--port', '1', '--device', '0', '--type', 'dvddrive', '--medium', 'emptydrive'))

if (-not $Create) {
    [pscustomobject]@{
        Mode = 'PreviewOnly'
        Name = $vmName
        Directory = $vmDirectory
        Guest = $Guest
        MemoryMB = 4096
        CPUs = 2
        DiskMB = [int]$diskSize
        Network = 'All adapters disabled'
        SharedFolders = 'None'
        StartsVM = $false
        Steps = $steps
    } | ConvertTo-Json -Depth 5
    return
}

# Explicit new targets only. Never modify, clone or remove existing user VMs.
New-Item -ItemType Directory -Path $vmBase -Force | Out-Null
foreach ($step in $steps) {
    & $vbox @step
    if ($LASTEXITCODE -ne 0) {
        throw "Creation stopped at $($step[0]); partial VM left for inspection. UUID: $vmId"
    }
}
& $vbox showvminfo $vmId --machinereadable
if ($LASTEXITCODE -ne 0) { throw 'Cannot verify the created VM.' }
Write-Output 'VM created powered off, without guest OS or network. No software has been installed.'
