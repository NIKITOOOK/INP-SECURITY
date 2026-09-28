$ErrorActionPreference = 'Stop'
$taskRoot = 'D:\AI-Agent-Security-Lab\workspace-current'
$taskEnv = Join-Path $taskRoot 'labs\00-environment'
$taskStage = Join-Path $taskEnv 'transfer\agt-budgets-a3-20260929'
$taskIso = Join-Path $taskEnv 'agt-budgets-a3-20260929.iso'
if (Test-Path -LiteralPath $taskIso) { throw 'ISO already exists; refusing overwrite' }
if (Test-Path -LiteralPath $taskStage) { throw 'Staging directory already exists; refusing overwrite' }
New-Item -ItemType Directory -Path $taskStage -Force | Out-Null
$taskOriginalRoot = Join-Path $taskRoot 'originals\agt-budgets\upstream'
$taskOriginals = @(Get-ChildItem -LiteralPath $taskOriginalRoot -File -Recurse)
if ($taskOriginals.Count -ne 8) { throw 'Expected exactly eight originals' }
$taskExpected = @{
'reference-implementations/agt/policy/lib/budgets.rego'='77F75D156D38E9B70694C4D0855417BB9E32C019320CE94DCAD43E6577C8C8BD'
'reference-implementations/agt/policy/lib/budgets_test.rego'='1ADC226099FEDE66139A686C18872B87704A6C968192010D5CF4FD60D40F4380'
'reference-implementations/agt/policy/LICENSE-AGT'='7DF20DCDF9197E9945C14858D41C60F11B52B93E5B69E2B63416B874D598D322'
'reference-implementations/agt/agt.lock'='5D2A9C78462240A1B660CE6C97DD7BF81BBB433849DD377352EF3F1C929615AC'
'LICENSING.md'='152605451433C5BD464DB8E3E9DA749CDBEDA2E45951625F22AB8E0FE3567733'
'NOTICE'='E0B1D5583F111AA7A217A4BDFB82CC3BF4F998A82D38679F17E6C7BEBC5C8193'
'LICENSE'='CFC7749B96F63BD31C3C42B5C471BF756814053E847C10F3EB003417BC523D30'
'LICENSE-DOCS'='28A9529C7D0BB4DC51F4BF5C116A3D16EF247A052F7591466768DDF563FD1CF5'
}
foreach ($taskFile in $taskOriginals) {
    $taskRelative = [IO.Path]::GetRelativePath($taskOriginalRoot,$taskFile.FullName).Replace('\','/')
    $taskHash = (Get-FileHash -LiteralPath $taskFile.FullName -Algorithm SHA256).Hash
    if ($taskHash -ne $taskExpected[$taskRelative]) { throw "Original hash mismatch: $taskRelative" }
    $taskDestination = Join-Path $taskStage ('originals\agt-budgets\upstream\' + $taskRelative)
    New-Item -ItemType Directory -Path (Split-Path $taskDestination -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $taskFile.FullName -Destination $taskDestination
    if ((Get-FileHash -LiteralPath $taskDestination -Algorithm SHA256).Hash -ne $taskHash) { throw 'Copy hash mismatch' }
}
$taskInputs = @(Get-ChildItem -LiteralPath (Join-Path $taskRoot 'labs\01-agt-budgets\inputs') -File -Filter '*.json')
if ($taskInputs.Count -ne 4) { throw 'Expected four synthetic inputs' }
$taskInputDestination = Join-Path $taskStage 'labs\01-agt-budgets\inputs'
New-Item -ItemType Directory -Path $taskInputDestination -Force | Out-Null
foreach ($taskInput in $taskInputs) {
    $taskDestination = Join-Path $taskInputDestination $taskInput.Name
    Copy-Item -LiteralPath $taskInput.FullName -Destination $taskDestination
    if ((Get-FileHash -LiteralPath $taskDestination).Hash -ne (Get-FileHash -LiteralPath $taskInput.FullName).Hash) { throw 'Input copy mismatch' }
}
$taskManifest = Get-ChildItem -LiteralPath $taskStage -File -Recurse | Sort-Object FullName | ForEach-Object {
    $taskRelative = [IO.Path]::GetRelativePath($taskStage,$_.FullName).Replace('\','/')
    (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $taskRelative
}
[IO.File]::WriteAllText((Join-Path $taskStage 'SHA256SUMS'), (($taskManifest -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
public static class LabIsoStream {
  public static void Save(object source, string path) {
    IStream stream = (IStream)source;
    STATSTG stat; stream.Stat(out stat, 1);
    byte[] buffer = new byte[65536];
    IntPtr count = System.Runtime.InteropServices.Marshal.AllocHGlobal(4);
    try {
      using (FileStream output = new FileStream(path, FileMode.CreateNew, FileAccess.Write)) {
        long remaining = stat.cbSize;
        while (remaining > 0) {
          int wanted = (int)Math.Min(buffer.Length, remaining);
          stream.Read(buffer, wanted, count);
          int received = System.Runtime.InteropServices.Marshal.ReadInt32(count);
          if (received <= 0) throw new EndOfStreamException();
          output.Write(buffer, 0, received); remaining -= received;
        }
      }
    } finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(count); }
  }
}
'@
$taskImage = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$taskImage.FileSystemsToCreate = 3
$taskImage.VolumeName = 'AGT_A3_20260929'
$taskImage.Root.AddTree($taskStage,$false)
$taskResult = $taskImage.CreateResultImage()
[LabIsoStream]::Save($taskResult.ImageStream,$taskIso)
$taskIsoHash = (Get-FileHash -LiteralPath $taskIso -Algorithm SHA256).Hash
[IO.File]::WriteAllText(($taskIso + '.sha256'),$taskIsoHash.ToLowerInvariant() + '  agt-budgets-a3-20260929.iso' + "`n",[Text.UTF8Encoding]::new($false))
& 'D:\Virtual machine\VBoxManage.exe' controlvm 'd7a65339-5f7e-45ee-ab7a-7de731146389' screenshotpng (Join-Path $taskEnv 'VirtualBox_A3_guest_diagnostics.png')
if ($LASTEXITCODE -ne 0) { throw 'Could not save guest screenshot' }
$taskNote = @'

## Диагностика локальной Ubuntu — 29.09.2026
Исполнитель: агент через VBoxManage keyboardputstring/keyboardputscancode; пользователь вошёл самостоятельно под labuser. Перед каждым вводом или изменением состояния VM предупреждать пользователя в чате, чтобы управление не было неожиданным. Это прямое пожелание пользователя от 29.09.2026.
Факты экрана: id => uid=1000(labuser), группы adm/cdrom/sudo/dip/plugdev/lxd; uname -r => 6.8.0-142-generic; ip -br address => только lo (127.0.0.1/8, ::1/128). IPv4 route get 1.1.1.1, IPv6 route get 2606:4700:4700::1111 и ping -c1 -W2 1.1.1.1 => Network is unreachable. findmnt для vboxsf/nfs/cifs не вывел точек монтирования. Эти наблюдения подтверждают отсутствие обычного внешнего сетевого доступа в текущей конфигурации; абсолютная безопасность гипервизора этим не доказана.
Файл /home/labuser/opa_linux_amd64_static: SHA-256 5eef70644868bb04d0556bcc795ee42f2ab379e73f51d1bfa30f83e1305bc9b9, совпадает с ожидаемым из методички. OPA не исполнялся, версия runtime не подтверждена запуском.
Скриншот: labs/00-environment/VirtualBox_A3_guest_diagnostics.png.
Подготовлен носитель ISO agt-budgets-a3-20260929.iso (ISO9660/Joliet), восемь выбранных оригиналов с проверкой всех ожидаемых SHA-256 и четыре синтетических JSON-входа. Внутри SHA256SUMS. Исходники не изменены и не исполнялись. Подключение ISO, гостевая сверка и принятие A3 пока не выполнены. Тесты A4 не запускались.
'@
Add-Content -LiteralPath (Join-Path $taskRoot 'ПЕРЕДАЧА.md') -Value $taskNote -Encoding utf8
Add-Content -LiteralPath (Join-Path $taskRoot 'logs\Журнал_работ.md') -Value $taskNote -Encoding utf8
$taskNote | Set-Content -LiteralPath (Join-Path $taskEnv 'Протокол_локальной_A3_20260929.md') -Encoding utf8
[pscustomobject]@{ISO=$taskIso;SHA256=$taskIsoHash;Originals=$taskOriginals.Count;Inputs=$taskInputs.Count;Bytes=(Get-Item -LiteralPath $taskIso).Length} | ConvertTo-Json -Compress
