param([Parameter(Mandatory)][Guid] $TransferId,
      [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string] $SourceManifestSha256)
$ErrorActionPreference = 'Stop'
$parcelName = 'AI1-C7-' + $TransferId.ToString('N')
$parcel = Join-Path 'C:\Users\Public\Documents' $parcelName
$root = Join-Path 'C:\Program Files' $parcelName
$name = 'AI1C7GuestAuthority'
$user = 'AI1C7GuestClient'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne 'S-1-5-18' -or !(Test-Path -LiteralPath $parcel) -or
    (Get-Item -LiteralPath $parcel).Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 61 }
if (@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'
}).Count) { exit 62 }
if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or
    (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $root)) { exit 63 }

$archive = Join-Path $parcel 'c7-binding.zip'
if ((Get-FileHash -LiteralPath $archive).Hash -ne '9D56A383933EA9D5469A3CE8588262376CDCDFC59438AF6779B3CE2FA85D7500') { exit 64 }
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
function Protect-Directory($Path, $Rules) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($system)
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($item in $Rules) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $item.sid,$item.access,'ContainerInherit,ObjectInherit','None','Allow'))
    }
    [void][IO.Directory]::CreateDirectory($Path,$acl)
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Checkpoint($Label, $Value) {
    [IO.File]::WriteAllText((Join-Path $parcel ($Label+'.code')), [string]$Value)
}
function Invoke-Scm([string[]] $ArgsList) {
    $result = & "$env:SystemRoot\System32\sc.exe" @ArgsList 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "SCM operation failed with exit $code" }
    return $result
}
function Wait-Status($Status, [int] $Seconds) {
    $service = [ServiceProcess.ServiceController]::new($name)
    try { $service.WaitForStatus($Status, [TimeSpan]::FromSeconds($Seconds)) }
    finally { $service.Dispose() }
}

$complete = $false
$created = $false
$createdUser = $false
$phase = 'create-root'
try {
    Protect-Directory $root @(@{sid=$system;access='FullControl'})
    $payload = Join-Path $root 'payload'
    $privateZip = Join-Path $root 'verified.zip'
    [IO.File]::Copy($archive,$privateZip,$false)
    if ((Get-FileHash -LiteralPath $privateZip).Hash -ne '9D56A383933EA9D5469A3CE8588262376CDCDFC59438AF6779B3CE2FA85D7500') { exit 64 }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($privateZip, $payload)
    $manifest = Join-Path $payload 'MANIFEST.json'
    if ((Get-FileHash -LiteralPath $manifest).Hash -ne '9E3363DAA02196EF011ED68BD8335838ED64992AA3854A625A2972D0FDC52E15') { exit 64 }
    foreach ($entry in (Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json).files.PSObject.Properties) {
        if ((Get-FileHash -LiteralPath (Join-Path $payload $entry.Name)).Hash -ne $entry.Value) { exit 64 }
    }
    $sourceManifest = Join-Path $root 'source-pins.json'
    [IO.File]::Copy((Join-Path $parcel 'source-pins.json'),$sourceManifest,$false)
    if ((Get-FileHash -LiteralPath $sourceManifest).Hash -ne $SourceManifestSha256) { exit 64 }
    $pins = Get-Content -LiteralPath $sourceManifest -Raw|ConvertFrom-Json
    foreach ($file in 'scm_service.cs','scm_probe.py','memory_authority_pipe.py') {
        $input = Join-Path $parcel $file
        $target = Join-Path $payload $(if($file -eq 'memory_authority_pipe.py'){'app\'+$file}else{'c7_qualification\'+$file})
        [IO.File]::Copy($input,$target,$false)
        if ((Get-FileHash -LiteralPath $target).Hash -ne $pins.$file) { exit 64 }
    }
    $phase = 'compile'
    $exe = Join-Path $root 'Authority.exe'
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /target:exe /reference:System.ServiceProcess.dll "/out:$exe" (Join-Path $payload 'c7_qualification\scm_service.cs') *> (Join-Path $parcel 'compile.log')
    if ($LASTEXITCODE -ne 0) { throw "Guest C# compiler exit $LASTEXITCODE" }
    Checkpoint compile 42
    Checkpoint binary-sha (Get-FileHash -LiteralPath $exe).Hash
    $phase = 'create-roles'
    $password = ConvertTo-SecureString ("Q!8a"+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $ordinary = New-LocalUser -Name $user -Password $password
    $createdUser = $true
    $credential = [pscredential]::new(".\$user",$password)
    $client = $ordinary.SID
    [void](Invoke-Scm @('create',$name,'type=','own','start=','demand','binpath=',('"\"' + $exe + '\""'),
                'obj=',("NT SERVICE\$name")))
    $created = $true
    $configured = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if ($configured.ImagePath -cne ('"'+$exe+'"') -or $configured.ObjectName -cne "NT SERVICE\$name") {
        throw 'SCM binary path or account differs from the reviewed request'
    }
    [void](Invoke-Scm @('sidtype',$name,'restricted'))
    $kind = Invoke-Scm @('qsidtype',$name)
    if (($kind -join "`n") -notmatch '(?i)RESTRICTED') { throw 'SCM did not confirm restricted SID type' }
    $authority = ([Security.Principal.NTAccount]::new("NT SERVICE\$name")).Translate([Security.Principal.SecurityIdentifier])
    $rule = @{sid=$system;access='FullControl'}
    Protect-Directory $root @($rule,@{sid=$authority;access='ReadAndExecute'},@{sid=$client;access='ReadAndExecute'})
    $state=Join-Path $root 'state'
    $archives=Join-Path $root 'archives'
    Protect-Directory $state @($rule,@{sid=$authority;access='Modify'})
    Protect-Directory $archives @($rule,@{sid=$authority;access='ReadAndExecute'},@{sid=$client;access='ReadAndExecute'})
    [IO.File]::WriteAllText((Join-Path $archives 'archive.synthetic'),'synthetic archive canary')
    @{authority=$authority.Value;client=$client.Value}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'enrollment.json') -Encoding ascii
    $parcelAcl=Get-Acl -LiteralPath $parcel
    $parcelAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($client,'Modify','None','None','Allow'))
    Set-Acl -LiteralPath $parcel -AclObject $parcelAcl
    Checkpoint roles 42
    $py=Join-Path $payload 'runtime\python\python.exe'
    $probe=Join-Path $payload 'c7_qualification\scm_probe.py'
    $phase = 'provision'
    & $py -I -S -B $probe provision *> (Join-Path $parcel 'provision.log')
    if ($LASTEXITCODE -ne 42) { throw "Provision exit $LASTEXITCODE" }
    Checkpoint provision 42
    $phase = 'start'
    [void](Invoke-Scm @('start',$name))
    Wait-Status 'Running' 20
    $first = [int][IO.File]::ReadAllText((Join-Path $state 'ready'))
    Checkpoint start 42
    $phase = 'ipc'
    $common = '-I -S -B "'+$probe+'" '
    $ordinaryProcess = Start-Process -FilePath $py -ArgumentList ($common+'ipc') -WorkingDirectory $parcel -Credential $credential -WindowStyle Hidden -PassThru
    if (!$ordinaryProcess.WaitForExit(10000)) { $ordinaryProcess.Kill(); throw 'Client IPC deadline' }
    Checkpoint ipc $ordinaryProcess.ExitCode
    if ($ordinaryProcess.ExitCode -notin (42,65)) { throw 'Unconfirmed non-elevated client outcome' }
    $phase = 'stop'
    [void](Invoke-Scm @('stop',$name))
    Wait-Status 'Stopped' 15
    if (Get-Process -Id $first -ErrorAction SilentlyContinue) { throw 'First worker still present' }
    Checkpoint stop 42
    $phase = 'restart'
    [void](Invoke-Scm @('start',$name))
    Wait-Status 'Running' 20
    $second = [int][IO.File]::ReadAllText((Join-Path $state 'ready'))
    if ($second -eq $first) { throw 'No new worker observed' }
    Checkpoint restart 42
    $phase = 'crash'
    [IO.File]::WriteAllBytes((Join-Path $state 'crash'), [byte[]]@())
    Wait-Status 'Stopped' 15
    if ((Get-Process -Id $second -ErrorAction SilentlyContinue) -or
        !(Test-Path -LiteralPath (Join-Path $state 'head.sqlite3-journal'))) { throw 'Crash or journal unconfirmed' }
    Checkpoint crash 42
    $phase = 'storage-denials'
    $ordinaryProcess = Start-Process -FilePath $py -ArgumentList ($common+'denied') -WorkingDirectory $parcel -Credential $credential -WindowStyle Hidden -PassThru
    if (!$ordinaryProcess.WaitForExit(10000)) { $ordinaryProcess.Kill(); throw 'Storage canary deadline' }
    Checkpoint storage-denials $ordinaryProcess.ExitCode
    if ($ordinaryProcess.ExitCode -ne 42) { throw 'SCM/storage denial failed' }
    $phase = 'recovery'
    [void](Invoke-Scm @('start',$name))
    Wait-Status 'Running' 20
    $third = [int][IO.File]::ReadAllText((Join-Path $state 'ready'))
    [void](Invoke-Scm @('stop',$name))
    Wait-Status 'Stopped' 15
    if (Get-Process -Id $third -ErrorAction SilentlyContinue) { throw 'Restart worker still present' }
    & $py -I -S -B $probe verify *> (Join-Path $parcel 'verify.log')
    if ($LASTEXITCODE -ne 42) { throw "Recovery verification exit $LASTEXITCODE" }
    Checkpoint recovery 42
    $complete = $true
} catch {
    Checkpoint failed-phase $phase
    [IO.File]::WriteAllText((Join-Path $parcel 'failure.log'), $_.ToString())
} finally {
    if ($created) {
        $status=Get-Service -Name $name
        if ($status.Status -ne 'Stopped') {
            & "$env:SystemRoot\System32\sc.exe" stop $name | Out-Null
            Wait-Status 'Stopped' 15
        }
        [void](Invoke-Scm @('delete',$name))
    }
    if ($createdUser) { Remove-LocalUser -Name $user }
    if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or
        (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) { throw 'Guest cleanup unconfirmed' }
    Checkpoint cleanup 42
}
if($complete){exit 42}
exit 1
