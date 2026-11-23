param([Parameter(Mandatory)][Guid] $TransferId,
      [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string] $SourceManifestSha256,
      [ValidateSet('high','medium')][string] $Profile='high',
      [switch] $EndToEnd,
      [switch] $WriteProfile,
      [switch] $WriteHttp)
$ErrorActionPreference = 'Stop'
$parcelName = 'AI1-C7-' + $TransferId.ToString('N')
$parcel = Join-Path 'C:\Users\Public\Documents' $parcelName
$root = Join-Path 'C:\Program Files' $parcelName
$name = 'AI1MemoryAuthority'
$user = 'AI1C7OrdinaryProbe'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne 'S-1-5-18' -or !(Test-Path -LiteralPath $parcel) -or
    (Get-Item -LiteralPath $parcel).Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 61 }
if (@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'
}).Count) { exit 62 }
if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $root)) { exit 63 }
$bridge = Get-Content -LiteralPath (Join-Path $parcel 'bridge-ready.json') -Raw|ConvertFrom-Json
$ordinary = Get-LocalUser -Name $user
if($bridge.preflight -ne 42 -or !$ordinary.Enabled -or $ordinary.SID.Value -ne $bridge.sid){exit 67}
$client = $ordinary.SID
if (($EndToEnd -or $WriteProfile) -and $Profile -ne 'medium') { exit 68 }
if ($EndToEnd -and $WriteProfile) { exit 69 }
if ($WriteHttp -and !$WriteProfile) { exit 69 }

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
    $files = @('scm_service.cs','scm_probe.py','memory_authority_pipe.py')
    if ($EndToEnd) { $files += 'scm_dpapi_e2e.py' }
    if ($WriteProfile) {
        $files += @('scm_write_probe.py','memory_service_pipe.py','memory_write_v2.py',
                    'windows_storage_inspector.py','memory_windows_archive.py','memory_service_http.py',
                    'memory_launch_v2.py','main.py','start.py')
    }
    if ($WriteHttp) { $files += @('scm_http_probe.py','scm_recovery_probe.py') }
    foreach ($file in $files) {
        $input = Join-Path $parcel $file
        $isApp=$file -in ('memory_authority_pipe.py','memory_service_pipe.py','memory_write_v2.py',
                        'windows_storage_inspector.py','memory_windows_archive.py','memory_service_http.py',
                        'memory_launch_v2.py','main.py','start.py')
        $target = Join-Path $payload $(if($isApp){'app\'+$file}else{'c7_qualification\'+$file})
        [IO.File]::Copy($input,$target,($WriteProfile -and $isApp))
        if ((Get-FileHash -LiteralPath $target).Hash -ne $pins.$file) { exit 64 }
    }
    if ($EndToEnd -or $WriteProfile) {
        $dependency = Join-Path $parcel 'dotenv-addon.zip'
        if ((Get-FileHash -LiteralPath $dependency).Hash -ne 'FF8F3C00CAA41A26A3C5328653E55AFF70F079E078518082C50D2A946AEA401E') { exit 64 }
        $deps = Join-Path $payload 'deps'
        [IO.Compression.ZipFile]::ExtractToDirectory($dependency,$deps)
        foreach ($wheel in (Get-ChildItem -LiteralPath (Join-Path $payload 'wheels') -Filter '*.whl')) {
            $entries = [IO.Compression.ZipFile]::OpenRead($wheel.FullName)
            try {
                foreach ($entry in $entries.Entries) {
                    if (!$entry.Name) { continue }
                    if ($entry.FullName -cnotmatch '^[a-zA-Z0-9_./+\-]+$' -or
                        $entry.FullName.Contains('..') -or $entry.FullName.StartsWith('/')) { exit 64 }
                    $destination = Join-Path $deps $entry.FullName
                    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$destination,$false)
                }
            } finally { $entries.Dispose() }
        }
        foreach ($pin in $pins.application.PSObject.Properties) {
            if ((Get-FileHash -LiteralPath (Join-Path $payload $pin.Name)).Hash -ne $pin.Value) { exit 64 }
        }
        Checkpoint application-pins 42
    }
    $phase = 'compile'
    $exe = Join-Path $root 'Authority.exe'
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $compiler /nologo /target:exe /reference:System.ServiceProcess.dll "/out:$exe" (Join-Path $payload 'c7_qualification\scm_service.cs') *> (Join-Path $parcel 'compile.log')
    if ($LASTEXITCODE -ne 0) { throw "Guest C# compiler exit $LASTEXITCODE" }
    Checkpoint compile 42
    Checkpoint binary-sha (Get-FileHash -LiteralPath $exe).Hash
    $phase = 'create-roles'
    $py=Join-Path $payload 'runtime\python\python.exe'
    $probe=Join-Path $payload 'c7_qualification\scm_probe.py'
    $ErrorActionPreference='Continue'
    & $py -I -S -B $probe register *> (Join-Path $parcel 'registration.log')
    $registration=$LASTEXITCODE
    $ErrorActionPreference='Stop'
    if ($registration -ne 42) { throw "SCM native registration exit $registration" }
    $created = $true
    $configured = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    if ($configured.ImagePath -cne ('"'+$exe+'"') -or $configured.ObjectName -cne "NT SERVICE\$name") {
        throw 'SCM binary path or account differs from the reviewed request'
    }
    if ($configured.ServiceSidType -ne 3) { throw 'SCM did not confirm restricted SID type' }
    Checkpoint scm-registration 42
    $authority = ([Security.Principal.NTAccount]::new("NT SERVICE\$name")).Translate([Security.Principal.SecurityIdentifier])
    $rule = @{sid=$system;access='FullControl'}
    Protect-Directory $root @($rule,@{sid=$authority;access='ReadAndExecute'},@{sid=$client;access='ReadAndExecute'})
    $state=Join-Path $root 'state'
    $archives=Join-Path $root 'archives'
    Protect-Directory $state @($rule,@{sid=$authority;access='Modify'})
    Protect-Directory $archives @($rule,@{sid=$authority;access='ReadAndExecute'},@{sid=$client;access='ReadAndExecute'})
    [IO.File]::WriteAllText((Join-Path $archives 'archive.synthetic'),'synthetic archive canary')
    $integrity=if($Profile -eq 'medium'){8192}else{12288}
    $enrollment=@{authority=$authority.Value;client=$client.Value;integrity=$integrity}
    if($WriteProfile){$enrollment.write_fixture=$true}
    if($WriteHttp){$enrollment.http_fixture=$true}
    $enrollment|
        ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'enrollment.json') -Encoding ascii
    $clientScratch = Join-Path $parcel 'ordinary'
    Protect-Directory $clientScratch @($rule,@{sid=$client;access='Modify'})
    if ($EndToEnd) {
        # The client must inspect the pinned parent handle. Keep the grant on
        # this directory only so bridge requests and protected inputs stay private.
        $parcelAcl = Get-Acl -LiteralPath $parcel
        $parcelAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $client,'ReadAndExecute','None','None','Allow'))
        Set-Acl -LiteralPath $parcel -AclObject $parcelAcl
    }
    Checkpoint roles 42
    function Invoke-Ordinary([string] $Action) {
        $request=Join-Path $parcel ($Action+'.request')
        $reply=Join-Path $parcel ($Action+'.reply')
        [IO.File]::WriteAllBytes($request,[byte[]]@())
        $deadline=[DateTime]::UtcNow.AddSeconds(22)
        while(!(Test-Path -LiteralPath $reply)){
            if([DateTime]::UtcNow -gt $deadline){throw 'Ordinary bridge deadline'}
            Start-Sleep -Milliseconds 150
        }
        $result=[int][IO.File]::ReadAllText($reply)
        $output=Join-Path $clientScratch ($Action+'.json')
        if(!(Test-Path -LiteralPath $output)){throw "Ordinary canary receipt unavailable: $result"}
        $receipt=Get-Content -LiteralPath $output -Raw|ConvertFrom-Json
        if((Get-Process -Id $receipt.pid -ErrorAction SilentlyContinue) -or $receipt.code -ne $result -or
           $receipt.token.integrity -ne 8192 -or $receipt.token.elevated -or $receipt.token.sid -ne $client.Value){
            throw 'Ordinary native identity or process receipt mismatch'
        }
        return $result
    }
    if ($WriteProfile) {
        $phase = 'write-start'
        [IO.File]::WriteAllBytes((Join-Path $state 'initialize-write'),[byte[]]@())
        [void](Invoke-Scm @('start',$name))
        Wait-Status 'Running' 20
        $first=[int][IO.File]::ReadAllText((Join-Path $state 'ready'))
        Checkpoint write-start 42
        $phase = 'write'
        if ((Invoke-Ordinary write) -ne 42) { throw 'Create/role/stale/replay or storage denial failed' }
        Checkpoint write 42
        & $py -I -S -B $probe wrong-peer *> (Join-Path $parcel 'wrong-peer.log')
        if($LASTEXITCODE -ne 42){throw 'Foreign SID denial failed'}
        Checkpoint wrong-peer 42
        [void](Invoke-Scm @('stop',$name))
        Wait-Status 'Stopped' 15
        if(Get-Process -Id $first -ErrorAction SilentlyContinue){throw 'First write worker still present'}
        Checkpoint write-stop 42
        if ($WriteHttp) {
            $phase='backup'
            & $py -I -S -B $probe snapshot *> (Join-Path $parcel 'snapshot.log')
            if($LASTEXITCODE -ne 42){throw 'Offline archive snapshot failed'}
            Checkpoint backup 42
            $profileFacts = Get-Content -LiteralPath (Join-Path $state 'profile-location.json') -Raw|ConvertFrom-Json
            $dedicated=@(
              "C:\Windows\ServiceProfiles\$name\AppData\Roaming\Microsoft\Protect\$($authority.Value)",
              "C:\Users\$name\AppData\Roaming\Microsoft\Protect\$($authority.Value)"
            )
            if($profileFacts.sid -eq $authority.Value -and $profileFacts.resolve_hresult -eq 0 -and
               $profileFacts.key_root -in $dedicated -and (Test-Path -LiteralPath $profileFacts.key_root -PathType Container)) {
                Checkpoint profile-location 42
                $phase='profile-backup'
                & $py -I -S -B $probe snapshot-profile *> (Join-Path $parcel 'profile-snapshot.log')
                if($LASTEXITCODE -ne 42){throw 'Dedicated profile snapshot was refused'}
                $keyRoot=[IO.Path]::GetFullPath($profileFacts.key_root)
                if($keyRoot -notin $dedicated){throw 'Unexpected profile key root'}
                $revisionTag='.AI1-qualification-'+$TransferId.ToString('N')
                $quarantine=$keyRoot+$revisionTag+'-held'
                $recreated=$keyRoot+$revisionTag+'-recreated'
                if((Test-Path -LiteralPath $quarantine) -or (Test-Path -LiteralPath $recreated)){
                    throw 'Profile trial staging already exists'
                }
                $keyAcl=Get-Acl -LiteralPath $keyRoot
                $securitySections=[Security.AccessControl.AccessControlSections]'Owner,Group,Access'
                $keySecurity=$keyAcl.GetSecurityDescriptorSddlForm($securitySections)
                $profilePins=(Get-Content -LiteralPath (Join-Path $state 'profile-backup-pins.json') -Raw|ConvertFrom-Json).PSObject.Properties
                $fileAcls=@{}
                foreach($member in $profilePins){
                    $original=Join-Path $keyRoot $member.Name
                    if((Get-FileHash -LiteralPath $original).Hash -ne $member.Value){throw 'Profile bytes changed before trial'}
                    $fileAcls[$member.Name]=(Get-Acl -LiteralPath $original).GetSecurityDescriptorSddlForm($securitySections)
                }
                @{root=$keySecurity;files=$fileAcls}|ConvertTo-Json -Depth 4 |
                    Set-Content -LiteralPath (Join-Path $state 'profile-security.json') -Encoding ascii
                Checkpoint profile-backup 42
                $phase='profile-missing'
                [IO.Directory]::Move($keyRoot,$quarantine)
                try {
                    $startupFailure=$false
                    try {
                        [void](Invoke-Scm @('start',$name))
                        Wait-Status 'Running' 20
                    } catch { $startupFailure=$true }
                    $currentService=Get-Service -Name $name
                    if($currentService.Status -ne 'Stopped'){
                        [void](Invoke-Scm @('stop',$name))
                        Wait-Status 'Stopped' 15
                    }
                    $failureLog=Join-Path $state 'worker-failure.log'
                    if($startupFailure -and (Test-Path -LiteralPath $failureLog) -and
                       ([IO.File]::ReadAllText($failureLog) -match 'ArchiveUnavailable: archive_unavailable')){
                        Checkpoint profile-missing 42
                    } else {
                        Checkpoint profile-missing 65
                    }
                } finally {
                    $phase='profile-copy-back'
                    if((Get-Service -Name $name).Status -ne 'Stopped'){throw 'Cannot restore with the service active'}
                    if(Test-Path -LiteralPath $keyRoot){
                        if((Get-Item -LiteralPath $keyRoot).Attributes -band [IO.FileAttributes]::ReparsePoint){
                            throw 'Unexpected recreated profile link'
                        }
                        [IO.Directory]::Move($keyRoot,$recreated)
                    }
                    & $py -I -S -B $probe restore-profile *> (Join-Path $parcel 'profile-restore.log')
                    if($LASTEXITCODE -ne 42){throw 'Backup operator could not restore the admitted profile'}
                    if((Get-Acl -LiteralPath $keyRoot).GetSecurityDescriptorSddlForm($securitySections) -cne $keySecurity){
                        throw 'Profile directory descriptor changed'
                    }
                    foreach($member in $profilePins){
                        $destination=Join-Path $keyRoot $member.Name
                        if((Get-FileHash -LiteralPath $destination).Hash -ne $member.Value){throw 'Profile restore pin mismatch'}
                        if((Get-Acl -LiteralPath $destination).GetSecurityDescriptorSddlForm($securitySections) -cne $fileAcls[$member.Name]){
                            throw 'Profile file descriptor changed'
                        }
                    }
                    Checkpoint profile-copy-back 42
                }
            } else {
                Checkpoint profile-location 65
            }
        }
        $phase = 'resume'
        [void](Invoke-Scm @('start',$name))
        Wait-Status 'Running' 20
        $second=[int][IO.File]::ReadAllText((Join-Path $state 'ready'))
        if($second -eq $first){throw 'No new service worker observed'}
        if ($WriteHttp) {
            if([IO.File]::ReadAllText((Join-Path $state 'verified-restore')) -cne 'ok'){
                throw 'Restored candidate was not validated by the new service process'
            }
            Checkpoint restore-same-profile 42
            if(Test-Path -LiteralPath (Join-Path $parcel 'profile-copy-back.code')) {
                Checkpoint restore-from-profile-copy 42
            }
        }
        [IO.File]::WriteAllBytes((Join-Path $state 'lose-write-ack'),[byte[]]@())
        if((Invoke-Ordinary resume) -ne 42){throw 'Restarted read or interrupted delete not confirmed'}
        Wait-Status 'Stopped' 15
        if(Get-Process -Id $second -ErrorAction SilentlyContinue){throw 'Crashed worker still present'}
        Checkpoint resume 42
        $phase = 'verify-write'
        [void](Invoke-Scm @('start',$name))
        Wait-Status 'Running' 20
        $third=[int][IO.File]::ReadAllText((Join-Path $state 'ready'))
        if($third -in ($first,$second) -or (Invoke-Ordinary verify-write) -ne 42) {
            throw 'Post-crash receipt or deletion unconfirmed'
        }
        Checkpoint verify-write 42
        [void](Invoke-Scm @('stop',$name))
        Wait-Status 'Stopped' 15
        if(Get-Process -Id $third -ErrorAction SilentlyContinue){throw 'Last write worker still present'}
        Checkpoint write-final-stop 42
        $complete=$true
        exit 42
    }
    if ($EndToEnd) {
        $phase = 'archive-enrollment'
        if ((Invoke-Ordinary e2e-seal) -ne 42) { throw 'Standard user DPAPI sealing failed' }
        $approved = Get-Content -LiteralPath (Join-Path $clientScratch 'dpapi-enrollment.json') -Raw|ConvertFrom-Json
        if ($approved.generation -cne '635f83dd-3bb7-4041-b4c8-7d39cb25d13a' -or
            $approved.current -cnotmatch '^[a-f0-9]{64}$' -or $approved.previous -cnotmatch '^[a-f0-9]{64}$' -or
            $approved.canary -cnotmatch '^[a-f0-9]{64}$' -or $approved.current -ceq $approved.previous) {
            throw 'Unexpected synthetic enrollment'
        }
        $copy = Join-Path $archives 'dpapi-current.v2a'
        [IO.File]::Copy((Join-Path $clientScratch ('dpapi-archives\memory-'+$approved.current+'.v2a')),$copy,$false)
        $canary = Join-Path $archives 'dpapi-canary.bin'
        [IO.File]::Copy((Join-Path $clientScratch 'dpapi-canary.bin'),$canary,$false)
        if ((Get-FileHash -LiteralPath $copy).Hash -ne $approved.current -or
            (Get-FileHash -LiteralPath $canary).Hash -ne $approved.canary) { throw 'DPAPI fixture digest mismatch' }
        $enrollment.dpapi = $approved
        $enrollment|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $root 'enrollment.json') -Encoding ascii
        Checkpoint archive-enrollment 42
    }
    $phase = 'provision'
    & $py -I -S -B $probe provision *> (Join-Path $parcel 'provision.log')
    if ($LASTEXITCODE -ne 42) { throw "Provision exit $LASTEXITCODE" }
    Checkpoint provision 42
    $phase = 'ordinary-preflight'
    Checkpoint ordinary-preflight 42
    $phase = 'start'
    [void](Invoke-Scm @('start',$name))
    Wait-Status 'Running' 20
    $first = [int][IO.File]::ReadAllText((Join-Path $state 'ready'))
    Checkpoint start 42
    if ($EndToEnd) {
        $phase = 'dpapi-boundary'
        $deniedCode = [int][IO.File]::ReadAllText((Join-Path $state 'dpapi-boundary.code'))
        if ($deniedCode -eq 0) { throw 'Authority DPAPI denial unconfirmed' }
        Checkpoint dpapi-boundary 42
        [IO.File]::WriteAllText((Join-Path $parcel 'dpapi-native-error.txt'), [string]$deniedCode)
        $phase = 'e2e-live'
        if ((Invoke-Ordinary e2e-live) -ne 42) { throw 'LOCAL and archive checks failed' }
        $checkLabels = Get-Content -LiteralPath (Join-Path $clientScratch 'e2e-live-checks.json') -Raw|ConvertFrom-Json
        if (($checkLabels -join ':') -cne 'e2e-live:wrong-generation:corrupt:stale:replaced-path:e2e-restored') { throw 'Archive check coverage mismatch' }
        foreach ($label in $checkLabels) { Checkpoint $label 42 }
    }
    $phase = 'ipc'
    $ordinaryAvailable = $false
    try {
        $ordinaryCode = Invoke-Ordinary ipc
        if ($ordinaryCode -notin (42,65)) { throw 'Unconfirmed non-elevated client outcome' }
        Checkpoint ipc $ordinaryCode
        $ordinaryAvailable = $true
    } catch {
        Checkpoint client-unqualified 97
        [IO.File]::WriteAllText((Join-Path $parcel 'client-unqualified.log'), $_.ToString())
    }
    if ($Profile -eq 'medium') {
        if (!$ordinaryAvailable -or $ordinaryCode -ne 42) { throw 'Medium profile client did not authenticate' }
        & $py -I -S -B $probe wrong-peer *> (Join-Path $parcel 'wrong-peer.log')
        if ($LASTEXITCODE -ne 42) { throw "Unexpected peer probe exit $LASTEXITCODE" }
        Checkpoint wrong-peer 42
        [IO.File]::WriteAllBytes((Join-Path $state 'drop-next'),[byte[]]@())
        if ((Invoke-Ordinary dropped) -ne 42) { throw 'Interrupted reply was not confirmed' }
        Checkpoint dropped 42
        if ((Invoke-Ordinary ipc-recovered) -ne 42) { throw 'IPC did not recover after disconnect' }
        Checkpoint ipc-recovered 42
        if ($EndToEnd) {
            foreach ($scenario in @(@{phase='e2e-drop';marker='drop-next'},@{phase='e2e-timeout';marker='timeout-next'})) {
                $phase = $scenario.phase
                [IO.File]::WriteAllBytes((Join-Path $state $scenario.marker),[byte[]]@())
                if ((Invoke-Ordinary $phase) -ne 42) { throw 'LOCAL failure did not prove safe refusal' }
                Checkpoint $phase 42
            }
        }
    }
    $phase = 'stop'
    [void](Invoke-Scm @('stop',$name))
    Wait-Status 'Stopped' 15
    if (Get-Process -Id $first -ErrorAction SilentlyContinue) { throw 'First worker still present' }
    Checkpoint stop 42
    if ($EndToEnd) {
        $phase = 'e2e-down'
        if ((Invoke-Ordinary e2e-down) -ne 42) { throw 'LOCAL did not refuse a stopped service' }
        Checkpoint e2e-down 42
    }
    if ($Profile -eq 'medium') {
        if ((Invoke-Ordinary counterfeit) -ne 42) { throw 'Counterfeit owner rejection was not confirmed' }
        Checkpoint counterfeit 42
    }
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
    if ($ordinaryAvailable) {
        $ordinaryCode = Invoke-Ordinary denied
        Checkpoint storage-denials $ordinaryCode
        if ($ordinaryCode -ne 42) { throw 'SCM/storage denial failed' }
    }
    $phase = 'recovery'
    [void](Invoke-Scm @('start',$name))
    Wait-Status 'Running' 20
    $third = [int][IO.File]::ReadAllText((Join-Path $state 'ready'))
    if ($EndToEnd) {
        $phase = 'e2e-restart'
        if ($third -in ($first,$second) -or (Invoke-Ordinary e2e-restart) -ne 42) { throw 'LOCAL did not recover after service crash' }
        Checkpoint e2e-restart 42
    }
    [void](Invoke-Scm @('stop',$name))
    Wait-Status 'Stopped' 15
    if (Get-Process -Id $third -ErrorAction SilentlyContinue) { throw 'Restart worker still present' }
    & $py -I -S -B $probe verify *> (Join-Path $parcel 'verify.log')
    if ($LASTEXITCODE -ne 42) { throw "Recovery verification exit $LASTEXITCODE" }
    Checkpoint recovery 42
    $complete = $true
} catch {
    Checkpoint failed-phase $phase
    [IO.File]::WriteAllText((Join-Path $parcel 'failure.log'), ($_.ToString()+'`n'+$_.InvocationInfo.PositionMessage))
} finally {
    if ($created) {
        $status=Get-Service -Name $name
        if ($status.Status -ne 'Stopped') {
            & "$env:SystemRoot\System32\sc.exe" stop $name | Out-Null
            Wait-Status 'Stopped' 15
        }
        [void](Invoke-Scm @('delete',$name))
    }
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Guest service cleanup unconfirmed' }
    [IO.File]::WriteAllBytes((Join-Path $parcel 'bridge-done'),[byte[]]@())
    Checkpoint cleanup 42
}
if($complete){exit 42}
exit 1
