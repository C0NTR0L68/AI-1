param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][string] $Evidence,
    [Parameter(Mandatory)][string] $DotenvArchive,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string] $Revision
)
$ErrorActionPreference = 'Stop'
$parcel = 'C:\Users\Public\Documents\AI1-C7-' + $TransferId.ToString('N')
$private = 'C:\Windows\System32\config\systemprofile\AI1-C7-' + $TransferId.ToString('N')
$archive = '9D56A383933EA9D5469A3CE8588262376CDCDFC59438AF6779B3CE2FA85D7500'
$manifest = '9E3363DAA02196EF011ED68BD8335838ED64992AA3854A625A2972D0FDC52E15'
$python = '42AC541168E97DEDB9AABD8BE335539FC41C682E414B9E8D137B164FB68683B0'
$dotenv = 'FF8F3C00CAA41A26A3C5328653E55AFF70F079E078518082C50D2A946AEA401E'
$repo = Split-Path $PSScriptRoot

function Invoke-Guest([string] $Command, [string] $Actor = 'ExistingLogin', [switch] $Encoded) {
    if ($Encoded) {
        $data = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
        $line = "powershell.exe -NoProfile -NonInteractive -EncodedCommand $data"
    } else {
        $line = "powershell.exe -NoProfile -NonInteractive -Command $Command"
    }
    if ($line.Length -gt 30500) { throw 'Guest command exceeds its bound.' }
    $reply = wsb exec --id $SandboxId --run-as $Actor --command $line --raw
    if ($LASTEXITCODE -ne 0) { throw 'Windows Sandbox command failed.' }
    return [int]($reply | ConvertFrom-Json).ExitCode
}

function Confirm([string] $Phase, [int] $Code) {
    [ordered]@{phase=$Phase;guest_exit=$Code;source_revision=$Revision} |
        ConvertTo-Json | Tee-Object -FilePath (Join-Path $Evidence ($Phase + '.json'))
    if ($Code -ne 42) { throw "Guest phase ${Phase}: $Code." }
}

$attest = @'
$ErrorActionPreference='Stop'
if((whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
if((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|
    Where-Object{$_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
exit 42
'@
Confirm 'isolation' (Invoke-Guest $attest -Encoded)
if ((Get-FileHash -LiteralPath $DotenvArchive).Hash -ne $dotenv) { throw 'Dotenv addon hash mismatch.' }

foreach ($stage in 'stage','stage-system') {
    $result = & (Join-Path $PSScriptRoot 'run_binding_guest.ps1') -SandboxId $SandboxId -TransferId $TransferId `
        -ArchiveSha256 $archive -ManifestSha256 $manifest -Mode $stage
    Confirm $stage $result.exit_code
}

$sources = [ordered]@{}
foreach ($name in 'app/memory_authority_pipe.py','c7_qualification/ipc_guest.py') {
    $path = Join-Path $repo $name
    $hash = (Get-FileHash -LiteralPath $path).Hash
    $raw = git -C $repo hash-object --no-filters -- $path
    $git = git -C $repo rev-parse "${Revision}:$name"
    if ($LASTEXITCODE -ne 0 -or $raw -ne $git) { throw 'Source is not the pinned Git blob.' }
    $sources[$name] = $hash
    $data = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
    foreach ($actor in 'ExistingLogin','System') {
        $target = "$(if($actor -eq 'System'){$private}else{$parcel})\payload\" + $name.Replace('/','\')
        $send = '$ErrorActionPreference=''Stop'';$p='''+$target+''';$d=[Convert]::FromBase64String('''+$data+''');' +
            '$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$f.Write($d,0,$d.Length);$f.Flush($true)}finally{$f.Dispose()};' +
            'if((Get-FileHash -LiteralPath $p).Hash -ne '''+$hash+'''){exit 66};exit 42'
        $slot = $name.Split('/')[-1] + '-' + $actor
        Confirm $slot (Invoke-Guest $send $actor)
    }
}
$sources | ConvertTo-Json | Out-File -Encoding utf8 (Join-Path $Evidence 'source-pins.json')
$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes($DotenvArchive))
$dep = '$ErrorActionPreference=''Stop'';$r='''+$parcel+''';$p=Join-Path $r ''dotenv-addon.zip'';' +
    '$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$d=[Convert]::FromBase64String('''+$data+''');$f.Write($d,0,$d.Length)}finally{$f.Dispose()};' +
    'if((Get-FileHash -LiteralPath $p).Hash -ne '''+$dotenv+'''){exit 66};' +
    'Add-Type -AssemblyName System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory($p,(Join-Path $r ''payload\deps''));exit 42'
Confirm 'dependency' (Invoke-Guest $dep)

function Scenario([string] $Action, [string] $Label, [string] $Actor = 'ExistingLogin',
                  [switch] $Background) {
    $root = if ($Actor -eq 'System') {$private} else {$parcel}
    $body = @'
$ErrorActionPreference='Stop'
$actor=[Security.Principal.WindowsIdentity]::GetCurrent()
if(($actor.User.Value -eq 'S-1-5-18') -ne __SYSTEM__){exit 61}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|
    Where-Object{$_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
$env:AI1_C7_OWNER=$actor.User.Value
$root='__ROOT__'
$pr=Join-Path $root 'payload\runtime\python\python.exe'
$script=Join-Path $root 'payload\c7_qualification\ipc_guest.py'
$module=Join-Path $root 'payload\app\memory_authority_pipe.py'
if((Get-FileHash $pr).Hash -ne '__PYTHON__' -or (Get-FileHash $script).Hash -ne '__SCRIPT__' -or
    (Get-FileHash $module).Hash -ne '__MODULE__'){exit 66}
$env:PYTHON_DOTENV_DISABLED='1'
$ErrorActionPreference='Continue'
& $pr -I -S -B $script '__ACTION__' '__PARCEL__' *> (Join-Path $root '__LABEL__.log')
$code=$LASTEXITCODE
if($code -eq 42 -and '__ACTION__' -eq 'provision'){
    $ErrorActionPreference='Stop'
    $f=Join-Path $root 'ipc-enrollment.json'
    $sid=[Security.Principal.SecurityIdentifier]::new((Get-Content -LiteralPath $f -Raw|ConvertFrom-Json).owner)
    $acl=Get-Acl -LiteralPath $f
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'Read','Allow'))
    Set-Acl -LiteralPath $f -AclObject $acl
}
exit $code
'@
    $command = $body.Replace('__ROOT__',$root).Replace('__PARCEL__',$parcel).Replace('__ACTOR__',$Actor).
        Replace('__SYSTEM__',$(if($Actor -eq 'System'){'$true'}else{'$false'})).
        Replace('__ACTION__',$Action).Replace('__LABEL__',$Label).Replace('__PYTHON__',$python).
        Replace('__SCRIPT__',$sources['c7_qualification/ipc_guest.py']).Replace('__MODULE__',$sources['app/memory_authority_pipe.py'])
    if (!$Background) {
        Confirm $Label (Invoke-Guest $command $Actor -Encoded)
        return
    }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    Start-ThreadJob -ArgumentList $SandboxId,$Actor,$encoded -ScriptBlock {
        param($id,$runAs,$data)
        $os = wsb exec --id $id --run-as $runAs --command "powershell.exe -NoProfile -NonInteractive -EncodedCommand $data" --raw
        if ($LASTEXITCODE -ne 0) { throw 'Guest authority process launch failed.' }
        return [int]($os | ConvertFrom-Json).ExitCode
    }
}

function Start-Authority([string] $Action, [string] $Label, [string] $Actor) {
    $job = Scenario $Action $Label $Actor -Background
    $name = "AI1-C7-" + $TransferId.ToString('N')
    $probe = '$ErrorActionPreference=''Stop'';if([IO.Directory]::GetFiles(''\\.\pipe\'','''+$name+''').Count -eq 1){exit 42};exit 71'
    for ($attempt=0; $attempt -lt 6; $attempt++){
        if ($job.State -in 'Completed','Failed') { break }
        if ((Invoke-Guest $probe) -eq 42) { return $job }
        Start-Sleep -Milliseconds 250
    }
    $rc = Receive-Job -Job $job -ErrorAction SilentlyContinue
    if ($null -ne $rc) { Confirm ($Label+'-early') $rc }
    throw 'Authority readiness was not confirmed.'
}

function Stop-Authority($Job, [string] $Label, [string] $Actor) {
    $stopRoot = if ($Actor -eq 'System') {$private} else {$parcel+'\ipc-scratch'}
    $marker = $stopRoot+'\stop'
    Confirm ($Label+'-signal') (Invoke-Guest ('$ErrorActionPreference=''Stop'';[IO.File]::Create('''+
        $marker+''').Dispose();exit 42') $Actor)
    if (!(Wait-Job -Job $Job -Timeout 12)) { throw 'Authority did not stop within deadline.' }
    Confirm ($Label+'-closed') (Receive-Job -Job $Job)
    Remove-Job -Job $Job
    Confirm ($Label+'-marker-closed') (Invoke-Guest ('$ErrorActionPreference=''Stop'';[IO.File]::Delete('''+
        $marker+''');exit 42') $Actor)
}

Scenario enroll enroll
Scenario provision provision System
$server = Start-Authority serve initial-server System
try {
    Scenario startup initial-startup
    Scenario denied wrong-client-sid System
} finally { Stop-Authority $server initial-server System }
Scenario unavailable authority-unavailable
$server = Start-Authority drop dropped-server System
try { Scenario disconnected authority-disconnected }
finally { Stop-Authority $server dropped-server System }
$server = Start-Authority impostor impostor-server ExistingLogin
try { Scenario wrong-server wrong-authority-owner }
finally { Stop-Authority $server impostor-server ExistingLogin }
Scenario advance authority-revision-advance System
$server = Start-Authority serve restarted-server System
try {
    Scenario startup-updated restarted-startup
    Scenario substitute archive-directory-substitution
    Scenario substituted refuse-substituted-archive
} finally { Stop-Authority $server restarted-server System }
Scenario journal create-real-journal System
Scenario ordinary-files deny-ordinary-file-operations
Scenario verify-files verify-head-and-journal System
