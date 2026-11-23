param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string] $Revision
)
$ErrorActionPreference = 'Stop'
$p = 'C:\Users\Public\Documents\AI1-C7-' + $TransferId.ToString('N')
$repo = Split-Path $PSScriptRoot
$archive = '9D56A383933EA9D5469A3CE8588262376CDCDFC59438AF6779B3CE2FA85D7500'
$manifest = '9E3363DAA02196EF011ED68BD8335838ED64992AA3854A625A2972D0FDC52E15'

function Invoke-Guest([string] $Body, [switch] $Encoded){
    $line = if ($Encoded) {
        'powershell.exe -NoProfile -NonInteractive -EncodedCommand ' +
        [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Body))
    } else { 'powershell.exe -NoProfile -NonInteractive -Command ' + $Body }
    if($line.Length -gt 30500){throw 'Guest command exceeds transport bound'}
    $reply=wsb exec --id $SandboxId --run-as ExistingLogin --command $line --raw
    if($LASTEXITCODE -ne 0){throw 'Guest command rejected'}
    return [int]($reply|ConvertFrom-Json).ExitCode
}

$stage=& (Join-Path $PSScriptRoot 'run_binding_guest.ps1') -SandboxId $SandboxId -TransferId $TransferId `
    -ArchiveSha256 $archive -ManifestSha256 $manifest -Mode stage
if($LASTEXITCODE -ne 0 -or $stage.exit_code -ne 42){throw 'Isolated staging did not pass'}

$pins=[ordered]@{}
foreach($name in 'app/memory_authority_pipe.py','c7_qualification/deployment_gate.py','c7_qualification/deployment_probe.py'){
    $file=Join-Path $repo $name
    $hash=(Get-FileHash -LiteralPath $file).Hash
    $rev=git -C $repo rev-parse "${Revision}:$name"
    $work=git -C $repo hash-object --no-filters -- $file
    if($LASTEXITCODE -ne 0 -or $work -ne $rev){throw 'Source Git pin mismatch'}
    $target=$p+'\payload\'+$name.Replace('/','\')
    $bytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($file))
    $send='$ErrorActionPreference=''Stop'';$p='''+$target+''';$d=[Convert]::FromBase64String('''+$bytes+''');'+
        '$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$f.Write($d,0,$d.Length)}finally{$f.Dispose()};'+
        'if((Get-FileHash -LiteralPath $p).Hash -ne '''+$hash+'''){exit 66};exit 42'
    if((Invoke-Guest $send) -ne 42){throw 'Guest source pin mismatch'}
    $pins[$name]=$hash
}

$body=@'
$ErrorActionPreference='Stop'
if((whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
if((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
$r='__ROOT__'
$p=Join-Path $r 'payload'
$py=Join-Path $p 'runtime\python\python.exe'
if((Get-FileHash -LiteralPath $py).Hash -ne '42AC541168E97DEDB9AABD8BE335539FC41C682E414B9E8D137B164FB68683B0'){exit 64}
$ErrorActionPreference='Continue'
& $py -I -S -B (Join-Path $p 'c7_qualification\deployment_probe.py') *> (Join-Path $r 'deployment-probe.log')
exit $LASTEXITCODE
'@
$code=Invoke-Guest $body.Replace('__ROOT__',$p) -Encoded
$read='$p='''+$p+'\deployment-safety\result.json'';if(!(Test-Path -LiteralPath $p)){exit 90};'+
    '$r=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json;exit (__VALUE__)'
$result=[ordered]@{revision=$Revision;exit=$code;base_archive_sha256=$archive;base_manifest_sha256=$manifest;
                   source_sha256=$pins}
foreach($name in 'tests','failures','errors','skips'){
    $value=Invoke-Guest ($read.Replace('__VALUE__','[int]$r.'+$name))
    $result[$name]=if($value -ne 90){$value}else{$null}
}
[pscustomobject]$result
if($code -ne 42 -or $result.tests -ne 3 -or $result.failures -ne 0 -or $result.errors -ne 0 -or $result.skips -ne 0){
    exit 1
}
exit 0
