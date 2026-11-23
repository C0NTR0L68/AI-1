param(
    [Parameter(Mandatory)][guid] $SandboxId,
    [Parameter(Mandatory)][guid] $TransferId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string] $Revision,
    [Parameter(Mandatory)][string] $Evidence
)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
$parcel='C:\Users\Public\Documents\AI1-C7-'+$TransferId.ToString('N')

function Guest([string] $body) {
    $command='powershell.exe -NoProfile -NonInteractive -Command '+$body
    if($command.Length -gt 30500){throw 'Guest command bound exceeded'}
    $raw=wsb exec --id $SandboxId --run-as ExistingLogin --command $command --raw
    if($LASTEXITCODE -ne 0){throw 'Sandbox command failed'}
    return [int]($raw|ConvertFrom-Json).ExitCode
}

$archive='9D56A383933EA9D5469A3CE8588262376CDCDFC59438AF6779B3CE2FA85D7500'
$manifest='9E3363DAA02196EF011ED68BD8335838ED64992AA3854A625A2972D0FDC52E15'
$stage=& (Join-Path $PSScriptRoot 'run_binding_guest.ps1') -SandboxId $SandboxId -TransferId $TransferId `
    -ArchiveSha256 $archive -ManifestSha256 $manifest -Mode stage
if($stage.exit_code -ne 42){throw 'Guest staging was not confirmed'}
$pins=[ordered]@{}
foreach($name in 'app/memory_write_v2.py','c7_qualification/cas_write_guest.py'){
    $source=Join-Path $repo $name
    $gitPin=git -C $repo rev-parse "${Revision}:$name"
    $working=git -C $repo hash-object --no-filters -- $source
    if($LASTEXITCODE -ne 0 -or $gitPin -ne $working){throw 'Source checkout is not byte-identical to the Git pin'}
    $bytes=[IO.File]::ReadAllBytes($source)
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    $pins[$name]=$hash
    $target=$parcel+'\payload\'+$name.Replace('/','\')
    $base64=[Convert]::ToBase64String($bytes)
    $body='$ErrorActionPreference=''Stop'';$p='''+$target+''';$bytes=[Convert]::FromBase64String('''+$base64+''');'+
        '$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};'+
        'if((Get-FileHash -LiteralPath $p).Hash -ne '''+$hash+'''){exit 66};exit 42'
    if((Guest $body) -ne 42){throw 'Guest source pin not confirmed'}
}
$result=[ordered]@{revision=$Revision;archive_sha256=$archive;manifest_sha256=$manifest;source_sha256=$pins;
    staging=42;profile='isolated guest interactive DPAPI owner';write=$null;restart=$null;reconcile=$null}
try {
    foreach($phase in 'write','restart','reconcile'){
        $body=@'
$ErrorActionPreference='Stop'
$p='__PARCEL__'
if((whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
if((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
$env:AI1_C7_OWNER=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$runtime=Join-Path $p 'payload\runtime\python\python.exe'
$probe=Join-Path $p 'payload\c7_qualification\cas_write_guest.py'
if((Get-FileHash -LiteralPath $runtime).Hash -ne '42AC541168E97DEDB9AABD8BE335539FC41C682E414B9E8D137B164FB68683B0' -or
   (Get-FileHash -LiteralPath $probe).Hash -ne '__PROBE__' -or
   (Get-FileHash -LiteralPath (Join-Path $p 'payload\app\memory_write_v2.py')).Hash -ne '__CORE__'){exit 65}
$ErrorActionPreference='Continue'
& $runtime -I -S -B $probe '__PHASE__' *> (Join-Path $p ('cas-__PHASE__'+'.log'))
exit $LASTEXITCODE
'@
        $body=$body.Replace('__PARCEL__',$parcel).Replace('__PHASE__',$phase).
            Replace('__PROBE__',$pins['c7_qualification/cas_write_guest.py']).Replace('__CORE__',$pins['app/memory_write_v2.py'])
        # Use an encoded inner script so the guest process receives PowerShell syntax verbatim.
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
        $result[$phase]=Guest ('& powershell.exe -NoProfile -NonInteractive -EncodedCommand '+$encoded+';exit $LASTEXITCODE')
        if($result[$phase] -ne $(if($phase -eq 'restart'){43}else{42})){throw "Native CAS phase $phase failed"}
    }
} finally {
    $result|ConvertTo-Json -Depth 4|Tee-Object -FilePath $Evidence
}
