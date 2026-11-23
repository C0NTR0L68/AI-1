param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string] $Revision,
    [Parameter(Mandatory)][string] $Evidence
)
$ErrorActionPreference='Stop'
$parcel='C:\Users\Public\Documents\AI1-C7-'+$TransferId.ToString('N')
$repo=Split-Path $PSScriptRoot

function Guest([string] $Body,[string] $Actor='System',[switch] $Encoded){
    $command=if($Encoded){
        'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+
            [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Body))
    } else { 'powershell.exe -NoProfile -NonInteractive -Command '+$Body }
    if($command.Length -gt 30500){throw 'Guest transport bound exceeded'}
    $r=wsb exec --id $SandboxId --run-as $Actor --command $command --raw
    if($LASTEXITCODE -ne 0){throw 'Windows Sandbox command failed'}
    return [int]($r|ConvertFrom-Json).ExitCode
}

$gate=@'
$ErrorActionPreference='Stop'
if((whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
if((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
exit 42
'@
if((Guest $gate ExistingLogin -Encoded) -ne 42){throw 'Disposable isolated guest was not attested'}

function Read-PinnedSource([string] $Name) {
    $f=Join-Path $repo $Name
    $pin=git -C $repo rev-parse "${Revision}:$Name"
    $working=git -C $repo hash-object --no-filters -- $f
    if($LASTEXITCODE -ne 0 -or $working -ne $pin){throw 'SCM source is not the reviewed Git blob'}
    return ,([IO.File]::ReadAllBytes($f))
}

function Upload([string] $Name,[byte[]] $Bytes) {
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))
    $destination=$parcel+'\'+$Name
    $base64=[Convert]::ToBase64String($Bytes)
    $body='$ErrorActionPreference=''Stop'';$p='''+$destination+''';$bytes=[Convert]::FromBase64String('''+$base64+''');'+
        '$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};'+
        'if((Get-FileHash -LiteralPath $p).Hash -ne '''+$hash+'''){exit 66};exit 42'
    if((Guest $body) -ne 42){throw 'Guest source upload not attested'}
    return $hash
}

$sources=[ordered]@{}
foreach($name in 'c7_qualification/scm_service.cs','c7_qualification/scm_probe.py','app/memory_authority_pipe.py'){
    $sources[$name.Split('/')[-1]]=Upload ($name.Split('/')[-1]) (Read-PinnedSource $name)
}
$manifest=Upload 'source-pins.json' ([Text.Encoding]::UTF8.GetBytes(($sources|ConvertTo-Json)))
$setup=Read-PinnedSource 'c7_qualification/scm_guest.ps1'
$setupHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($setup))
$setup64=[Convert]::ToBase64String($setup)
$command='$ErrorActionPreference=''Stop'';$bytes=[Convert]::FromBase64String('''+$setup64+''');'+
    '$s=[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($bytes));& $s -TransferId '''+$TransferId+''' -SourceManifestSha256 '''+$manifest+''''
$exitCode=Guest $command

$result=[ordered]@{
    revision=$Revision;guest_exit=$exitCode;source_sha256=$sources;guest_script_sha256=$setupHash;guest_source_manifest_sha256=$manifest
}
$prefix='$ErrorActionPreference=''Stop'';$p='''+$parcel+''';'
foreach($phase in 'compile','scm-registration','roles','provision','start','ipc','stop','restart','crash','storage-denials','recovery','cleanup'){
    $code=Guest ($prefix+'$f=Join-Path $p '''+$phase+'.code'';if(!(Test-Path -LiteralPath $f)){exit 90};exit ([int][IO.File]::ReadAllText($f))')
    $result[$phase]=if($code -ne 90){$code}else{$null}
}
if($exitCode -ne 42){
    $result.failed_phase_code=Guest ($prefix+'$f=Join-Path $p ''failed-phase.code'';if(!(Test-Path $f)){exit 90};'+
        '$v=[IO.File]::ReadAllText($f);$a=@(''create-root'',''compile'',''create-roles'',''provision'',''start'',''ipc'',''stop'',''restart'',''crash'',''storage-denials'',''recovery'');exit (100+[array]::IndexOf($a,$v))')
    $result.diagnostic_code=Guest ($prefix+'$f=Join-Path $p ''failure.log'';if(!(Test-Path $f)){exit 90};$s=Get-Content $f -Raw;'+
        'if($s -match ''SCM operation failed with exit (\d+)''){exit [int]$Matches[1]};'+
        'if($s -match ''binary path or account''){exit 91};if($s -match ''did not confirm restricted''){exit 92};'+
        'if($s -match ''Guest C\# compiler exit (\d+)''){exit (100+[int]$Matches[1])};exit 99')
}
$result|ConvertTo-Json -Depth 6|Tee-Object -FilePath $Evidence
if($exitCode -ne 42){exit 1}
exit 0
