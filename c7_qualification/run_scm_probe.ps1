param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string] $Revision,
    [Parameter(Mandatory)][string] $Evidence,
    [ValidateSet('high','medium')][string] $Profile='high',
    [string] $DotenvArchive
)
$ErrorActionPreference='Stop'
$parcel='C:\Users\Public\Documents\AI1-C7-'+$TransferId.ToString('N')
$repo=Split-Path $PSScriptRoot
$endToEnd = $DotenvArchive -ne ''
if ($endToEnd -and $Profile -ne 'medium') { throw 'Explicit medium enrollment required' }

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
$sourceFiles = @('c7_qualification/scm_service.cs','c7_qualification/scm_probe.py','app/memory_authority_pipe.py')
if ($endToEnd) { $sourceFiles += 'c7_qualification/scm_dpapi_e2e.py' }
foreach($name in $sourceFiles){
    $sources[$name.Split('/')[-1]]=Upload ($name.Split('/')[-1]) (Read-PinnedSource $name)
}
if ($endToEnd) {
    if ((Get-FileHash -LiteralPath $DotenvArchive).Hash -ne 'FF8F3C00CAA41A26A3C5328653E55AFF70F079E078518082C50D2A946AEA401E') {
        throw 'Dependency pin mismatch'
    }
    $sources.dotenv=Upload 'dotenv-addon.zip' ([IO.File]::ReadAllBytes($DotenvArchive))
    $appPins=[ordered]@{}
    $files = @(git -C $repo ls-tree -r --name-only $Revision -- app)
    if($LASTEXITCODE -ne 0 -or $files.Count -eq 0){throw 'Trusted application file list unavailable'}
    foreach ($name in ($files + 'c7_qualification/probe.py')) {
        $appPins[$name]=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData((Read-PinnedSource $name)))
    }
    $sources.application=$appPins
}
$manifest=Upload 'source-pins.json' ([Text.Encoding]::UTF8.GetBytes(($sources|ConvertTo-Json)))
$setup=Read-PinnedSource 'c7_qualification/scm_guest.ps1'
$setupHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($setup))
$setup64=[Convert]::ToBase64String($setup)
$command='$ErrorActionPreference=''Stop'';$bytes=[Convert]::FromBase64String('''+$setup64+''');'+
    '$s=[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($bytes));& $s -TransferId '''+$TransferId+''' -SourceManifestSha256 '''+$manifest+''' -Profile '''+$Profile+''''
if ($endToEnd) { $command += ' -EndToEnd' }
$preflight=Read-PinnedSource 'c7_qualification/standard_user_preflight.ps1'
$preflightHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($preflight))
$preflight64=[Convert]::ToBase64String($preflight)
$bridgeBody='$s=[ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+
    $preflight64+''')));& $s -ParcelId '''+$TransferId+''' -Bridge'
$bridgeCommand='powershell.exe -NoProfile -NonInteractive -Command '+$bridgeBody
$job=Start-ThreadJob -ArgumentList $SandboxId,$bridgeCommand -ScriptBlock {
    param($sid,$line)
    $reply=wsb exec --id $sid --run-as ExistingLogin --command $line --raw
    if($LASTEXITCODE -ne 0){throw 'Bridge guest command failed'}
    return [int]($reply|ConvertFrom-Json).ExitCode
}
$prefix='$ErrorActionPreference=''Stop'';$p='''+$parcel+''';'
$bridgeExit=$null
try {
    $attested=$false
    for($attempt=0;$attempt -lt 8;$attempt++){
        if($job.State -in 'Completed','Failed'){break}
        if((Guest ($prefix+'if(Test-Path -LiteralPath (Join-Path $p ''bridge-ready.json'')){exit 42};exit 90') ExistingLogin) -eq 42){
            $attested=$true
            break
        }
        Start-Sleep -Milliseconds 300
    }
    if(!$attested){throw 'Verified ordinary bridge did not become ready'}
    $exitCode=Guest $command
} finally {
    [void](Guest ($prefix+'[IO.File]::WriteAllBytes((Join-Path $p ''bridge-done''),[byte[]]@());exit 42') ExistingLogin)
    if(!(Wait-Job -Job $job -Timeout 20)){throw 'Ordinary launch bridge cleanup unconfirmed'}
    $bridgeExit=Receive-Job -Job $job
    Remove-Job -Job $job
}

$result=[ordered]@{
    revision=$Revision;guest_exit=$exitCode;source_sha256=$sources;guest_script_sha256=$setupHash;guest_source_manifest_sha256=$manifest
    ordinary_bridge_sha256=$preflightHash;ordinary_bridge_exit=$bridgeExit
    profile=$Profile; end_to_end=$endToEnd
}
$phases=@('compile','scm-registration','roles','provision','ordinary-preflight','start','ipc','client-unqualified','wrong-peer','dropped','ipc-recovered','stop','counterfeit','restart','crash','storage-denials','recovery','cleanup')
if($endToEnd){$phases+=@('application-pins','archive-enrollment','dpapi-boundary','e2e-live','wrong-generation','corrupt','stale','replaced-path','e2e-restored','e2e-drop','e2e-timeout','e2e-down','e2e-restart')}
foreach($phase in $phases){
    $code=Guest ($prefix+'$f=Join-Path $p '''+$phase+'.code'';if(!(Test-Path -LiteralPath $f)){exit 90};exit ([int][IO.File]::ReadAllText($f))')
    $result[$phase]=if($code -ne 90){$code}else{$null}
}
if($endToEnd -and $result['dpapi-boundary'] -eq 42){
    # Send only the numeric native failure; encode each byte in a bounded exit code.
    $parts=0..3|ForEach-Object {
        Guest ($prefix+'$v=[int][IO.File]::ReadAllText((Join-Path $p ''dpapi-native-error.txt''));exit (($v -shr '+($_*8)+') -band 255)')
    }
    $result.dpapi_native_error_hex=('{0:X2}{1:X2}{2:X2}{3:X2}' -f $parts[3],$parts[2],$parts[1],$parts[0])
}
if($exitCode -ne 42){
    $result.failed_phase_code=Guest ($prefix+'$f=Join-Path $p ''failed-phase.code'';if(!(Test-Path $f)){exit 90};'+
        '$v=[IO.File]::ReadAllText($f);$a=@(''create-root'',''compile'',''create-roles'',''provision'',''start'',''ipc'',''stop'',''restart'',''crash'',''storage-denials'',''recovery'',''ordinary-preflight'',''archive-enrollment'',''dpapi-boundary'',''e2e-live'',''e2e-drop'',''e2e-timeout'',''e2e-down'',''e2e-restart'');exit (100+[array]::IndexOf($a,$v))')
    $result.diagnostic_code=Guest ($prefix+'$f=Join-Path $p ''failure.log'';if(!(Test-Path $f)){exit 90};$s=Get-Content $f -Raw;'+
        'if($s -match ''SCM operation failed with exit (\d+)''){exit [int]$Matches[1]};'+
        'if($s -match ''binary path or account''){exit 91};if($s -match ''did not confirm restricted''){exit 92};'+
        'if($s -match ''Guest C\# compiler exit (\d+)''){exit (100+[int]$Matches[1])};exit 99')
}
$result|ConvertTo-Json -Depth 6|Tee-Object -FilePath $Evidence
if($exitCode -ne 42 -or $bridgeExit -ne 42){exit 1}
exit 0
