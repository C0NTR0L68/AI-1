param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string] $RuntimeSha256,
    [Parameter(Mandatory)][ValidateSet("stage","prepare","verify-reopened","make-links","reject-links")][string] $Mode
)
$ErrorActionPreference = "Stop"
$parcel = "C:\Users\Public\Documents\AI1-C7-" + $TransferId.ToString("N")
$probe = Join-Path $PSScriptRoot "probe.py"
$probePin = (Get-FileHash -LiteralPath $probe).Hash
$pythonPin = "42AC541168E97DEDB9AABD8BE335539FC41C682E414B9E8D137B164FB68683B0"

$guest = @'
$ErrorActionPreference='Stop'
$r='__PARCEL__'
$mode='__MODE__'
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
    Where-Object {$_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
if($mode -eq 'make-links'){
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if($identity.User.Value -ne 'S-1-5-18'){exit 61}
} else {
    if((whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
    if((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
}
$p=Join-Path $r 'payload'
if($mode -eq 'stage'){
    $zip=Join-Path $r 'c7-runtime.zip'
    if((Get-FileHash -LiteralPath $zip).Hash -ne '__RUNTIME__'){exit 64}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if(!(Test-Path -LiteralPath $p)){
        [IO.Compression.ZipFile]::ExtractToDirectory($zip,$p)
    }
    $pinSource=Join-Path $p 'MANIFEST.json'
    $manifest=Get-Content -LiteralPath $pinSource -Raw|ConvertFrom-Json
    if(@($manifest.PSObject.Properties).Count -ne 660){exit 65}
    foreach($entry in $manifest.PSObject.Properties){
        if($entry.Name -notmatch '^(app|runtime/python)/[a-zA-Z0-9_./-]+$' -or $entry.Name.Contains('..')){exit 65}
        $item=Join-Path $p $entry.Name
        if((Get-Item -LiteralPath $item).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 65}
        if((Get-FileHash -LiteralPath $item).Hash -ne $entry.Value){exit 65}
    }
    exit 42
}
$python=Join-Path $p 'runtime\python\python.exe'
$dest=Join-Path $p 'probe-revision2.py'
if((Get-FileHash -LiteralPath $dest).Hash -ne '__PROBE__'){exit 66}
if((Get-FileHash -LiteralPath $python).Hash -ne '__PYTHON__'){exit 67}
if((Get-FileHash -LiteralPath (Join-Path $p 'app\memory_windows_archive.py')).Hash -ne '57807579826E2CBFCEB9D9B5CA3519943C2E841EDE3F495298F5C2D0FB6307FB'){exit 68}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$env:AI1_C7_OWNER=$identity.User.Value
$ErrorActionPreference='Continue'
& $python -I -S -B $dest $mode *> (Join-Path $r ($mode+'.log'))
exit $LASTEXITCODE
'@

$guest = $guest.Replace('__PARCEL__',$parcel).Replace('__MODE__',$Mode).
    Replace('__RUNTIME__',$RuntimeSha256).Replace('__PROBE__',$probePin).Replace('__PYTHON__',$pythonPin)
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($guest))
if ($encoded.Length -gt 29500) { throw "Guest command exceeds the transport bound." }
$actor = if ($Mode -eq "make-links") { "System" } else { "ExistingLogin" }
if ($Mode -eq "make-links") {
    # RDP drive redirection is scoped to ExistingLogin. SYSTEM cannot query it.
    $gate = '$ErrorActionPreference=''Stop'';if((whoami) -notmatch ''\\wdagutilityaccount$''){exit 61};' +
        'if((Test-Path ''\\tsclient\C'') -or (Test-Path ''\\tsclient\D'')){exit 62};exit 42'
    $gateEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($gate))
    $attestation = wsb exec --id $SandboxId --run-as ExistingLogin --command "powershell.exe -NoProfile -NonInteractive -EncodedCommand $gateEncoded" --raw
    if ($LASTEXITCODE -ne 0 -or ($attestation | ConvertFrom-Json).ExitCode -ne 42) {
        throw "Guest login did not attest absent RDP drives."
    }
}
$reply = wsb exec --id $SandboxId --run-as $actor --command "powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded" --raw
if ($LASTEXITCODE -ne 0) { throw "Guest command failed to start." }
$result = $reply | ConvertFrom-Json
if ($Mode -eq "stage" -and $result.ExitCode -eq 42) {
    $path = $parcel + '\payload\probe-revision2.py'
    $base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($probe))
    $send = '$ErrorActionPreference=''Stop'';$p='''+$path+''';' +
        '$b=[Convert]::FromBase64String('''+$base64+''');' +
        '$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew);' +
        'try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()};' +
        'if((Get-FileHash -LiteralPath $p).Hash -ne '''+$probePin+'''){exit 66};exit 42'
    if ($send.Length -gt 29500) { throw "Probe exceeds the transport bound." }
    $receipt = wsb exec --id $SandboxId --run-as ExistingLogin --command "powershell.exe -NoProfile -NonInteractive -Command $send" --raw
    if ($LASTEXITCODE -ne 0) { throw "Probe transfer failed." }
    $result = $receipt | ConvertFrom-Json
}
[pscustomobject]@{ mode = $Mode; actor = $actor; exit_code = $result.ExitCode;
                  runtime_sha256 = $RuntimeSha256; probe_sha256 = $probePin }
if ($result.ExitCode -ne 42) { exit 1 }
exit 0
