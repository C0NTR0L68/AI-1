param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][string] $FrozenHarness,
    [ValidateSet("preflight","suite")][string] $Mode = "preflight"
)
$ErrorActionPreference = "Stop"
$root = "C:\Users\Public\Documents\AI1-B5-" + $TransferId.ToString("N")
$zipSha = "569FD484C31746A0A3A2DA0D133C2EEB8D426C607E71888F2CE113A43F69D8E7"
$pySha = "42AC541168E97DEDB9AABD8BE335539FC41C682E414B9E8D137B164FB68683B0"
$baseline = @{
    "guard.py" = "D643E34C31CAC0CA1446669C873681E4783F771F872385803C82B9DBC1F6D044"
    "adapters.py" = "9FE23C1DBBDCC2F420B45EA5FEF6ADB6BC235DF647618A16507D7115D5EF9EC4"
    "harness.py" = "25C7279F1EE4180649D4CB855CB51177298B35DA23713C9BE42E2BC477C5F9C3"
}
$files = [ordered]@{}
foreach ($name in $baseline.Keys) {
    $source = Join-Path $FrozenHarness $name
    if ((Get-FileHash -LiteralPath $source).Hash -ne $baseline[$name]) { throw "Frozen harness SHA mismatch." }
    $files[$name] = [IO.File]::ReadAllBytes($source)
}
foreach ($name in "b5_admission.py","b5_worker_adapters.py","b5_worker_job.py","b5_guest.py") {
    $files[$name] = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name))
}

function Invoke-Guest([string] $Body) {
    $line = "powershell.exe -NoProfile -NonInteractive -Command $Body"
    if ($line.Length -gt 30500) { throw "Command outside transport bounds." }
    $reply = wsb exec --id $SandboxId --run-as ExistingLogin --command $line --raw | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $null -eq $reply.ExitCode) { throw "Guest launcher unavailable." }
    return [int]$reply.ExitCode
}

$probe = '$ErrorActionPreference=''Stop'';$d='''+$root+''';' +
    'if((whoami) -notmatch ''\\wdagutilityaccount$''){exit 61};' +
    'if((Test-Path ''\\tsclient\C'') -or (Test-Path ''\\tsclient\D'')){exit 62};' +
    'if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{$_.OperationalStatus -eq ''Up'' -and $_.NetworkInterfaceType -ne ''Loopback''}).Count){exit 63};' +
    '$z=Join-Path $d ''AI-1-B5-Offline.zip'';if(!(Test-Path -LiteralPath $z -PathType Leaf)){exit 64};' +
    'if((Get-FileHash -LiteralPath $z).Hash -ne '''+$zipSha+'''){exit 65};exit 42'
$gate = Invoke-Guest $probe
if ($gate -ne 42) { throw "Guest preflight refused: code $gate." }

if ($Mode -eq "preflight") {
    $unpack = '$ErrorActionPreference=''Stop'';$r='''+$root+''';' +
        '$p=Join-Path $r ''payload'';$s=Join-Path $r ''runner'';if((Test-Path $p) -or (Test-Path $s)){exit 67};' +
        'Expand-Archive -LiteralPath (Join-Path $r ''AI-1-B5-Offline.zip'') -DestinationPath $p;' +
        '[void][IO.Directory]::CreateDirectory($s);exit 42'
    if ((Invoke-Guest $unpack) -ne 42) { throw "Guest unpack refused." }
    foreach ($name in $files.Keys) {
        $bytes = [byte[]] $files[$name]
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
        $send = '$ErrorActionPreference=''Stop'';$p='''+$root+'\runner\'+$name+''';' +
            '$d=[Convert]::FromBase64String('''+[Convert]::ToBase64String($bytes)+''');' +
            '$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$f.Write($d,0,$d.Length);$f.Flush($true)}finally{$f.Dispose()};' +
            'if((Get-FileHash -LiteralPath $p).Hash -ne '''+$hash+'''){exit 67};exit 42'
        if ((Invoke-Guest $send) -ne 42) { throw "Guest source transfer refused." }
    }
}

$strictSources = ""
foreach ($name in $files.Keys) {
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]] $files[$name]))
    $strictSources += 'if((Get-FileHash -LiteralPath (Join-Path $r ''runner\'+$name+''')).Hash -ne '''+$hash+'''){exit 69};'
}
$run = '$ErrorActionPreference=''Stop'';$r='''+$root+''';'+$strictSources+
    '$p=Join-Path $r ''payload'';$y=Join-Path $p ''runtime\python\python.exe'';' +
    'if((Get-FileHash -LiteralPath $y).Hash -ne '''+$pySha+'''){exit 68};' +
    '& $y -I -S -B (Join-Path $r ''runner\b5_guest.py'') $p '''+$Mode+''';exit $LASTEXITCODE'
$code = Invoke-Guest $run
[pscustomobject]@{ mode = $Mode; exit = $code; sandbox = $SandboxId; transfer = $TransferId }
exit $code
