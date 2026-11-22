param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][string] $FrozenHarness,
    [ValidateSet("preflight","suite")][string] $Mode = "preflight",
    [switch] $SchemaRevision
)
$ErrorActionPreference = "Stop"
$root = "C:\Users\Public\Documents\AI1-B5-" + $TransferId.ToString("N")
$zipSha = "569FD484C31746A0A3A2DA0D133C2EEB8D426C607E71888F2CE113A43F69D8E7"
$expectedBase = 195
$expectedCases = 603
if ($SchemaRevision) {
    $zipSha = "4BCE5F2BEF7CB4374CB42F8AFDD56C6BC5304CAD7A5754282E5808C417A66D15"
    $expectedBase = 198
    $expectedCases = 609
}
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
        '$p=Join-Path $r ''payload'';$s=Join-Path $r ''runner'';$log=Join-Path $r ''guest-preflight.console.log'';' +
        'foreach($old in @($p,$s,$log)){if(Test-Path -LiteralPath $old){' +
        'if((Get-Item -LiteralPath $old).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 67};' +
        'Move-Item -LiteralPath $old -Destination ($old+''.previous-''+[guid]::NewGuid().ToString(''N''))}};' +
        'Add-Type -AssemblyName System.IO.Compression.FileSystem;' +
        '[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $r ''AI-1-B5-Offline.zip''),$p);' +
        '[void][IO.Directory]::CreateDirectory($s);exit 42'
    $unpackCode = Invoke-Guest $unpack
    if ($unpackCode -ne 42) { throw "Guest unpack refused: code $unpackCode." }
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
    '$log=Join-Path $r (''guest-'+$Mode+'.console.log'');' +
    '$ErrorActionPreference=''Continue'';' +
    '& $y -I -S -B (Join-Path $r ''runner\b5_guest.py'') $p '''+$Mode+''' *> $log;exit $LASTEXITCODE'
$code = Invoke-Guest $run
$report = [ordered]@{ mode = $Mode; exit = $code; sandbox = $SandboxId; transfer = $TransferId; archiveSha256 = $zipSha }
if ($code -ne 0) {
    $diagnostic = '$p='''+$root+'\guest-'+$Mode+'.console.log'';' +
        'if(!(Test-Path -LiteralPath $p -PathType Leaf)){exit 90};$s=Get-Content -LiteralPath $p -Raw;' +
        'if($s -match ''WinError|Win32''){exit 91};if($s -match ''Job limits differ|not assigned to a Job''){exit 92};' +
        'if($s -match ''ModuleNotFoundError|ImportError''){exit 93};if($s -match ''AdmissionDenied|PermissionError''){exit 94};' +
        'if($s -match ''TimeoutError''){exit 95};if($s -match ''unexpected|unavailable|RuntimeError''){exit 96};exit 97'
    $report.failureCategory = Invoke-Guest $diagnostic
}
if ($Mode -eq "suite") {
    $read = '$ErrorActionPreference=''Stop'';$p='''+$root+'\payload\result-suite.json'';' +
        'if(!(Test-Path -LiteralPath $p -PathType Leaf)){exit 10001};' +
        '$r=Get-Content -LiteralPath $p -Raw|ConvertFrom-Json;if($r.mode -ne ''suite''){exit 10002};'
    $metrics = [ordered]@{
        baseFunctions = 'exit [int]$r.base_functions'
        collected = 'exit [int]$r.collected'
        passedCalls = 'exit @($r.items|Where-Object{$_[1] -eq ''call'' -and $_[2] -eq ''passed''}).Count'
        unsuccessfulPhases = 'exit @($r.items|Where-Object{$_[2] -ne ''passed''}).Count'
        nodeTestPassed = 'exit [int](@($r.items|Where-Object{$_[0] -match ''test_ui.py::test_ui_reliability_handlers$'' -and $_[1] -eq ''call'' -and $_[2] -eq ''passed''}).Count -eq 1)'
    }
    foreach ($name in $metrics.Keys) {
        $value = Invoke-Guest ($read + $metrics[$name])
        $report[$name] = if ($value -lt 10000) { $value } else { $null }
    }
    if ($SchemaRevision) {
        $checks = [ordered]@{
            expectedCollection = 'exit [int]($r.collection_sha256 -eq ''e94ca9c3a4dfb44926d5d059ccdfb24df3fbecdfd30f462f48d5d252364d83fa'')'
            passedSchemaCases = 'exit @($r.items|Where-Object{$_[0] -match ''^tests/test_schema_contract\.py::'' -and $_[1] -eq ''call'' -and $_[2] -eq ''passed''}).Count'
            completedPhases = 'exit @($r.items).Count'
            unexpectedDenials = 'exit @($r.denials).Count'
        }
        foreach ($name in $checks.Keys) {
            $value = Invoke-Guest ($read + $checks[$name])
            $report[$name] = if ($value -lt 10000) { $value } else { $null }
        }
        foreach ($name in "tests","pass","fail","cancelled","skipped","todo") {
            $value = Invoke-Guest ($read + 'if($r.node_results.Count -ne 1 -or !$r.node_results[0]){exit 10003};exit [int]$r.node_results[0].'+$name)
            $report[('node_' + $name)] = if ($value -lt 10000) { $value } else { $null }
        }
        if ($code -eq 0 -and ($report.expectedCollection -ne 1 -or $report.passedSchemaCases -ne 8 -or
            $report.completedPhases -ne 3 * $expectedCases -or $null -eq $report.unexpectedDenials -or
            $report.unexpectedDenials -ne 0 -or $report.node_tests -ne 22 -or $report.node_pass -ne 22 -or
            @("fail","cancelled","skipped","todo" | Where-Object {
                $null -eq $report["node_$_"] -or $report["node_$_"] -ne 0
            }).Count -ne 0)) {
            $code = 76
            $report.exit = $code
        }
    }
    if ($code -eq 0 -and ($report.baseFunctions -ne $expectedBase -or $report.collected -ne $expectedCases -or
        $report.passedCalls -ne $report.collected -or $report.unsuccessfulPhases -ne 0 -or $report.nodeTestPassed -ne 1)) {
        $code = 74
        $report.exit = $code
    }
}
[pscustomobject] $report
exit $code
