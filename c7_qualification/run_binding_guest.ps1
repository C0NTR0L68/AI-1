param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string] $ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string] $ManifestSha256,
    [Parameter(Mandatory)][ValidateSet('stage','stage-system','binding','prepare','verify-reopened',
                                      'make-links','reject-links','provision','ordinary','verify')][string] $Mode
)
$ErrorActionPreference = 'Stop'
$parcel = 'C:\Users\Public\Documents\AI1-C7-' + $TransferId.ToString('N')
$fixture = Join-Path $PSScriptRoot 'authority_fixture.py'
$fixtureSha = (Get-FileHash -LiteralPath $fixture).Hash
$source64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($fixture))
$gate = @'
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if((whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
if((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
exit 42
'@
function Invoke-Guest([string] $Body, [string] $Actor) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Body))
    if ($encoded.Length -gt 29500) { throw 'Guest command exceeds its bound.' }
    $reply = wsb exec --id $SandboxId --run-as $Actor --command "powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded" --raw
    if ($LASTEXITCODE -ne 0) { throw 'Guest launcher failed.' }
    return [int]($reply | ConvertFrom-Json).ExitCode
}
if ((Invoke-Guest $gate ExistingLogin) -ne 42) { throw 'No attested isolated guest login.' }

$body = @'
$ErrorActionPreference='Stop'
$r='__ROOT__'
$mode='__MODE__'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem=$identity.User.Value -eq 'S-1-5-18'
if($isSystem -ne ($mode -in 'stage-system','make-links','provision','verify')){exit 61}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
$system=Join-Path $env:SystemRoot ('System32\config\systemprofile\'+[IO.Path]::GetFileName($r))
$p=Join-Path $(if($isSystem){$system}else{$r}) 'payload'
if($mode -in 'stage','stage-system'){
    $archive=Join-Path $r 'c7-binding.zip'
    if($isSystem){
        if(Test-Path -LiteralPath $system){exit 70}
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($identity.User)
        $acl.SetAccessRuleProtection($true,$false)
        $rule=[Security.AccessControl.FileSystemAccessRule]::new(
            $identity.User,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
        [void][IO.Directory]::CreateDirectory($system,$acl)
        $privateZip=Join-Path $system 'verified.zip'
        [IO.File]::Copy($archive,$privateZip,$false)
        $archive=$privateZip
    }
    if((Get-FileHash -LiteralPath $archive).Hash -ne '__ARCHIVE__' -or (Test-Path -LiteralPath $p)){exit 64}
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($archive,$p)
    $manifest=Join-Path $p 'MANIFEST.json'
    if((Get-FileHash -LiteralPath $manifest).Hash -ne '__MANIFEST__'){exit 65}
    $members=(Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json).files.PSObject.Properties
    foreach($member in $members){
        if($member.Name.Contains('..') -or $member.Name -notmatch '^[a-zA-Z0-9_./+\-]+$'){exit 65}
        $m=Join-Path $p $member.Name
        if((Get-Item -LiteralPath $m).Attributes -band [IO.FileAttributes]::ReparsePoint){exit 65}
        if((Get-FileHash -LiteralPath $m).Hash -ne $member.Value){exit 65}
    }
    $fixture=Join-Path $p 'c7_qualification\authority_fixture.py'
    [IO.File]::WriteAllBytes($fixture,[Convert]::FromBase64String('__FIXTURE_BYTES__'))
    if((Get-FileHash -LiteralPath $fixture).Hash -ne '__FIXTURE__'){exit 66}
    if(!$isSystem){
        $deps=Join-Path $p 'deps'
        [void][IO.Directory]::CreateDirectory($deps)
        foreach($wheel in (Get-ChildItem -LiteralPath (Join-Path $p 'wheels') -Filter '*.whl')){
            $z=[IO.Compression.ZipFile]::OpenRead($wheel.FullName)
            try {
                foreach($entry in $z.Entries){
                    if(!$entry.Name){continue}
                    if($entry.FullName -notmatch '^[a-zA-Z0-9_./+\-]+$' -or $entry.FullName.Contains('..')){exit 65}
                    $out=Join-Path $deps $entry.FullName
                    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($out))
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$out,$false)
                }
            } finally {$z.Dispose()}
        }
    }
    exit 42
}
if($mode -eq 'make-links'){
    $scratch=Join-Path $r 'scratch'
    $state=Get-Content -LiteralPath (Join-Path $scratch 'synthetic-proof.json') -Raw|ConvertFrom-Json
    if($state.digest -notmatch '^[a-f0-9]{64}$'){exit 71}
    $archives=Join-Path $scratch 'archives'
    $current=Join-Path $archives ('memory-'+$state.digest+'.v2a')
    $original=Join-Path $archives 'original.v2a'
    [IO.File]::Move($current,$original)
    [void](New-Item -ItemType SymbolicLink -Path $current -Target $original)
    [void](New-Item -ItemType SymbolicLink -Path (Join-Path $scratch 'archive-directory-link') -Target $archives)
    exit 42
}
$env:AI1_C7_OWNER=$identity.User.Value
$py=Join-Path $p 'runtime\python\python.exe'
if((Get-FileHash -LiteralPath $py).Hash -ne '42AC541168E97DEDB9AABD8BE335539FC41C682E414B9E8D137B164FB68683B0'){exit 67}
$logs=if($isSystem){$system}else{$r}
$log=Join-Path $logs ($mode+'.log')
$ErrorActionPreference='Continue'
if($mode -in 'provision','ordinary','verify'){
    $f=Join-Path $p 'c7_qualification\authority_fixture.py'
    if((Get-FileHash -LiteralPath $f).Hash -ne '__FIXTURE__'){exit 66}
    & $py -I -S -B $f $mode $r *> $log
} elseif($mode -eq 'binding'){
    & $py -I -S -B (Join-Path $p 'c7_qualification\binding_suite.py') *> $log
} else {
    & $py -I -S -B (Join-Path $p 'probe.py') $mode *> $log
}
exit $LASTEXITCODE
'@
$body=$body.Replace('__ROOT__',$parcel).Replace('__MODE__',$Mode).Replace('__ARCHIVE__',$ArchiveSha256).
    Replace('__MANIFEST__',$ManifestSha256).Replace('__FIXTURE__',$fixtureSha).
    Replace('__FIXTURE_BYTES__',$(if($Mode -in 'stage','stage-system'){$source64}else{''}))
$actor=if($Mode -in 'stage-system','make-links','provision','verify'){'System'}else{'ExistingLogin'}
$exitCode=Invoke-Guest $body $actor
[pscustomobject]@{mode=$Mode;actor=$actor;exit_code=$exitCode;archive_sha256=$ArchiveSha256;
                 manifest_sha256=$ManifestSha256;synthetic_fixture_sha256=$fixtureSha}
if($exitCode -ne 42){exit 1}
exit 0
