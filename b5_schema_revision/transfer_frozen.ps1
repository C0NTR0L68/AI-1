param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][string] $CandidateArchive,
    [ValidateRange(1,8)][int] $Throttle = 8
)
$ErrorActionPreference = 'Stop'
$sha = '4BCE5F2BEF7CB4374CB42F8AFDD56C6BC5304CAD7A5754282E5808C417A66D15'
$archive = (Resolve-Path -LiteralPath $CandidateArchive).Path
if ((Get-FileHash -LiteralPath $archive).Hash -ne $sha) { throw 'Candidate archive SHA mismatch.' }
$chunk = 22000
$size = (Get-Item -LiteralPath $archive).Length
$total = [int][Math]::Ceiling($size / $chunk)
$id = $SandboxId.ToString()
$root = 'C:\Users\Public\Documents\AI1-B5-' + $TransferId.ToString('N')
$receiver = $root + '\chunkrecv.exe'

function Invoke-Guest([string] $Code) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Code))
    $response = wsb exec --id $id --run-as ExistingLogin --command "powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded" --raw
    if ($LASTEXITCODE -ne 0) { throw 'Guest command unavailable.' }
    return [int](($response | ConvertFrom-Json).ExitCode)
}

$source = @'
using System;
using System.IO;
using System.Globalization;
using System.Security.Cryptography;
public static class Receiver {
 const string Parcel = @"__ROOT__";
 public static int Main(string[] args) {
  try {
   int index, count;
   if (args.Length != 4 ||
       !Int32.TryParse(args[0], NumberStyles.None, CultureInfo.InvariantCulture, out index) ||
       !Int32.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out count) ||
       index < 0 || index >= __TOTAL__ || count < 1 || count > 22000 ||
       (File.GetAttributes(Parcel) & FileAttributes.ReparsePoint) != 0) return 70;
   var bytes = Convert.FromBase64String(args[3]);
   if (bytes.Length != count || Compute(bytes) != args[2]) return 71;
   var path = Path.Combine(Parcel, index.ToString("D6", CultureInfo.InvariantCulture) + ".part");
   if (!File.Exists(path)) {
    using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
     stream.Write(bytes, 0, bytes.Length);
     stream.Flush(true);
    }
   }
   if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return 72;
   return Compute(File.ReadAllBytes(path)) == args[2] ? 42 : 73;
  } catch (Exception) { return 75; }
 }
 static string Compute(byte[] bytes) {
  using (var hash = SHA256.Create())
   return BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "");
 }
}
'@
$source = $source.Replace('__ROOT__',$root).Replace('__TOTAL__',$total.ToString())
$source64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($source))
$setup = @'
$ErrorActionPreference='Stop'
if ((whoami) -notmatch '\\wdagutilityaccount$') { exit 61 }
if ((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')) { exit 62 }
if (@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
      Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' }).Count) { exit 63 }
$d='__ROOT__'
if (!(Test-Path -LiteralPath $d)) { [void][IO.Directory]::CreateDirectory($d) }
if ((Get-Item -LiteralPath $d).Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 70 }
$e=Join-Path $d 'chunkrecv.exe'
if (!(Test-Path -LiteralPath $e)) {
  $s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__'))
  Add-Type -TypeDefinition $s -OutputAssembly $e -OutputType ConsoleApplication
}
if ((Get-Item -LiteralPath $e).Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 70 }
exit 42
'@
$setupCode = Invoke-Guest ($setup.Replace('__ROOT__',$root).Replace('__SOURCE__',$source64))
if ($setupCode -ne 42) { throw "Guest setup refused: $setupCode." }
$timer = [Diagnostics.Stopwatch]::StartNew()
$confirmed = 0
0..($total - 1) | ForEach-Object -ThrottleLimit $Throttle -Parallel {
    $ErrorActionPreference = 'Stop'
    $index = $_
    $stream = [IO.File]::OpenRead($using:archive)
    try {
        $stream.Position = [long]$index * $using:chunk
        $count = [int][Math]::Min($using:chunk, $stream.Length - $stream.Position)
        $bytes = [byte[]]::new($count)
        $stream.ReadExactly($bytes, 0, $count)
    } finally { $stream.Dispose() }
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    $base64 = [Convert]::ToBase64String($bytes)
    $response = wsb exec --id $using:id --run-as ExistingLogin --command "$using:receiver $index $count $digest $base64" --raw
    if ($LASTEXITCODE -ne 0 -or ($response|ConvertFrom-Json).ExitCode -ne 42) { throw "Block $index refused." }
    $index
} | ForEach-Object {
    $confirmed++
    if ($confirmed % 240 -eq 0 -or $confirmed -eq $total) { "CONFIRMED=$confirmed/$total" }
}
if ($confirmed -ne $total) { throw 'Candidate transfer incomplete.' }
$join = @'
$ErrorActionPreference='Stop'
$r='__ROOT__'
$z=Join-Path $r 'AI-1-B5-Offline.zip'
if (!(Test-Path -LiteralPath $z)) {
  $q=Join-Path $r ([guid]::NewGuid().ToString('N')+'.pending')
  $o=[IO.File]::Open($q,[IO.FileMode]::CreateNew)
  try {
    for($i=0;$i -lt __TOTAL__;$i++) {
      $p=Join-Path $r ($i.ToString('D6')+'.part')
      if ((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint) {exit 72}
      $f=[IO.File]::OpenRead($p)
      try {$f.CopyTo($o)} finally {$f.Dispose()}
    }
    $o.Flush($true)
  } finally {$o.Dispose()}
  if ((Get-Item -LiteralPath $q).Length -ne __SIZE__ -or (Get-FileHash -LiteralPath $q).Hash -ne '__SHA__') {exit 73}
  [IO.File]::Move($q,$z)
}
if ((Get-Item -LiteralPath $z).Attributes -band [IO.FileAttributes]::ReparsePoint -or
    (Get-Item -LiteralPath $z).Length -ne __SIZE__ -or (Get-FileHash -LiteralPath $z).Hash -ne '__SHA__') {exit 73}
exit 42
'@
$join = $join.Replace('__ROOT__',$root).Replace('__TOTAL__',$total.ToString()).Replace('__SIZE__',$size.ToString()).Replace('__SHA__',$sha)
$joined = Invoke-Guest $join
if ($joined -ne 42) { throw "Complete guest verification failed: $joined." }
"GUEST_FROZEN_SHA256_MATCH=$sha"
"ELAPSED_SECONDS=$($timer.Elapsed.TotalSeconds)"
