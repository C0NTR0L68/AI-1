param(
    [Parameter(Mandatory)][Guid] $SandboxId,
    [Parameter(Mandatory)][Guid] $TransferId,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{64}$')][string] $ExpectedSha256,
    [Parameter(Mandatory)][string] $OutputFile
)
$ErrorActionPreference = 'Stop'
if(Test-Path -LiteralPath $OutputFile){throw 'An output binary already exists'}
$name='AI1-C7-'+$TransferId.ToString('N')
$parcel='C:\Users\Public\Documents\'+$name
$suffix=[Guid]::NewGuid().ToString('N')
$packed=$parcel+'\release-artifact-'+$suffix+'.gz'
$reader=$parcel+'\artifact-word-'+$suffix+'.exe'

function Guest([string]$Body,[string]$Actor='System') {
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Body))
    $value=wsb exec --id $SandboxId --run-as $Actor --command "powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded" --raw
    if($LASTEXITCODE){ throw 'Guest export command refused' }
    return [long]($value|ConvertFrom-Json).ExitCode
}

$isolation=@'
$ErrorActionPreference='Stop'
if((whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
if((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
exit 42
'@
if((Guest $isolation ExistingLogin) -ne 42){throw 'Guest export isolation not confirmed'}

$stage=@'
$ErrorActionPreference='Stop'
try {
$current=[Security.Principal.WindowsIdentity]::GetCurrent()
if($current.User.Value -ne 'S-1-5-18'){exit 61}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
if((Get-Service AI1MemoryAuthority -ErrorAction SilentlyContinue)){exit 64}
$exe='C:\Program Files\__NAME__\service-release\Authority.exe'
$src=Get-Item -LiteralPath $exe
if(($src.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $src.Length -gt 65536 -or
   (Get-FileHash -LiteralPath $exe).Hash -cne '__SHA__'){exit 65}
$output=[IO.File]::Open('__PACKED__',[IO.FileMode]::CreateNew)
try{
    $compression=[IO.Compression.GZipStream]::new($output,[IO.Compression.CompressionMode]::Compress,$true)
    try{
        $sourceStream=[IO.File]::OpenRead($exe)
        try{$sourceStream.CopyTo($compression)}finally{$sourceStream.Dispose()}
    }finally{$compression.Dispose()}
    $output.Flush($true)
}finally{$output.Dispose()}
$source=@"
using System;
using System.IO;
public static class ArtifactWord {
    public static int Main(string[] args) {
        int word;
        if(args.Length!=1 || !Int32.TryParse(args[0],out word) || word<0 || word>8191) return 0;
        using(var file=File.OpenRead(@"__PACKED__")) {
            long offset=4L*word;
            if(offset>=file.Length) return 0;
            byte[] data=new byte[4];
            file.Position=offset;
            int need=(int)Math.Min(4,file.Length-offset);
            for(int pos=0;pos<need;) {
                int got=file.Read(data,pos,need-pos);
                if(got==0) return 0;
                pos+=got;
            }
            return BitConverter.ToInt32(data,0);
        }
    }
}
"@
Add-Type -TypeDefinition $source -OutputAssembly '__READER__' -OutputType ConsoleApplication
exit ([int](Get-Item -LiteralPath '__PACKED__').Length+100000)
} catch {
    [IO.File]::WriteAllText('__PARCEL__\export-stage-error.txt',$_.ToString()+' '+$_.InvocationInfo.ScriptLineNumber)
    exit 70
}
'@
$encodedLength=Guest ($stage.Replace('__NAME__',$name).Replace('__SHA__',$ExpectedSha256).
    Replace('__PACKED__',$packed).Replace('__READER__',$reader).Replace('__PARCEL__',$parcel))
$length=$encodedLength-100000
if($length -le 0 -or $length -gt 32768){throw "Binary export staging refused: $encodedLength"}
$words=[int][Math]::Ceiling($length/4.0)
$collected=0
$buffer=[byte[]]::new($words*4)
0..($words-1) | ForEach-Object -ThrottleLimit 8 -Parallel {
    $index=[int]$_
    $result=wsb exec --id $using:SandboxId --run-as ExistingLogin --command "$using:reader $index" --raw
    if($LASTEXITCODE){throw 'Guest artifact word unavailable'}
    $word=[long]($result|ConvertFrom-Json).ExitCode
    if($word -lt 0){$word+=4294967296L}
    if($word -lt 0 -or $word -gt 4294967295L){throw 'Invalid artifact word'}
    [pscustomobject]@{index=$index;bytes=[BitConverter]::GetBytes([uint32]$word)}
} | ForEach-Object {
    [Array]::Copy($_.bytes,0,$buffer,$_.index*4,4)
    $collected++
    if($collected%250 -eq 0 -or $collected -eq $words){"EXPORTED_WORDS=$collected/$words"}
}
if($collected -ne $words){throw 'Guest artifact transport incomplete'}
$compressed=[IO.MemoryStream]::new($buffer,0,[int]$length,$false)
try{
    $stream=[IO.Compression.GZipStream]::new($compressed,[IO.Compression.CompressionMode]::Decompress)
    $release=[IO.MemoryStream]::new()
    try{
        $block=[byte[]]::new(4096)
        while(($size=$stream.Read($block,0,$block.Length)) -gt 0){
            if($release.Length+$size -gt 65536){throw 'Artifact exceeds its size bound'}
            $release.Write($block,0,$size)
        }
        $bytes=$release.ToArray()
    }finally{$release.Dispose();$stream.Dispose()}
}finally{$compressed.Dispose()}
if($bytes.Length -gt 65536 -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)) -cne $ExpectedSha256){
    throw 'Exported artifact SHA-256 mismatch'
}
$out=[IO.File]::Open($OutputFile,[IO.FileMode]::CreateNew)
try{$out.Write($bytes);$out.Flush($true)}finally{$out.Dispose()}
"ARTIFACT_SHA256=$ExpectedSha256"
