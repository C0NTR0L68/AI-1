param([Parameter(Mandatory)][Guid] $TransferId)
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if($id.User.Value -ne 'S-1-5-18'){exit 61}
if(@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 62}
$root=Join-Path 'C:\Program Files' ('AI1-C7-'+$TransferId.ToString('N'))
$config=Get-Content -LiteralPath (Join-Path $root 'enrollment.json') -Raw|ConvertFrom-Json
$system='S-1-5-18'
$writeMask=0xD0156 # DELETE, WRITE_DAC, WRITE_OWNER, file/directory mutation and DELETE_CHILD
$records=@(
    @{path=$root; protected=$true; allowed=@($system,$config.authority,$config.client)},
    @{path=(Join-Path $root 'Authority.exe'); protected=$false; allowed=@($system,$config.authority,$config.client)},
    @{path=(Join-Path $root 'state'); protected=$true; allowed=@($system,$config.authority)},
    @{path=(Join-Path $root 'state\head.sqlite3'); protected=$false; allowed=@($system,$config.authority)},
    @{path=(Join-Path $root 'archives'); protected=$true; allowed=@($system,$config.authority,$config.client)},
    @{path=(Join-Path $root 'archives\archive.synthetic'); protected=$false; allowed=@($system,$config.authority,$config.client)}
)
foreach($entry in $records){
    $item=Get-Item -LiteralPath $entry.path
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){exit 63}
    $acl=Get-Acl -LiteralPath $entry.path
    if($acl.AreAccessRulesProtected -ne $entry.protected -or
       $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $system){exit 64}
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if($rules.Count -ne $entry.allowed.Count){exit 65}
    foreach($rule in $rules){
        if($rule.IdentityReference.Value -notin $entry.allowed -or $rule.AccessControlType -ne 'Allow'){exit 65}
        if($rule.IdentityReference.Value -eq $config.client -and ([int]$rule.FileSystemRights -band $writeMask)){exit 66}
    }
}
exit 42
