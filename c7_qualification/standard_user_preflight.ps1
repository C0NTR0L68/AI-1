param([Parameter(Mandatory)][Guid] $ParcelId,[switch] $Bridge)
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if ($id.IsSystem -or (whoami) -notmatch '\\wdagutilityaccount$'){exit 61}
if ((Test-Path '\\tsclient\C') -or (Test-Path '\\tsclient\D')){exit 62}
if (@([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()|Where-Object{
    $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback'}).Count){exit 63}
$root=Join-Path 'C:\Users\Public\Documents' ('AI1-C7-'+$ParcelId.ToString('N'))
if($Bridge){
    if(!(Test-Path -LiteralPath (Join-Path $root 'c7-binding.zip'))){exit 64}
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($id.User)
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in $id.User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18')){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $root -AclObject $acl
} else {
    if(Test-Path -LiteralPath $root){exit 64}
    [void][IO.Directory]::CreateDirectory($root)
}
$name='AI1C7OrdinaryProbe'
if(Get-LocalUser -Name $name -ErrorAction SilentlyContinue){exit 65}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public static class Ai1StandardGuest
{
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct Startup
    {
        public int size;
        public string reserved,desktop,title;
        public int x,y,width,height,cols,rows,fill,flags;
        public short show,reservedSize;
        public IntPtr reservedPointer,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Child
    {
        public IntPtr process, thread;
        public int pid, tid;
    }

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    private static extern bool CreateProcessWithLogonW(string user,string domain,IntPtr password,
        uint logonFlags,string file,StringBuilder args,uint flags,IntPtr environment,string cwd,
        ref Startup startup,out Child result);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    private static extern bool LogonUserW(string user,string domain,IntPtr password,int type,int provider,out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr process,int rights,out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int bytes,out int required);
    [DllImport("kernel32.dll")]
    private static extern int WaitForSingleObject(IntPtr handle,int millis);
    [DllImport("kernel32.dll")]
    private static extern int ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")]
    private static extern bool GetExitCodeProcess(IntPtr handle,out int code);
    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(IntPtr handle,int code);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static int TokenEvidence(IntPtr token, string expected)
    {
        int size;
        GetTokenInformation(token,1,IntPtr.Zero,0,out size);
        if(size < IntPtr.Size || size > 4096) return 73;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if(!GetTokenInformation(token,1,buffer,size,out size)) return 73;
            if(new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value != expected) return 71;
        }
        finally { Marshal.FreeHGlobal(buffer); }
        GetTokenInformation(token,25,IntPtr.Zero,0,out size);
        if(size < IntPtr.Size || size > 4096) return 73;
        buffer = Marshal.AllocHGlobal(size);
        try
        {
            if(!GetTokenInformation(token,25,buffer,size,out size)) return 73;
            if(new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value != "S-1-16-8192") return 74;
        }
        finally { Marshal.FreeHGlobal(buffer); }
        buffer = Marshal.AllocHGlobal(4);
        try
        {
            if(!GetTokenInformation(token,20,buffer,4,out size) || Marshal.ReadInt32(buffer) != 0) return 75;
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return 42;
    }

    public static int VerifyCredentials(string user,string domain,IntPtr password,string sid)
    {
        IntPtr token;
        if(!LogonUserW(user,domain,password,2,0,out token)) return 20000 + Marshal.GetLastWin32Error();
        try { return TokenEvidence(token,sid); }
        finally { CloseHandle(token); }
    }

    public static int Launch(string user,string domain,IntPtr password,string sid)
    {
        string home=Environment.GetFolderPath(Environment.SpecialFolder.System);
        string pythonless=System.IO.Path.Combine(home,@"WindowsPowerShell\v1.0\powershell.exe");
        return LaunchVerified(user,domain,password,sid,pythonless,
            " -NoLogo -NoProfile -NonInteractive -Command exit 42",home);
    }

    public static int LaunchFixture(string user,string domain,IntPtr password,string sid,string parcel,string kind)
    {
        if(!System.Text.RegularExpressions.Regex.IsMatch(parcel,@"\AAI1-C7-[a-f0-9]{32}\z")
            || !System.Text.RegularExpressions.Regex.IsMatch(kind,
                @"\A(ipc|denied|counterfeit|dropped|ipc-recovered|e2e-seal|e2e-live|e2e-drop|e2e-timeout|e2e-down|e2e-restart|write|resume|verify-write)\z")) return 78;
        string root=System.IO.Path.Combine(@"C:\Program Files",parcel,"payload");
        string python=System.IO.Path.Combine(root,@"runtime\python\python.exe");
        string probe=System.IO.Path.Combine(root,@"c7_qualification\scm_probe.py");
        string cwd=System.IO.Path.Combine(@"C:\Users\Public\Documents",parcel,"ordinary");
        return LaunchVerified(user,domain,password,sid,python," -I -S -B \"" + probe + "\" " + kind,cwd);
    }

    private static int LaunchVerified(string user,string domain,IntPtr password,string sid,
                                      string executable,string args,string home)
    {
        var line=new StringBuilder("\"" + executable + "\"" + args);
        var startup=new Startup();
        startup.size=Marshal.SizeOf(typeof(Startup));
        Child child;
        if(!CreateProcessWithLogonW(user,domain,password,1,executable,line,0x08000004,
                                   IntPtr.Zero,home,ref startup,out child))
            return 30000 + Marshal.GetLastWin32Error();
        bool completed=false;
        try
        {
            IntPtr token;
            if(!OpenProcessToken(child.process,8,out token)) return 76;
            int evidence;
            try { evidence=TokenEvidence(token,sid); }
            finally { CloseHandle(token); }
            if(evidence!=42) return evidence;
            if(ResumeThread(child.thread)!=1 || WaitForSingleObject(child.process,18000)!=0) return 77;
            completed=true;
            int code;
            return GetExitCodeProcess(child.process,out code) ? code : 78;
        }
        finally
        {
            if(!completed && TerminateProcess(child.process,1)) WaitForSingleObject(child.process,3000);
            CloseHandle(child.thread); CloseHandle(child.process);
        }
    }
}
'@

$created=$false
$result=[ordered]@{account=$null;local_logon=$null;ordinary_process=$null;cleanup=$null}
function Publish-Receipt([string] $Path,[string] $Contents){
    $pending=$Path+'.pending'
    $file=[IO.File]::Open($pending,[IO.FileMode]::CreateNew)
    try {
        $bytes=[Text.Encoding]::ASCII.GetBytes($Contents)
        $file.Write($bytes,0,$bytes.Length)
        $file.Flush($true)
    } finally { $file.Dispose() }
    [IO.File]::Move($pending,$Path)
}
try {
    $password=ConvertTo-SecureString ('Q8z!'+[guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $account=New-LocalUser -Name $name -Password $password
    $created=$true
    $userSid=$account.SID.Value
    $administrators=@(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')))
    if(!$account.Enabled -or $userSid -in $administrators.SID.Value){throw 'Standard guest principal not confirmed'}
    $result.account=42
    $memory=[Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($password)
    try {
        $result.local_logon=[Ai1StandardGuest]::VerifyCredentials($name,$env:COMPUTERNAME,$memory,$userSid)
        $result.ordinary_process=[Ai1StandardGuest]::Launch($name,$env:COMPUTERNAME,$memory,$userSid)
        if($Bridge -and $result.ordinary_process -eq 42 -and $result.local_logon -eq 42){
            Publish-Receipt (Join-Path $root 'bridge-ready.json') (@{sid=$userSid;preflight=42}|ConvertTo-Json)
            $deadline=[DateTime]::UtcNow.AddMinutes(5)
            $stop=Join-Path $root 'bridge-done'
            while(!(Test-Path -LiteralPath $stop)){
                if([DateTime]::UtcNow -gt $deadline){throw 'Synthetic bridge deadline'}
                foreach($phase in 'ipc','denied','counterfeit','dropped','ipc-recovered',
                    'e2e-seal','e2e-live','e2e-drop','e2e-timeout','e2e-down','e2e-restart','write','resume','verify-write'){
                    $request=Join-Path $root ($phase+'.request')
                    $reply=Join-Path $root ($phase+'.reply')
                    if((Test-Path -LiteralPath $request) -and !(Test-Path -LiteralPath $reply)){
                        $value=[Ai1StandardGuest]::LaunchFixture($name,$env:COMPUTERNAME,$memory,$userSid,
                                                                 (Split-Path -Leaf $root),$phase)
                        Publish-Receipt $reply ([string]$value)
                    }
                }
                Start-Sleep -Milliseconds 150
            }
            $result.bridge_closed=42
        }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($memory)
        $password.Dispose()
    }
} catch {
    $failure=$_.Exception
    while($failure.InnerException){$failure=$failure.InnerException}
    $result.error_hr=$failure.HResult
    [IO.File]::WriteAllText((Join-Path $root 'preflight-error.txt'), $failure.GetType().Name)
} finally {
    if($created){Remove-LocalUser -Name $name}
    if(!(Get-LocalUser -Name $name -ErrorAction SilentlyContinue)){$result.cleanup=42}
    $result|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'standard-preflight.json') -Encoding ascii
}
if($result.ordinary_process -eq 42 -and $result.cleanup -eq 42 -and (!$Bridge -or $result.bridge_closed -eq 42)){exit 42}
exit 1
