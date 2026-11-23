// Disposable SCM adapter. Built inside the isolated guest only.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

internal sealed class AuthorityFixtureService : ServiceBase
{
    private Process worker;
    private Timer watchdog;
    private volatile bool stopping;
    private readonly string home = AppDomain.CurrentDomain.BaseDirectory;

    public AuthorityFixtureService()
    {
        ServiceName = "AI1C7GuestAuthority";
        CanStop = true;
        AutoLog = false;
    }

    protected override void OnStart(string[] args)
    {
        if (args.Length != 0) throw new InvalidOperationException("Fixed synthetic launch only");
        string state = Path.Combine(home, "state");
        File.Delete(Path.Combine(state, "ready"));
        File.Delete(Path.Combine(state, "stop"));
        var info = new ProcessStartInfo(Path.Combine(home, @"payload\runtime\python\python.exe"));
        info.Arguments = "-I -S -B \"" + Path.Combine(home, @"payload\c7_qualification\scm_probe.py") + "\" serve";
        info.WorkingDirectory = state;
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        worker = Process.Start(info);
        try
        {
            var clock = Stopwatch.StartNew();
            while (!File.Exists(Path.Combine(state, "ready")))
            {
                if (worker.HasExited || clock.ElapsedMilliseconds > 12000)
                    throw new InvalidOperationException("Synthetic authority did not become ready");
                Thread.Sleep(60);
            }
            watchdog = new Timer(_ =>
            {
                if (!stopping && worker.HasExited)
                    Environment.Exit(79);
            }, null, 200, 200);
        }
        catch
        {
            if (!worker.HasExited) { worker.Kill(); worker.WaitForExit(4000); }
            worker.Dispose();
            throw;
        }
    }

    protected override void OnStop()
    {
        stopping = true;
        using (var finished = new ManualResetEvent(false))
        {
            if (watchdog != null && watchdog.Dispose(finished))
                finished.WaitOne(2000);
        }
        File.WriteAllBytes(Path.Combine(home, @"state\stop"), new byte[0]);
        if (!worker.WaitForExit(6000))
        {
            worker.Kill();
            worker.WaitForExit(4000);
            throw new InvalidOperationException("Synthetic worker did not drain");
        }
        if (worker.ExitCode != 42) throw new InvalidOperationException("Worker stop was unconfirmed");
        worker.Dispose();
    }

    public static int Main(string[] args)
    {
        if (args.Length != 0)
        {
            if (args.Length != 2 || args[0] != "--client" ||
                (args[1] != "preflight" && args[1] != "ipc" && args[1] != "denied")
                || !WindowsIdentity.GetCurrent().IsSystem) return 78;
            return StartOrdinary(args[1]);
        }
        ServiceBase.Run(new AuthorityFixtureService());
        return 0;
    }

    private static int StartOrdinary(string action)
    {
        string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
        string name = Path.GetFileName(root);
        if (Path.GetDirectoryName(root) != @"C:\Program Files" ||
            !System.Text.RegularExpressions.Regex.IsMatch(name, @"\AAI1-C7-[a-f0-9]{32}\z")) return 78;
        string python = Path.Combine(root, @"payload\runtime\python\python.exe");
        string probe = Path.Combine(root, @"payload\c7_qualification\scm_probe.py");
        string cwd = Path.Combine(@"C:\Users\Public\Documents", name, "ordinary");
        string password = Console.ReadLine();
        if (String.IsNullOrEmpty(password)) return 78;
        IntPtr token;
        if (!LogonUserW("AI1C7GuestClient", Environment.MachineName, password, 2, 0, out token))
            return 20000 + Marshal.GetLastWin32Error();
        password = null;
        try
        {
            IntPtr environment;
            if (!CreateEnvironmentBlock(out environment, token, false))
                return 20000 + Marshal.GetLastWin32Error();
            try
            {
                var startup = new Startup();
                startup.size = Marshal.SizeOf(typeof(Startup));
                var command = new StringBuilder("\"" + python + "\" -I -S -B \"" + probe + "\" " + action);
                Child result;
                if (!CreateProcessAsUserW(token, python, command, IntPtr.Zero, IntPtr.Zero, false,
                    0x08000400, environment, cwd, ref startup, out result))
                    return 20000 + Marshal.GetLastWin32Error();
                try
                {
                    if (WaitForSingleObject(result.process, 14000) != 0)
                    {
                        if (TerminateProcess(result.process, 1)) WaitForSingleObject(result.process, 3000);
                        return 79;
                    }
                    int code;
                    return GetExitCodeProcess(result.process, out code) ? code : 79;
                }
                finally { CloseHandle(result.thread); CloseHandle(result.process); }
            }
            finally { DestroyEnvironmentBlock(environment); }
        }
        finally { CloseHandle(token); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct Startup
    {
        public int size;
        public string reserved, desktop, title;
        public int x, y, width, height, columns, rows, fill, flags;
        public short show, reservedSize;
        public IntPtr reservedPointer, input, output, error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Child
    {
        public IntPtr process, thread;
        public int pid, tid;
    }

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool LogonUserW(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CreateProcessAsUserW(IntPtr token, string file, StringBuilder command,
        IntPtr processAttrs, IntPtr threadAttrs, bool inherit, uint flags, IntPtr environment,
        string cwd, ref Startup startup, out Child result);
    [DllImport("userenv.dll", SetLastError=true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll")]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern int WaitForSingleObject(IntPtr handle, int millis);
    [DllImport("kernel32.dll")]
    private static extern bool GetExitCodeProcess(IntPtr handle, out int code);
    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(IntPtr handle, int code);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
