// Disposable SCM adapter. Built inside the isolated guest only.
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
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

    public static void Main()
    {
        ServiceBase.Run(new AuthorityFixtureService());
    }
}
