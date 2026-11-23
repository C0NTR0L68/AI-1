using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;

internal sealed class Authority : ServiceBase
{
    private readonly string root = AppDomain.CurrentDomain.BaseDirectory;
    private Process worker;
    private Timer monitor;
    private volatile bool stopping;

    internal Authority()
    {
        ServiceName = "AI1MemoryAuthority";
        CanStop = true;
        AutoLog = false;
    }

    private static string Hash(string path)
    {
        using (var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
    }

    private string Input(string relative)
    {
        if (!Regex.IsMatch(relative, @"\A[A-Za-z0-9_./+\-]+\z") ||
            relative.StartsWith("/") || relative.Contains(".."))
            throw new InvalidOperationException("Invalid release member");
        string path = root;
        foreach (string part in relative.Split('/'))
        {
            path = Path.Combine(path, part);
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Release reparse point");
        }
        return path;
    }

    private void VerifyInputs()
    {
        string manifest = Input("inputs.sha256");
        if (Hash(manifest) != AuthorityPins.ManifestSha256)
            throw new InvalidOperationException("Release manifest mismatch");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in File.ReadLines(manifest))
        {
            string[] fields = line.Split(new[] {' '}, 2);
            if (fields.Length != 2 || !names.Add(fields[1]) || Hash(Input(fields[1])) != fields[0])
                throw new InvalidOperationException("Release input mismatch");
        }
        if (!names.Contains("payload/runtime/python/python.exe") ||
            !names.Contains("payload/app/memory_authority_service.py"))
            throw new InvalidOperationException("Incomplete release manifest");
        // The installation directory has an independently admitted administrator ACL.
        // Reject unpinned imports and DLLs as well as byte changes to pinned files.
        foreach (string subtree in new[] {"payload"})
        {
            var pending = new Stack<string>();
            pending.Push(Input(subtree));
            while (pending.Count != 0)
            {
                string directory = pending.Pop();
                foreach (string entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    var attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                        throw new InvalidOperationException("Release reparse point");
                    if ((attributes & FileAttributes.Directory) != 0)
                        pending.Push(entry);
                    else if (!names.Contains(entry.Substring(root.Length).Replace('\\', '/')))
                        throw new InvalidOperationException("Unpinned release file");
                }
            }
        }
    }

    protected override void OnStart(string[] args)
    {
        bool provision = args.Length == 1 && args[0] == "provision";
        if (args.Length != 0 && !provision)
            throw new InvalidOperationException("Invalid authority start command");
        VerifyInputs();
        var launch = new ProcessStartInfo(Input("payload/runtime/python/python.exe"));
        launch.Arguments = "-I -S -B \"" + Input("payload/app/memory_authority_service.py") + "\"" +
            (provision ? " provision" : " serve");
        launch.WorkingDirectory = root;
        launch.UseShellExecute = false;
        launch.CreateNoWindow = true;
        launch.RedirectStandardInput = true;
        launch.RedirectStandardOutput = true;
        launch.RedirectStandardError = true;
        launch.EnvironmentVariables["PATH"] = Environment.SystemDirectory;
        worker = Process.Start(launch);
        try
        {
            var ready = worker.StandardOutput.ReadLineAsync();
            worker.BeginErrorReadLine();
            if (!ready.Wait(15000) || ready.Result != "READY" || worker.HasExited)
                throw new InvalidOperationException("Authority failed startup");
            monitor = new Timer(_ =>
            {
                if (!stopping && worker.HasExited)
                    Environment.Exit(79);
            }, null, 200, 200);
        }
        catch
        {
            if (!worker.HasExited) { worker.Kill(); worker.WaitForExit(5000); }
            worker.Dispose();
            throw;
        }
    }

    protected override void OnStop()
    {
        stopping = true;
        using (var stopped = new ManualResetEvent(false))
        {
            if (monitor != null && monitor.Dispose(stopped) && !stopped.WaitOne(2000))
                throw new InvalidOperationException("Authority monitor did not drain");
        }
        try
        {
            worker.StandardInput.WriteLine("STOP");
            worker.StandardInput.Flush();
            if (!worker.WaitForExit(16000))
            {
                worker.Kill();
                worker.WaitForExit(5000);
                throw new InvalidOperationException("Authority exceeded shutdown deadline");
            }
            if (worker.ExitCode != 0)
                throw new InvalidOperationException("Authority shutdown unconfirmed");
        }
        finally { worker.Dispose(); }
    }

    public static void Main()
    {
        ServiceBase.Run(new Authority());
    }
}
