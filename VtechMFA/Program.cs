using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace VtechMFA
{
    public sealed class VtechMFAService : ServiceBase
    {
        public const string ServiceNameConst = "VtechMFADeviceAuthService";
        private static readonly DateTime ExpiryDate = new DateTime(2027, 3, 20);

        private HttpListener _listener;
        private Task _listenerTask;
        private Task _updaterTask;
        private CancellationTokenSource _cts;
        private Config _config;

        public VtechMFAService()
        {
            ServiceName = ServiceNameConst;
            CanShutdown = true;
            CanStop = true;
        }

        protected override void OnStart(string[] args)
        {
            if (DateTime.Now > ExpiryDate)
            {
                Logger.Log("License expired. Service will not start.");
                Stop();
                return;
            }

            try
            {
                Logger.Log("=== Service starting (v" + Assembly.GetExecutingAssembly().GetName().Version + ") ===");
                LogServiceDetails();

                _config = Config.Load(Logger.Log);
                _cts = new CancellationTokenSource();

                StartHttps();

                var updater = new AutoUpdater(_config, Logger.Log);
                _updaterTask = Task.Run(() => updater.RunLoopAsync(_cts.Token));
            }
            catch (Exception ex)
            {
                Logger.Log("Service start error: " + ex);
                Stop();
            }
        }

        protected override void OnStop()
        {
            Logger.Log("Service stopping...");
            try
            {
                if (_cts != null) _cts.Cancel();

                if (_listener != null)
                {
                    try { _listener.Stop(); } catch (ObjectDisposedException) { }
                    try { _listener.Close(); } catch { }
                    _listener = null;
                }

                if (_listenerTask != null)
                {
                    try { _listenerTask.Wait(5000); } catch { }
                }
                if (_updaterTask != null)
                {
                    try { _updaterTask.Wait(2000); } catch { }
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Error stopping listener: " + ex);
            }
            Logger.Log("Service stopped.");
        }

        private void StartHttps()
        {
            X509Certificate2 cert = CertManager.EnsureCertificate(Logger.Log);

            CertManager.EnsureUrlAcl(_config.EndpointPrefix, Logger.Log);
            bool bound = CertManager.BindCertToPort(_config.IpPort, cert.Thumbprint, Logger.Log);
            if (!bound)
                Logger.Log("WARNING: SSL cert binding may have failed. Listener may not start.");

            _listener = new HttpListener();
            _listener.Prefixes.Add(_config.EndpointPrefix);
            _listener.Start();
            Logger.Log("Listening on " + _config.EndpointPrefix);

            _listenerTask = Task.Run(() => ListenLoop(_cts.Token));
        }

        private async Task ListenLoop(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested && _listener != null && _listener.IsListening)
                {
                    HttpListenerContext context;
                    try
                    {
                        context = await _listener.GetContextAsync();
                    }
                    catch (ObjectDisposedException) { break; }
                    catch (HttpListenerException ex)
                    {
                        Logger.Log("Listener error: " + ex.Message + " (code " + ex.ErrorCode + ")");
                        break;
                    }

                    _ = Task.Run(() => HandleRequestAsync(context));
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Listener loop crashed: " + ex);
            }
        }

        private async Task HandleRequestAsync(HttpListenerContext context)
        {
            try
            {
                ApplyCorsHeaders(context);

                if (context.Request.HttpMethod == "OPTIONS")
                {
                    context.Response.StatusCode = (int)HttpStatusCode.NoContent;
                    return;
                }

                string path = context.Request.Url.AbsolutePath.TrimEnd('/').ToLowerInvariant();
                if (path == "") path = "/";

                switch (path)
                {
                    case "/device-info":
                    case "/":
                        await WriteDeviceInfo(context);
                        break;
                    case "/health":
                        await WriteJson(context, new { status = "ok", service = ServiceNameConst });
                        break;
                    case "/version":
                        await WriteJson(context, new
                        {
                            version = Assembly.GetExecutingAssembly().GetName().Version.ToString(),
                            expiry = ExpiryDate.ToString("yyyy-MM-dd"),
                            updateRepo = _config.UpdateRepoOwner + "/" + _config.UpdateRepoName
                        });
                        break;
                    default:
                        context.Response.StatusCode = 404;
                        break;
                }
            }
            catch (Exception ex)
            {
                Logger.Log("Request handling error: " + ex);
                try { context.Response.StatusCode = 500; } catch { }
            }
            finally
            {
                try { context.Response.Close(); } catch { }
            }
        }

        private void ApplyCorsHeaders(HttpListenerContext context)
        {
            var req = context.Request;
            var resp = context.Response;

            string origin = req.Headers["Origin"];
            string allowOrigin = "*";
            if (_config.AllowedOrigins != null && _config.AllowedOrigins.Length > 0
                && Array.IndexOf(_config.AllowedOrigins, "*") < 0)
            {
                allowOrigin = Array.IndexOf(_config.AllowedOrigins, origin) >= 0 ? origin : _config.AllowedOrigins[0];
            }

            resp.Headers["Access-Control-Allow-Origin"] = allowOrigin;
            resp.Headers["Vary"] = "Origin";
            resp.Headers["Access-Control-Allow-Methods"] = "GET, OPTIONS";
            resp.Headers["Access-Control-Allow-Headers"] = req.Headers["Access-Control-Request-Headers"] ?? "Content-Type, Authorization";

            // Private Network Access (Chrome 130+ requires this for HTTPS->loopback calls).
            if (req.Headers["Access-Control-Request-Private-Network"] == "true"
                || req.Headers["Origin"] != null)
            {
                resp.Headers["Access-Control-Allow-Private-Network"] = "true";
            }

            resp.Headers["Cache-Control"] = "no-store";
        }

        private async Task WriteDeviceInfo(HttpListenerContext context)
        {
            Tuple<string, string> publicIPs = GetPublicIP();
            var deviceInfo = new
            {
                SerialNumber = GetSerialNumber(),
                MachineName = Environment.MachineName,
                LocalIPv4 = GetLocalIPAddress(),
                PublicIPv4 = publicIPs.Item1,
                PublicIPv6 = publicIPs.Item2,
                InstalledAntivirus = GetInstalledAntivirus(),
                ServiceVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString()
            };
            await WriteJson(context, deviceInfo);
        }

        private static async Task WriteJson(HttpListenerContext context, object payload)
        {
            string json = JsonSerializer.Serialize(payload);
            byte[] buffer = Encoding.UTF8.GetBytes(json);
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            context.Response.ContentLength64 = buffer.Length;
            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }

        #region Device info helpers

        private static string GetSerialNumber()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                        return obj["SerialNumber"]?.ToString() ?? "UNKNOWN";
                }
            }
            catch (Exception ex) { Logger.Log("Error fetching serial number: " + ex.Message); }
            return "ERROR";
        }

        private static string GetLocalIPAddress()
        {
            try
            {
                IPAddress[] ipList = Dns.GetHostEntry(Dns.GetHostName()).AddressList;
                foreach (IPAddress ip in ipList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                        return ip.ToString();
                }
            }
            catch (Exception ex) { Logger.Log("Error fetching IP address: " + ex.Message); }
            return "UNKNOWN";
        }

        private static List<string> GetInstalledAntivirus()
        {
            var list = new List<string>();
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntivirusProduct"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["displayName"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(name)) list.Add(name);
                    }
                }
            }
            catch (Exception ex) { Logger.Log("Error fetching antivirus details: " + ex.Message); }
            if (list.Count == 0) list.Add("No antivirus detected");
            return list;
        }

        private static Tuple<string, string> GetPublicIP()
        {
            try
            {
                if (!IsInternetAvailable()) return Tuple.Create("OFFLINE", "OFFLINE");
                using (var client = new WebClient())
                {
                    string ipv4 = client.DownloadString("https://api.ipify.org?format=text").Trim();
                    string ipv6 = client.DownloadString("https://api64.ipify.org?format=text").Trim();
                    return Tuple.Create(ipv4, ipv6);
                }
            }
            catch { return Tuple.Create("OFFLINE", "OFFLINE"); }
        }

        private static bool IsInternetAvailable()
        {
            try
            {
                using (var client = new WebClient())
                using (client.OpenRead("http://clients3.google.com/generate_204"))
                    return true;
            }
            catch { return false; }
        }

        private static void LogServiceDetails()
        {
            try
            {
                string user = WindowsIdentity.GetCurrent()?.Name ?? "UNKNOWN";
                Logger.Log("Running as: " + user + ", PID: " + Process.GetCurrentProcess().Id);
            }
            catch (Exception ex) { Logger.Log("Error retrieving service details: " + ex.Message); }
        }

        #endregion

        public static void Main(string[] args)
        {
            try
            {
                if (args != null && args.Length > 0)
                {
                    string cmd = args[0].ToLowerInvariant();
                    if (cmd == "--install" || cmd == "/install")  { Installer.Install(); return; }
                    if (cmd == "--uninstall" || cmd == "/uninstall") { Installer.Uninstall(); return; }
                    if (cmd == "--check-update" || cmd == "/check-update")
                    {
                        ForceUpdateCheck().GetAwaiter().GetResult();
                        return;
                    }
                }

                if (DateTime.Now > ExpiryDate)
                {
                    Console.WriteLine("License expired. Exiting.");
                    return;
                }

                if (Environment.UserInteractive)
                {
                    var svc = new VtechMFAService();
                    svc.OnStart(null);
                    Console.WriteLine("Press Enter to stop...");
                    Console.ReadLine();
                    svc.OnStop();
                }
                else
                {
                    ServiceBase.Run(new VtechMFAService());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Fatal error: " + ex);
                Logger.Log("Fatal error: " + ex);
            }
        }

        private static async Task ForceUpdateCheck()
        {
            var cfg = Config.Load(Console.WriteLine);
            var updater = new AutoUpdater(cfg, Console.WriteLine);
            using (var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10)))
                await updater.CheckOnceAsync(cts.Token);
        }
    }

    internal static class Logger
    {
        private const long MaxLogSizeBytes = 10 * 1024 * 1024;
        private static readonly object _lock = new object();

        public static void Log(string message)
        {
            try
            {
                Directory.CreateDirectory(Config.LogDir);
                string path = Path.Combine(Config.LogDir, "service.log");

                lock (_lock)
                {
                    if (File.Exists(path) && new FileInfo(path).Length > MaxLogSizeBytes)
                    {
                        string rotated = Path.Combine(Config.LogDir, "service.1.log");
                        try { if (File.Exists(rotated)) File.Delete(rotated); } catch { }
                        try { File.Move(path, rotated); } catch { }
                    }
                    File.AppendAllText(path, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + message + Environment.NewLine);
                }
            }
            catch { }
        }
    }

    internal static class Installer
    {
        public static void Install()
        {
            string exe = Assembly.GetExecutingAssembly().Location;
            RunSc("create " + VtechMFAService.ServiceNameConst
                + " binPath= \"" + exe + "\""
                + " start= auto"
                + " DisplayName= \"Vtech MFA Device Auth Service\"");
            RunSc("description " + VtechMFAService.ServiceNameConst
                + " \"Provides local device authentication info to the Vtech MFA web client over HTTPS on 127.0.0.1:5002.\"");
            // Auto-restart on crash: after 30s, 60s, 120s; reset failure count every 24h.
            RunSc("failure " + VtechMFAService.ServiceNameConst
                + " reset= 86400 actions= restart/30000/restart/60000/restart/120000");
            RunSc("start " + VtechMFAService.ServiceNameConst);
            Console.WriteLine("Service installed and started.");
        }

        public static void Uninstall()
        {
            RunSc("stop " + VtechMFAService.ServiceNameConst);
            RunSc("delete " + VtechMFAService.ServiceNameConst);
            Console.WriteLine("Service uninstalled.");
        }

        private static void RunSc(string args)
        {
            var psi = new ProcessStartInfo("sc.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (var p = Process.Start(psi))
            {
                Console.Write(p.StandardOutput.ReadToEnd());
                Console.Write(p.StandardError.ReadToEnd());
                p.WaitForExit(10000);
            }
        }
    }
}
